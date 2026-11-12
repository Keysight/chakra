"""
Chakra trace linter.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

import argparse
import logging
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from functools import cache
from pathlib import Path

from .attribute_rules import AttributeRules
from .catalog import shipped_rules
from .consumer import (
    Finding,
    Gap,
    Issue,
    TraceResult,
)
from .index_builder import IndexBuilder
from .messages import TRACE_VALUES, Message, Messages, default_messages, remember, render, rule_messages
from .replay_rules import exempt_matcher
from .reports import CLI_FORMATS, REPORT_FORMATS, rule_inventory, stylish_block, stylish_summary, trace_findings
from .rule_config import LOG, Rule, RuleConfigError, apply_overrides, expand_selectors, read_settings
from .rule_family import ERROR, FATAL, INFO, PASSED, Hit, build_families


# Verbosity choices of --log-level, quietest last
LOG_LEVELS = ("debug", "info", "warning", "error", "critical")


def lint_trace(
    path: Path,
    disabled: frozenset[str] = frozenset(),
    messages: Messages | None = None,
    exempt: Sequence[str] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    rules: dict[str, Rule] | None = None,
) -> TraceResult:
    """
    Scan one trace; each finding sets an impact per consumer.

    The trace origin (PyTorch capture or synthetic) is inferred from content.
    Findings of rules in `disabled` are dropped before grading.
    `messages` holds the report text per rule; the shipped file by default.
    `exempt` lists name patterns of childless CPU annotations needing no schema.
    `rules` sets severity and consumer impact per rule; the shipped ones by default.
    `on_progress` receives (nodes read, total) every PROGRESS_STEP nodes; the
    total comes from a fast scan once the header decodes.
    """
    values: dict[str, object] = {}
    token = TRACE_VALUES.set(values)
    try:
        result = scan_trace(path, disabled, messages, exempt, on_progress, rules)
    finally:
        TRACE_VALUES.reset(token)
    result.values = values
    return result


def finding_for(hit: Hit, message: "Message") -> "Finding":
    """Turn a hit into a CLI finding; a node type prefixes the message."""
    if hit.node_type is not None:
        message = Message(f"{Gap.type_name(hit.node_type)}: {message}", message.total, message.noun)
    return Finding(hit.severity, message, hit.rule, hit.ids)


def scan_trace(
    path: Path,
    disabled: frozenset[str] = frozenset(),
    messages: Messages | None = None,
    exempt: Sequence[str] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    rules: dict[str, Rule] | None = None,
) -> TraceResult:
    """Run the scan behind `lint_trace`; trace-wide placeholders go to `remember`."""
    rules = rules or shipped_rules()
    messages = messages or default_messages()
    skip = exempt_matcher(default_exempt() if exempt is None else exempt)
    # Registered families in report order: findings list in this order
    families = build_families(disabled, skip)
    gates = [f for f in families if f.gate]
    others = [f for f in families if not f.gate]
    result = TraceResult()
    index = IndexBuilder(path, on_progress, AttributeRules.ATTR_KINDS, families).build()
    result.type_counts, result.elapsed = index.type_counts, index.elapsed
    result.pytorch_nodes = index.pytorch_nodes
    for family in families:
        family.resolve(index)
    result.total = result.type_counts.total()
    header = index.header
    remember(start=header.get("start_ts"), finish=header.get("finish_ts"))
    remember(total=result.total, **{k: v for f in families for k, v in f.facts().items()})
    # No capture markers and no device data: generated, so no merge applies
    result.synthetic = index.synthetic
    # A fatal hit from a gate family stops the scan before grading
    hits = resolve_severity([h for f in gates for h in f.finish(index)], rules)
    fatal = [h for h in hits if h.severity == FATAL]
    if fatal:
        result.problems += [render(messages, h.rule, noun=rules[h.rule].noun, **h.values) for h in fatal]
        result.fatal_rule = fatal[0].rule
        return result
    # Metadata and integrity ran first; the rest follow in report order
    hits += resolve_severity([h for f in others for h in f.finish(index)], rules)
    for hit in hits:
        message = render(messages, hit.rule, noun=rules[hit.rule].noun, **hit.values)
        if hit.severity != PASSED:
            result.findings.append(finding_for(hit, message))
        if hit.severity in (INFO, PASSED):
            # Info and pass lower no consumer impact; they only inform
            result.notes.append(Issue(hit.rule, message, hit.ids))
        elif rules[hit.rule].is_gap():
            result.gaps.append(Gap.from_hit(hit, message, rules))
    return result


def resolve_severity(hits: list[Hit], rules: dict[str, Rule]) -> list[Hit]:
    """Set each hit's severity from the effective rules, overrides included."""
    return [replace(hit, severity=rules[hit.rule].severity) for hit in hits]


def rule_exempt(rules: dict[str, Rule]) -> list[str]:
    """Return the annotation patterns of the one rule that declares them."""
    declared = [r.exempt for r in rules.values() if r.exempt]
    if len(declared) != 1:
        raise RuleConfigError(f"expected one rule with an exempt list, found {len(declared)}")
    return declared[0]


@cache
def default_exempt() -> list[str]:
    """Return the annotation patterns of the shipped rules."""
    return rule_exempt(shipped_rules())


def disabled_rules(
    rules: dict[str, Rule],
    enable: list[str] | None = None,
    disable: list[str] | None = None,
) -> frozenset[str]:
    """Return rule IDs to skip: rule defaults, then command-line overrides."""
    enable = expand_selectors(rules, enable or [])
    disable = expand_selectors(rules, disable or [])
    both = sorted(set(enable) & set(disable))
    if both:
        raise RuleConfigError(f"rule both enabled and disabled: {', '.join(both)}")
    for rule_id in (r for r in disable if rules[r].required):
        LOG.warning("ignored --disable-rule %s: a required rule always runs", rule_id)
    disable = [r for r in disable if not rules[r].required]
    off = {r.id for r in rules.values() if not r.enabled}
    return frozenset((off | set(disable)) - set(enable))


def collect_traces(paths: list[Path], recursive: bool = False) -> list[Path]:
    """Expand directories into their .et files, at any depth when recursive."""
    pattern = "**/*.et" if recursive else "*.et"
    traces: list[Path] = []
    for path in paths:
        traces.extend(sorted(path.glob(pattern)) if path.is_dir() else [path])
    return traces


def build_parser() -> argparse.ArgumentParser:
    """Define the command-line options."""
    parser = argparse.ArgumentParser(description="Chakra trace linter.")
    parser.add_argument("paths", nargs="*", type=Path, help="traces or dirs")
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="descend into subdirectories to find .et traces",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        metavar="FILE",
        help="write the report to FILE, or - for stdout; omit for no report",
    )
    parser.add_argument(
        "--report-format",
        choices=tuple(REPORT_FORMATS),
        default="markdown",
        help="format of the report (default: %(default)s)",
    )
    parser.add_argument(
        "--cli-color",
        choices=("auto", "always", "never"),
        default="auto",
        help="color CLI output (default: %(default)s, on for a terminal)",
    )
    parser.add_argument(
        "--cli-output",
        type=Path,
        metavar="FILE",
        help="also save the CLI output, uncolored, to FILE",
    )
    parser.add_argument(
        "--cli-format",
        choices=tuple(CLI_FORMATS),
        default="text",
        help="format of the --cli-output file (default: %(default)s)",
    )
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        dest="settings",
        metavar="ID.FIELD=VALUE",
        help="override a rule field, for example STO007.severity=info; the ID may be a "
        "name or prefix; fields: enabled, severity, message, exempt, consumer_impact.<consumer>; repeatable",
    )
    parser.add_argument(
        "--set-file",
        type=Path,
        metavar="FILE",
        help="read ID.FIELD=VALUE settings from FILE, one per line; # starts a comment; --set wins",
    )
    parser.add_argument(
        "--enable-rule",
        action="append",
        default=[],
        metavar="ID",
        help="run rule ID, name or prefix (e.g. DAG) even if disabled; repeatable",
    )
    parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        metavar="ID",
        help="skip rule ID, name or prefix (e.g. DAG); repeatable",
    )
    parser.add_argument(
        "--log-level",
        type=str.lower,
        choices=LOG_LEVELS,
        default="warning",
        help="verbosity of messages on stderr (default: %(default)s); settings the linter "
        "cannot honor log at warning",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="list every rule with its effective settings, then exit",
    )
    return parser


def lint_traces(
    traces: list[Path],
    disabled: frozenset[str],
    messages: Messages,
    exempt: list[str],
    color: bool,
    show_cli: bool,
    rules: dict[str, Rule] | None = None,
) -> list[tuple[Path, TraceResult]]:
    """Lint each trace in order; print its rows as soon as it is graded."""
    # A full scan takes minutes; show progress on a terminal only
    progress = sys.stderr.isatty()

    def show_progress(text: str) -> None:
        if progress:
            sys.stderr.write(f"\r\033[K{text}")
            sys.stderr.flush()

    results = []
    for index, trace in enumerate(traces, 1):
        label = f"Linting {index}/{len(traces)}: {trace}"

        def on_progress(done: int, total: int, label: str = label) -> None:
            show_progress(f"{label} ({done:,}/{total:,} nodes)")

        show_progress(label)
        try:
            result = lint_trace(trace, disabled, messages, exempt, on_progress, rules)
        except RuleConfigError:
            show_progress("")
            raise
        results.append((trace, result))
        show_progress("")
        if show_cli:
            print(*stylish_block(trace, result, color, messages), sep="\n", flush=True)
    return results


def main(argv: list[str] | None = None) -> int:
    """Run the linter; return 0 clean, 1 on any error finding, 2 on bad usage."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), format="%(levelname)s: %(message)s", force=True)
    if not args.paths and not args.list_rules:
        parser.error("the following arguments are required: paths")

    # Fail before any scan when the rule file or overrides are unusable
    try:
        settings = [*(read_settings(args.set_file) if args.set_file else []), *args.settings]
        rules = apply_overrides(shipped_rules(), settings)
        messages = rule_messages(rules)
        exempt = rule_exempt(rules)
        disabled = disabled_rules(rules, args.enable_rule, args.disable_rule)
    except RuleConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.list_rules:
        print(rule_inventory(rules, disabled))
        return 0

    # The report on stdout replaces the CLI output
    show_cli = str(args.report_output) != "-"
    color = args.cli_color == "always" or (args.cli_color == "auto" and sys.stdout.isatty())
    traces = collect_traces(args.paths, args.recursive)
    try:
        results = lint_traces(traces, disabled, messages, exempt, color, show_cli, rules)
    except RuleConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.cli_output:
        args.cli_output.write_text(CLI_FORMATS[args.cli_format](results, rules, disabled) + "\n")
    if args.report_output:
        report = REPORT_FORMATS[args.report_format](results, rules, disabled)
        if show_cli:
            args.report_output.write_text(report + "\n")
        else:
            print(report)
    if show_cli:
        print(stylish_summary(results, color))
    # Nonzero exit on any error, as linters do, so CI can gate on it
    return 1 if any(f.severity == ERROR for _, r in results for f in trace_findings(r)) else 0
