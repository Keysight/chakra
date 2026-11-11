"""
Chakra trace linter.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

import argparse
import sys
from collections.abc import Callable, Sequence
from functools import cache
from pathlib import Path

try:
    from . import (
        comm_rules,  # noqa: F401  (registers its family)
        dag_rules,  # noqa: F401  (registers its family)
        kineto_rules,  # noqa: F401  (registers its family)
        metadata_rules,  # noqa: F401  (registers its family)
        storage_rules,  # noqa: F401  (registers its family)
        timing_rules,  # noqa: F401  (registers its family)
    )
    from .attribute_rules import AttributeRules
    from .consumer import (
        Finding,
        Gap,
        Issue,
        TraceResult,
    )
    from .index_builder import IndexBuilder
    from .integrity_rules import IntegrityRules
    from .messages import TRACE_VALUES, Message, Messages, default_messages, remember, render, rule_messages
    from .replay_rules import ReplayRules, exempt_matcher
    from .reports import CLI_FORMATS, REPORT_FORMATS, rule_inventory, stylish_block, stylish_summary, trace_findings
    from .rule_config import DEFAULT_RULES, FATAL_RULES, Rule, RuleConfigError, load_rules, shipped_rules
    from .rule_family import ERROR, FATAL, INFO, PASSED, Hit, build_families
except ImportError:  # run as a top-level module, not a package
    import comm_rules  # noqa: F401  (registers its family)
    import dag_rules  # noqa: F401  (registers its family)
    import kineto_rules  # noqa: F401  (registers its family)
    import metadata_rules  # noqa: F401  (registers its family)
    import storage_rules  # noqa: F401  (registers its family)
    import timing_rules  # noqa: F401  (registers its family)
    from attribute_rules import AttributeRules  # type: ignore[no-redef]
    from consumer import (  # type: ignore[no-redef]
        Finding,
        Gap,
        Issue,
        TraceResult,
    )
    from index_builder import IndexBuilder  # type: ignore[no-redef]
    from integrity_rules import IntegrityRules  # type: ignore[no-redef]
    from messages import (  # type: ignore[no-redef]
        TRACE_VALUES,
        Message,
        Messages,
        default_messages,
        remember,
        render,
        rule_messages,
    )
    from replay_rules import ReplayRules, exempt_matcher  # type: ignore[no-redef]
    from reports import (  # type: ignore[no-redef]
        CLI_FORMATS,
        REPORT_FORMATS,
        rule_inventory,
        stylish_block,
        stylish_summary,
        trace_findings,
    )
    from rule_config import (  # type: ignore[no-redef]
        DEFAULT_RULES,
        FATAL_RULES,
        Rule,
        RuleConfigError,
        load_rules,
        shipped_rules,
    )
    from rule_family import ERROR, FATAL, INFO, PASSED, Hit, build_families  # type: ignore[no-redef]


def lint_trace(
    path: Path,
    disabled: frozenset[str] = frozenset(),
    messages: Messages | None = None,
    exempt: Sequence[str] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> TraceResult:
    """
    Scan one trace; each finding sets an impact per consumer.

    The trace origin (PyTorch capture or synthetic) is inferred from content.
    Findings of rules in `disabled` are dropped before grading.
    `messages` holds the report text per rule; the shipped file by default.
    `exempt` lists name patterns of childless CPU annotations needing no schema.
    `on_progress` receives (nodes read, total) every PROGRESS_STEP nodes; the
    total comes from a fast scan once the header decodes.
    """
    values: dict[str, object] = {}
    token = TRACE_VALUES.set(values)
    try:
        result = scan_trace(path, disabled, messages, exempt, on_progress)
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
) -> TraceResult:
    """Run the scan behind `lint_trace`; trace-wide placeholders go to `remember`."""
    messages = messages or default_messages()
    skip = exempt_matcher(default_exempt() if exempt is None else exempt)
    # Registered families in report order: findings list in this order
    families = build_families(disabled, skip)
    integrity = next(f for f in families if isinstance(f, IntegrityRules))
    replay = next(f for f in families if isinstance(f, ReplayRules))
    result = TraceResult()
    index = IndexBuilder(path, on_progress, AttributeRules.ATTR_KINDS, families).build()
    result.type_counts, result.elapsed = index.type_counts, index.elapsed
    result.pytorch_nodes = index.pytorch_nodes
    replay.resolve(index)
    result.total = result.type_counts.total()
    header = index.header
    remember(start=header.get("start_ts"), finish=header.get("finish_ts"))
    remember(total=result.total, schema=replay.comp_schema)
    # No capture markers and no device data: generated, so no merge applies
    result.synthetic = index.synthetic
    # A fatal hit (unreadable or empty trace) stops the scan before grading
    hits = integrity.finish(index)
    fatal = [h for h in hits if h.severity == FATAL]
    if fatal:
        result.problems += [render(messages, h.rule, **h.values) for h in fatal]
        result.fatal_rule = fatal[0].rule
        return result
    # Integrity ran first; the rest follow in report order
    hits += [hit for family in families if family is not integrity for hit in family.finish(index)]
    shipped = shipped_rules()
    for hit in hits:
        message = render(messages, hit.rule, **hit.values)
        if hit.severity != PASSED:
            result.findings.append(finding_for(hit, message))
        if hit.severity in (INFO, PASSED):
            # Info and pass lower no consumer impact; they only inform
            result.notes.append(Issue(hit.rule, message, hit.ids))
        elif shipped[hit.rule].is_gap():
            result.gaps.append(Gap.from_hit(hit, message))
    return result


def rule_exempt(rules: dict[str, Rule]) -> list[str]:
    """Return the CPU annotation patterns of `OPS001`; shipped if absent."""
    if "OPS001" not in rules:
        rules = load_rules(DEFAULT_RULES)
    return rules["OPS001"].exempt


@cache
def default_exempt() -> list[str]:
    """Return the annotation patterns of the shipped rule file, loaded once."""
    return rule_exempt(load_rules(DEFAULT_RULES))


def expand_selectors(rules: dict[str, Rule], selectors: list[str]) -> list[str]:
    """Resolve codes, names and code prefixes (such as DAG) to rule IDs."""
    by_name = {r.name: r.id for r in rules.values()}
    resolved, unknown = [], []
    for selector in selectors:
        if selector in rules:
            resolved.append(selector)
        elif selector in by_name:
            resolved.append(by_name[selector])
        elif matches := [r for r in rules if r.rstrip("0123456789") == selector]:
            resolved.extend(matches)
        else:
            unknown.append(selector)
    if unknown:
        raise RuleConfigError(f"unknown rule ID: {', '.join(sorted(unknown))}")
    return resolved


def disabled_rules(
    rules: dict[str, Rule],
    enable: list[str] | None = None,
    disable: list[str] | None = None,
) -> frozenset[str]:
    """Return rule IDs to skip: file settings, then command-line overrides."""
    enable = expand_selectors(rules, enable or [])
    disable = expand_selectors(rules, disable or [])
    both = sorted(set(enable) & set(disable))
    if both:
        raise RuleConfigError(f"rule both enabled and disabled: {', '.join(both)}")
    fatal = [r for r in disable if r in FATAL_RULES]
    if fatal:
        raise RuleConfigError(f"rule cannot be disabled: {', '.join(fatal)}")
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
        "--rules",
        type=Path,
        default=DEFAULT_RULES,
        metavar="FILE",
        help="rule configuration file (default: %(default)s)",
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
        "--list-rules",
        action="store_true",
        help="list every rule with its enabled state, then exit",
    )
    return parser


def lint_traces(
    traces: list[Path],
    disabled: frozenset[str],
    messages: Messages,
    exempt: list[str],
    color: bool,
    show_cli: bool,
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
            result = lint_trace(trace, disabled, messages, exempt, on_progress)
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
    if not args.paths and not args.list_rules:
        parser.error("the following arguments are required: paths")

    # Fail before any scan when the rule file or overrides are unusable
    try:
        rules = load_rules(args.rules)
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
        results = lint_traces(traces, disabled, messages, exempt, color, show_cli)
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


if __name__ == "__main__":
    sys.exit(main())
