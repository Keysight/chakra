"""
Report renderers: markdown, HTML, stylish CLI, JSON and SARIF.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

import html
import json
import re
from collections import Counter
from datetime import date
from functools import cache
from pathlib import Path

from .catalog import shipped_rules
from .consumer import (
    CONSUMER_LABELS,
    CONSUMERS,
    LIMITED,
    NOT_SUITABLE,
    READY,
    REVIEW,
    Finding,
    TraceResult,
)
from .messages import (
    Messages,
    chakra_version,
    package_version,
    rule_messages,
)
from .rule_config import Rule, changed_fields
from .rule_family import ERROR, INFO, WARNING
from .sampling import SAMPLE_LIMIT

# A ready status needs no reader attention; the rest are bold
PLAIN_STATUSES = {READY}


def cell(text: str) -> str:
    """Escape text for a markdown table cell."""
    return text.replace("|", "\\|").replace("\n", "<br>")


def status_cell(status: str) -> str:
    """Bold any status that needs reader attention."""
    if not status or status in PLAIN_STATUSES:
        return status
    return f"**{status}**"


def table(headers: list[str], body: list[list[str]]) -> list[str]:
    """Render a markdown table."""
    lines = [f"| {' | '.join(headers)} |", f"|{'|'.join('---' for _ in headers)}|"]
    lines += [f"| {' | '.join(cell(c) for c in row)} |" for row in body]
    return lines


def trace_anchors(results: list[tuple[Path, TraceResult]]) -> list[str]:
    """Return the heading anchor of each trace section, in order."""
    seen: Counter = Counter()
    anchors = []
    for trace, _ in results:
        slug = re.sub(r"[^\w\- ]", "", trace.name.lower()).replace(" ", "-")
        anchors.append(f"{slug}-{seen[slug]}" if seen[slug] else slug)
        seen[slug] += 1
    return anchors


def summary_lines(results: list[tuple[Path, TraceResult]]) -> list[str]:
    """Render one overview row per trace with an impact per consumer."""
    body = []
    for (trace, result), anchor in zip(results, trace_anchors(results), strict=False):
        impacts = [result.status(c)[0] for c in CONSUMERS]
        body.append(
            [
                f"[`{trace.name}`](#{anchor})",
                f"{result.total:,}",
            ]
            + [status_cell(impact) for impact in impacts]
        )
    headers = ["Trace", "Nodes", *CONSUMER_LABELS]
    return [
        "## Summary",
        "",
        *table(headers, body),
        "",
        "Definitions appear in [Impact](#impact).",
        "",
    ]


# Plain-language overview shown before the summary
OVERVIEW = (
    "## Overview",
    "",
    "This report checks Chakra execution traces and states whether ",
    "users can rely on them for their intended work.",
    "",
    "- **Usability:** the linter grades each trace for three uses:",
    "  - `Replay`: re-execute the recorded operators on hardware.",
    "    Needs callable operators with reconstructable inputs (`op_schema` and",
    "    matching I/O) and communication attributes. Durations may be zero.",
    "  - `Simulator`: model execution time from the graph, without running anything.",
    "    Needs communication attributes and a duration or I/O size for each",
    "    compute node. Needs no `op_schema` or device link.",
    "  - `Analysis`: study the timing and structure of a captured run.",
    "    Needs nonzero durations, a device link and the capture metadata",
    "    (`pid`, `time`, `start_ts`, `finish_ts`). Needs no `op_schema`.",
    "- **How to read it:** the Summary lists one row per trace. Each trace",
    "  section repeats the CLI output: node ID, severity, message, and rule.",
    "  Every rule ID links to its description in [Rules](#rules).",
    "",
)

# Status meanings shown before the rule descriptions
IMPACT_LEGEND = (
    "## Impact",
    "",
    "- **Consumer impact** (the worst applicable gap sets the impact)",
    "  - `READY`: fully usable; no gap affects the use.",
    "  - `LIMITED`: a known gap lowers fidelity; the use still works.",
    "  - `REVIEW`: the linter cannot decide; a reviewer decides.",
    "  - `NOT SUITABLE`: a finding rules out the use.",
    "- **Severity** (trace rows)",
    "  - `error`: a finding that makes any use `NOT SUITABLE`.",
    "  - `warning`: any other finding.",
    "  - `pass`: no gap affects the use.",
    f"- **Sample IDs:** up to {SAMPLE_LIMIT} affected node IDs to inspect.",
    "",
)


def rule_descriptions(rules: dict[str, Rule], disabled: frozenset[str]) -> list[str]:
    """Render one heading per rule; each ID link in a trace block lands here."""
    lines = ["## Rules", ""]
    for rule in rules.values():
        state = "disabled" if rule.id in disabled else "enabled"
        lines += [f"#### {rule.id}", "", f"- **State:** {state}"]
        lines += [f"- {rule.description}", ""]
    for aggregate in TraceResult.aggregates().values():
        lines += [f"#### {aggregate.id}", "", f"- {aggregate.description}", ""]
    return lines


def block_rows(result: TraceResult) -> list[tuple[str, str, str]]:
    """Return the CLI rows of one trace: findings, then suitability."""
    rows = stylish_rows(result)
    for consumer, name in zip(CONSUMERS, CONSUMER_LABELS, strict=False):
        impact = result.status(consumer)[0]
        text = suitability_text(impact, name, result.causes(consumer))
        rows.append((SUITABILITY_IDS[consumer], IMPACT_SEVERITY[impact][0], text))
    return rows


def markdown_block(trace: Path, result: TraceResult) -> list[str]:
    """Render one trace as a table of CLI rows with linked rule IDs."""
    body = []
    for rule, severity, message in block_rows(result):
        label = f"**{severity}**" if severity == ERROR else severity
        link = f"[`{rule}`](#{rule})" if rule else ""
        body.append([link, label, message])
    return [*table(["Code", "State", "Description"], body), ""]


def html_block(trace: Path, result: TraceResult) -> list[str]:
    """Render one trace as a preformatted block laid out like the CLI."""
    css = {ERROR: "err", WARNING: "warn"}
    indent = " " * (2 + CODE_WIDTH + 2 + SEVERITY_WIDTH + 2)
    lines = [f'<span class="path">{html.escape(str(trace))}</span>']
    for rule, severity, message in block_rows(result):
        head, *more = message.split("\n")
        link = f'<a href="#{rule}">{rule}</a>' if rule else ""
        pad = " " * (CODE_WIDTH - len(rule))
        lines.append(
            f"  {link}{pad}  "
            f'<span class="{css.get(severity, "ok")}">'
            f"{severity.ljust(SEVERITY_WIDTH)}</span>  {html.escape(head)}"
        )
        lines += [indent + html.escape(line) for line in more]
    return ['<pre class="cli">' + "\n".join(lines) + "</pre>", ""]


def render_report(
    results: list[tuple[Path, TraceResult]],
    rules: dict[str, Rule],
    disabled: frozenset[str] = frozenset(),
    as_html: bool = False,
) -> str:
    """Render the markdown report; as_html swaps in CLI-style trace blocks."""
    skipped = ", ".join(f"`{r}`" for r in sorted(disabled)) or "none"
    block = html_block if as_html else markdown_block
    lines = [
        "# Chakra Linter Report",
        "",
        f"- **Date:** {date.today().isoformat()}",
        f"- **mlc-chakra:** {chakra_version()}",
        f"- **protobuf:** {package_version('protobuf')}",
        f"- **Traces:** {len(results)}",
        f"- **Disabled rules:** {skipped}",
        "",
        *OVERVIEW,
        *summary_lines(results),
        "## Traces",
        "",
    ]
    for index, (trace, result) in enumerate(results):
        # Horizontal rule separates consecutive traces
        lines += ["---", ""] if index else []
        lines += [
            f"### `{trace.name}`",
            "",
            f"- **Nodes:** {result.total:,}",
            f"- **Scan time:** {result.elapsed:.2f}s",
            "",
        ]
        lines += [*block(trace, result), "[Back to summary](#summary)", ""]
    lines += [*IMPACT_LEGEND, *rule_descriptions(rules, disabled)]
    return "\n".join(lines)


@cache
def rule_positions() -> dict[str, int]:
    """Map each rule ID to its position in the shipped catalog."""
    return {rule_id: i for i, rule_id in enumerate(shipped_rules())}


def trace_findings(result: TraceResult) -> list[Finding]:
    """List every finding for one trace in catalog order."""
    if result.fatal_rule:
        return [Finding(ERROR, result.problems[0], result.fatal_rule)]
    order = rule_positions()
    return sorted(result.findings, key=lambda f: order.get(f.rule, len(order)))


def paint(text: str, code: str, color: bool) -> str:
    """Wrap text in an ANSI style when color is on."""
    return f"\033[{code}m{text}\033[0m" if color else text


def plural(count: int, noun: str) -> str:
    """Format a count with its noun, adding an s unless the count is one."""
    return f"{count:,} {noun}{'' if count == 1 else 's'}"


def stylish_rows(result: TraceResult) -> list[tuple[str, str, str]]:
    """Return the code, state, and description cells for one trace."""
    return [(f.rule, f.severity, f.text()) for f in trace_findings(result)]


# Severity-column label for a trace with no findings
PASS_LABEL = "pass"

# ANSI style per finding severity
FINDING_STYLE = {ERROR: "31", WARNING: "33", INFO: "36"}

# Fixed column widths keep every trace aligned while output streams
CODE_WIDTH, SEVERITY_WIDTH = 6, len(WARNING)


# Severity cell and style per consumer impact on the suitability rows
IMPACT_SEVERITY = {
    READY: (PASS_LABEL, "32"),
    LIMITED: (WARNING, "33"),
    REVIEW: (WARNING, "33"),
    NOT_SUITABLE: (ERROR, "31"),
}

# Stable code per consumer suitability row: SUI001 Replay, SUI002 Simulator,
# SUI003 Analysis; the code is never reused
SUITABILITY_IDS = {c: a.id for c, a in TraceResult.aggregates().items()}


def suitability_text(impact: str, consumer: str, rules: list[str]) -> str:
    """Phrase a consumer's impact, naming the rules that cause it."""
    if impact == READY:
        return f"suitable for {consumer} use"
    verdict = {
        NOT_SUITABLE: "not suitable",
        REVIEW: "review needed",
        LIMITED: "limited",
    }[impact]
    return f"{verdict} for {consumer} use due to {', '.join(rules)}"


def row_line(code: str, state: str, text: str, style: str, color: bool) -> list[str]:
    """Render one CLI row: code, state, description; extra lines align."""
    head, *more = text.split("\n")
    code_cell = paint(code.ljust(CODE_WIDTH), "2", color)
    state_cell = paint(state.ljust(SEVERITY_WIDTH), style, color)
    indent = " " * (2 + CODE_WIDTH + 2 + SEVERITY_WIDTH + 2)
    first = f"  {code_cell}  {state_cell}  {head}"
    return [first, *(f"{indent}{line}" for line in more)]


def suitability_lines(result: TraceResult, color: bool) -> list[str]:
    """Render one row per consumer with its impact, causes, and ID."""
    lines = []
    for consumer, name in zip(CONSUMERS, CONSUMER_LABELS, strict=False):
        impact = result.status(consumer)[0]
        label, style = IMPACT_SEVERITY[impact]
        text = suitability_text(impact, name, result.causes(consumer))
        lines += row_line(SUITABILITY_IDS[consumer], label, text, style, color)
    return lines


def stylish_block(
    trace: Path,
    result: TraceResult,
    color: bool,
    messages: Messages | None = None,
) -> list[str]:
    """Render one trace's path, node total, rules, then its suitability."""
    lines = [paint(str(trace), "4", color)]
    for code, severity, text in stylish_rows(result):
        lines += row_line(code, severity, text, FINDING_STYLE[severity], color)
    return [*lines, *suitability_lines(result, color), ""]


def stylish_summary(results: list[tuple[Path, TraceResult]], color: bool) -> str:
    """Total the problems, errors, and warnings across all traces."""
    counts = Counter(f.severity for _, r in results for f in trace_findings(r))
    total, traces = counts[ERROR] + counts[WARNING], plural(len(results), "trace")
    if not total:
        return paint(f"No problems in {traces}", "32", color)
    summary = (
        f"\u2716 {plural(total, 'problem')} ({plural(counts[ERROR], ERROR)}, "
        f"{plural(counts[WARNING], WARNING)}) in {traces}"
    )
    return paint(summary, "1;31" if counts[ERROR] else "1;33", color)


def render_stylish(
    results: list[tuple[Path, TraceResult]],
    color: bool,
    messages: Messages | None = None,
) -> str:
    """Render findings grouped by trace, in ESLint's stylish format."""
    lines = [line for t, r in results for line in stylish_block(t, r, color, messages)]
    return "\n".join([*lines, stylish_summary(results, color)])


def render_json(results: list[tuple[Path, TraceResult]]) -> str:
    """Render findings per trace, following ESLint's json formatter layout."""
    entries = []
    for trace, result in results:
        findings = trace_findings(result)
        messages = [
            {
                "nodeId": f.node_ids[0] if f.node_ids else None,
                "sampleNodeIds": f.node_ids,
                "severity": f.severity,
                "message": str(f.message),
                "count": getattr(f.message, "total", None),
                "ruleId": f.rule,
            }
            for f in findings
        ]
        entries.append(
            {
                "filePath": str(trace),
                "messages": messages,
                "errorCount": sum(f.severity == ERROR for f in findings),
                "warningCount": sum(f.severity == WARNING for f in findings),
                "suitability": {c: result.status(c)[0] for c in CONSUMERS},
            }
        )
    return json.dumps(entries, indent=2)


# SARIF 2.1.0 identifiers that code-scanning dashboards validate against
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "chakra-linter"


def artifact_uri(trace: Path) -> str:
    """Return a SARIF URI: relative paths as given, absolute as file URIs."""
    return trace.resolve().as_uri() if trace.is_absolute() else trace.as_posix()


def sarif_rule(rule: Rule, disabled: frozenset[str]) -> dict:
    """Describe one rule for the SARIF tool driver."""
    short = rule.description.split(". ")[0].rstrip(".") + "."
    return {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": short},
        "fullDescription": {"text": rule.description},
        "defaultConfiguration": {"enabled": rule.id not in disabled},
    }


# SARIF names the informational level `note`
SARIF_LEVEL = {INFO: "note"}


def sarif_result(finding: Finding, uri: str, index: dict[str, int]) -> dict:
    """Turn one finding into a SARIF result anchored on the trace file."""
    location: dict = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    if finding.node_ids:
        # Traces have no lines; the node ID is the logical location
        node = {"name": f"node {finding.node_ids[0]}", "kind": "element"}
        location["logicalLocations"] = [node]
    result = {
        "ruleId": finding.rule,
        "level": SARIF_LEVEL.get(finding.severity, finding.severity),
        "message": {"text": finding.text()},
        "locations": [location],
        "properties": {"sampleNodeIds": finding.node_ids},
    }
    if finding.rule in index:
        result["ruleIndex"] = index[finding.rule]
    return result


def render_sarif(
    results: list[tuple[Path, TraceResult]],
    rules: dict[str, Rule],
    disabled: frozenset[str],
) -> str:
    """Render findings as one SARIF 2.1.0 run for code-scanning dashboards."""
    index = {rule_id: i for i, rule_id in enumerate(rules)}
    artifacts, sarif_results = [], []
    for trace, result in results:
        uri = artifact_uri(trace)
        suitability = {c: result.status(c)[0] for c in CONSUMERS}
        artifacts.append({"location": {"uri": uri}, "properties": {"suitability": suitability}})
        sarif_results += [sarif_result(f, uri, index) for f in trace_findings(result)]
    driver = {
        "name": TOOL_NAME,
        "rules": [sarif_rule(rule, disabled) for rule in rules.values()],
    }
    run = {"tool": {"driver": driver}, "artifacts": artifacts, "results": sarif_results}
    log = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
    return json.dumps(log, indent=2)


# CLI output formats a --cli-output file accepts; each takes the results,
# the loaded rules, and the disabled rule IDs
CLI_FORMATS = {
    "text": lambda results, rules, disabled: render_stylish(results, False, rule_messages(rules)),
    "json": lambda results, rules, disabled: render_json(results),
    "sarif": render_sarif,
}

# Stylesheet for the HTML report; follows the viewer's light or dark theme
HTML_STYLE = """
:root { color-scheme: light dark; --fg: #1f2328; --bg: #fff;
  --muted: #59636e; --line: #d1d9e0; --head: #f6f8fa; --link: #0969da;
  --err: #cf222e; --warn: #9a6700; --ok: #1a7f37; }
@media (prefers-color-scheme: dark) { :root { --fg: #f0f6fc; --bg: #0d1117;
  --muted: #9198a1; --line: #3d444d; --head: #151b23; --link: #4493f8;
  --err: #ff7b72; --warn: #d29922; --ok: #3fb950; } }
body { margin: 0 auto; max-width: 72rem; padding: 2rem 1rem;
  font: 15px/1.5 system-ui, sans-serif; color: var(--fg); background: var(--bg); }
a { color: var(--link); }
h1, h2 { border-bottom: 1px solid var(--line); padding-bottom: .3em; }
code { font: 0.9em ui-monospace, monospace; background: var(--head);
  padding: .1em .3em; border-radius: 4px; }
table { border-collapse: collapse; display: block; overflow-x: auto;
  margin: 0 0 1rem; }
th, td { border: 1px solid var(--line); padding: .35em .7em;
  text-align: left; vertical-align: top; }
th { background: var(--head); }
pre.cli { font: 13px/1.45 ui-monospace, monospace; background: var(--head);
  border: 1px solid var(--line); border-radius: 6px; padding: .8em 1em;
  overflow-x: auto; }
pre.cli .path { text-decoration: underline; }
pre.cli .err { color: var(--err); }
pre.cli .warn { color: var(--warn); }
pre.cli .ok { color: var(--ok); }
pre.cli a { color: var(--muted); }
hr { border: 0; border-top: 1px solid var(--line); margin: 2rem 0; }
"""


def render_html(report: str) -> str:
    """Convert the markdown report into a standalone HTML page."""
    import markdown

    body = markdown.markdown(report, extensions=["tables", "toc"])
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>Chakra Linter Report</title>\n<style>{HTML_STYLE}</style>\n"
        f"</head>\n<body>\n{body}\n</body>\n</html>"
    )


def rule_inventory(rules: dict[str, Rule], disabled: frozenset[str]) -> str:
    """List each rule with its effective settings; flag changes to defaults."""
    shipped = shipped_rules()
    width = max(len(rule_id) for rule_id in rules)
    name_width = max(len(rule.name) for rule in rules.values())
    severity_width = max(len(rule.severity) for rule in rules.values())
    lines = []
    for rule_id, rule in rules.items():
        state = "disabled" if rule_id in disabled else "enabled"
        line = f"{rule_id:<{width}}  {rule.name:<{name_width}}  {rule.severity:<{severity_width}}  {state}"
        changed = changed_fields(rule, shipped[rule_id]) if rule_id in shipped else []
        lines.append(f"{line}  (set: {', '.join(changed)})" if changed else line)
    off = sum(rule_id in disabled for rule_id in rules)
    lines.append(f"{plural(len(rules), 'rule')}, {off} disabled")
    return "\n".join(lines)


REPORT_FORMATS = {
    "markdown": lambda results, rules, disabled: render_report(results, rules, disabled),
    "html": lambda results, rules, disabled: render_html(render_report(results, rules, disabled, as_html=True)),
}
