"""
Rule model, validation and command-line overrides.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

import re
import string
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

# Severity of a hit: fatal stops the scan; error, warning and info show the
# message; pass shows nothing but still counts toward suitability
FATAL, ERROR, WARNING, INFO, PASSED = "fatal", "error", "warning", "info", "pass"
SEVERITIES = (FATAL, ERROR, WARNING, INFO, PASSED)

# Consumers a trace may serve; each reports its own impact
REPLAY, SIMULATOR, ANALYSIS = "replay", "simulator", "analysis"
CONSUMERS = (REPLAY, SIMULATOR, ANALYSIS)

# Consumer impact values; LIMITED: known gap, REVIEW: linter cannot decide
READY, LIMITED, REVIEW, NOT_SUITABLE = "READY", "LIMITED", "REVIEW", "NOT SUITABLE"
IMPACTS = (READY, LIMITED, REVIEW, NOT_SUITABLE)

# Rule ID: two or three capital letters and three digits, such as DAG001
RULE_ID = re.compile(r"[A-Z]{2,3}[0-9]{3}")

# Rule name: lowercase words joined by hyphens
RULE_NAME = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")

# Message placeholders: each {name} a message may use, and what fills it
PLACEHOLDERS = {
    "count": "Number of items the finding covers, such as nodes, dependencies or attributes.",
    "total": "Population size that count is drawn from, such as all nodes or replayable operators.",
    "error": "Text of the exception that the protobuf decoder raised.",
    "type": "Numeric node type that the installed Chakra schema does not define.",
    "version": "Version of the installed mlc-chakra package.",
    "field": "Dependency field that holds the cycle: ctrl_deps or data_deps.",
    "stream": "Default stream ID (0) that all collectives use.",
    "family": "Operator or kernel family name, derived from the node name and truncated for display.",
    "schema": "Number of compute nodes that carry an op_schema.",
    "name": "Name of the node or metadata attribute that is absent.",
    "start": "Value of the start_ts metadata attribute.",
    "finish": "Value of the finish_ts metadata attribute.",
    "value": "Value of the metadata attribute that the converter does not support.",
}


class RuleConfigError(Exception):
    """A rule definition or an override is invalid."""


@dataclass
class Rule:
    """One lint rule: its defaults, as declared beside its check."""

    id: str
    name: str
    description: str
    enabled: bool
    severity: str  # fatal, error, warning, info or pass
    message: str
    # Impact per consumer: replay, simulator, analysis; READY means no effect
    consumer_impact: dict[str, str]
    exempt: list[str] = field(default_factory=list)  # name patterns, if any
    required: bool = False  # always runs, always at its severity

    def is_gap(self) -> bool:
        """Return True when a finding lowers the impact for a consumer."""
        return self.severity not in (INFO, PASSED)


def master_placeholders() -> frozenset[str]:
    """Return the placeholder names that messages may use."""
    return frozenset(PLACEHOLDERS)


def check_template(rule_id: str, template: str) -> None:
    """Reject a template that names a value outside `PLACEHOLDERS`."""
    allowed = master_placeholders()
    names = ", ".join(f"{{{n}}}" for n in sorted(allowed))
    where = f"rule {rule_id} message"
    try:
        fields = list(string.Formatter().parse(template))
    except ValueError as exc:
        raise RuleConfigError(f"{where} is malformed: {exc}") from exc
    unknown = [name for _, name, _, _ in fields if name not in (None, *allowed)]
    if unknown:
        raise RuleConfigError(f"{where} uses {{{unknown[0]}}}; allowed placeholders: {names}")
    # Trial render catches nested fields and bad format specs
    try:
        template.format(**dict.fromkeys(allowed, "0"))
    except (ValueError, KeyError, IndexError, AttributeError) as exc:
        raise RuleConfigError(f"{where} is malformed: {exc!r}") from exc


def check_rule(rule: Rule) -> None:
    """Reject a rule whose fields break the catalog conventions."""
    where = f"rule {rule.id}"
    if not RULE_ID.fullmatch(rule.id):
        raise RuleConfigError(f"bad rule ID {rule.id!r}")
    if not RULE_NAME.fullmatch(rule.name):
        raise RuleConfigError(f"{where}: name {rule.name!r} is not kebab-case")
    if not rule.description.endswith("."):
        raise RuleConfigError(f"{where}: description must end with a period")
    if rule.severity not in SEVERITIES:
        raise RuleConfigError(f"{where}: severity {rule.severity!r} not in {', '.join(SEVERITIES)}")
    if list(rule.consumer_impact) != list(CONSUMERS):
        raise RuleConfigError(f"{where}: consumer_impact must name {', '.join(CONSUMERS)}")
    bad = [v for v in rule.consumer_impact.values() if v not in IMPACTS]
    if bad:
        raise RuleConfigError(f"{where}: impact {bad[0]!r} not in {', '.join(IMPACTS)}")
    check_template(rule.id, rule.message)


def expand_selectors(rules: Mapping[str, Rule], selectors: list[str]) -> list[str]:
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


# Fields that a setting may change, for the error message
SETTABLE = ("enabled", "severity", "message", "exempt", *(f"consumer_impact.{c}" for c in CONSUMERS))


def parse_flag(rule: Rule, value: str) -> bool:
    """Read true or false, in any case."""
    if value.lower() not in ("true", "false"):
        raise RuleConfigError(f"{rule.id}.enabled: expected true or false, got {value!r}")
    return value.lower() == "true"


def set_field(rule: Rule, key: str, value: str) -> Rule:
    """Return the rule with one field changed; reject a bad key or value."""
    where = f"{rule.id}.{key}"
    if key == "enabled":
        return replace(rule, enabled=parse_flag(rule, value))
    if key == "severity":
        if value not in SEVERITIES:
            raise RuleConfigError(f"{where}: {value!r} not in {', '.join(SEVERITIES)}")
        return replace(rule, severity=value)
    if key == "message":
        check_template(rule.id, value)
        return replace(rule, message=value)
    if key == "exempt":
        if not rule.exempt:
            raise RuleConfigError(f"{where}: rule has no exempt list")
        return replace(rule, exempt=[p.strip() for p in value.split(",") if p.strip()])
    consumer = key.removeprefix("consumer_impact.")
    if key.startswith("consumer_impact.") and consumer in CONSUMERS:
        if value not in IMPACTS:
            raise RuleConfigError(f"{where}: {value!r} not in {', '.join(IMPACTS)}")
        return replace(rule, consumer_impact={**rule.consumer_impact, consumer: value})
    raise RuleConfigError(f"{where}: unknown field; settable: {', '.join(SETTABLE)}")


def apply_overrides(rules: Mapping[str, Rule], settings: Iterable[str]) -> dict[str, Rule]:
    """
    Apply `SELECTOR.field=value` settings in order; return a new rule set.

    A selector is a rule ID, name or prefix. A required rule keeps its
    enabled state and severity.
    """
    result = dict(rules)
    for setting in settings:
        target, equals, value = setting.partition("=")
        selector, dot, key = target.partition(".")
        if not (equals and dot and selector and key):
            raise RuleConfigError(f"bad setting {setting!r}: expected SELECTOR.field=value")
        for rule_id in expand_selectors(result, [selector]):
            changed = set_field(result[rule_id], key, value)
            required = result[rule_id].required
            if required and (changed.enabled, changed.severity) != (result[rule_id].enabled, result[rule_id].severity):
                raise RuleConfigError(f"{rule_id}.{key}: required rule cannot be disabled or re-graded")
            result[rule_id] = changed
    return result


def read_settings(path: Path) -> list[str]:
    """Read settings from a file: one per line; blank lines and # skipped."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuleConfigError(f"cannot read settings file {path}: {exc}") from exc
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def changed_fields(rule: Rule, default: Rule) -> list[str]:
    """Name the fields where a rule differs from its shipped default."""
    names = ("enabled", "severity", "message", "exempt")
    changed = [n for n in names if getattr(rule, n) != getattr(default, n)]
    changed += [f"consumer_impact.{c}" for c in CONSUMERS if rule.consumer_impact[c] != default.consumer_impact[c]]
    return changed
