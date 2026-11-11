"""
Rule configuration: rules.toml, its JSON schema and message templates.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

import json
import string
import tomllib
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import jsonschema

# Rule file and its syntax schema, shipped beside the linter
DEFAULT_RULES = Path(__file__).with_name("rules.toml")
RULES_SCHEMA = Path(__file__).with_name("rules.schema.json")

# Unreadable or empty traces cannot be graded, so these rules stay on
FATAL_RULES = ("INT001", "INT002")


class RuleConfigError(Exception):
    """The rule configuration file is missing or invalid."""


@dataclass
class Rule:
    """One lint rule as defined in the configuration file."""

    id: str
    name: str
    description: str
    enabled: bool
    severity: str  # fatal, error, warning, info or pass
    message: str
    # Impact per consumer: replay, simulator, analysis; READY means no effect
    consumer_impact: dict[str, str]
    exempt: list[str] = field(default_factory=list)  # name patterns, if any

    def is_gap(self) -> bool:
        """Return True when a finding lowers the impact for a consumer."""
        return self.severity not in ("info", "pass")


def _validate_schema(document: dict, path: Path) -> None:
    """Validate the parsed rule file against `rules.schema.json`."""
    try:
        schema = json.loads(RULES_SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuleConfigError(f"cannot load schema {RULES_SCHEMA}: {exc}") from exc
    try:
        jsonschema.validate(document, schema)
    except jsonschema.ValidationError as exc:
        where = "/".join(str(p) for p in exc.absolute_path) or "<root>"
        raise RuleConfigError(f"{path}: {where}: {exc.message}") from exc


@dataclass
class Consumer:
    """One consumer entry; rule consumer_impact lines set its impact."""

    id: str
    name: str
    description: str


def _read_document(path: Path) -> dict:
    """Parse the rule file and validate its syntax against the schema."""
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except OSError as exc:
        raise RuleConfigError(f"cannot read rules file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RuleConfigError(f"malformed rules file {path}: {exc}") from exc
    _validate_schema(document, path)
    return document


def load_rules(path: Path = DEFAULT_RULES) -> dict[str, Rule]:
    """Load and validate the rule file; return the rules keyed by ID."""
    document = _read_document(path)
    rules: dict[str, Rule] = {}
    for entry in document["rule"]:
        if entry["id"] in rules:
            raise RuleConfigError(f"{path}: duplicate rule ID {entry['id']}")
        if any(entry["name"] == r.name for r in rules.values()):
            raise RuleConfigError(f"{path}: duplicate rule name {entry['name']}")
        check_template(path, entry["id"], entry["message"])
        rules[entry["id"]] = Rule(**entry)
    fatal = [r for r in FATAL_RULES if r in rules and not rules[r].enabled]
    if fatal:
        raise RuleConfigError(f"{path}: rule cannot be disabled: {', '.join(fatal)}")
    return rules


def load_consumers(path: Path = DEFAULT_RULES) -> dict[str, Consumer]:
    """Load the consumer entries keyed by consumer."""
    document = _read_document(path)
    aggregates: dict[str, Consumer] = {}
    for entry in document.get("consumer", []):
        aggregate = Consumer(**entry)
        if aggregate.name in aggregates:
            raise RuleConfigError(f"{path}: two aggregates for {aggregate.name}")
        aggregates[aggregate.name] = aggregate
    return aggregates


def master_placeholders() -> frozenset[str]:
    """Return the placeholder names that the schema declares."""
    try:
        schema = json.loads(RULES_SCHEMA.read_text(encoding="utf-8"))
        return frozenset(schema["x-placeholders"]) - {"$comment"}
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        raise RuleConfigError(f"cannot load placeholders from {RULES_SCHEMA}: {exc!r}") from exc


def check_template(path: Path, rule_id: str, template: str) -> None:
    """Reject a template that names a value missing from the schema list."""
    allowed = master_placeholders()
    names = ", ".join(f"{{{n}}}" for n in sorted(allowed))
    where = f"{path}: rule {rule_id} message"
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


@cache
def shipped_rules() -> dict[str, Rule]:
    """Return the rules of the shipped file, loaded once."""
    return load_rules(DEFAULT_RULES)


@cache
def shipped_consumers() -> dict[str, Consumer]:
    """Return the consumer aggregates of the shipped file, loaded once."""
    return load_consumers(DEFAULT_RULES)
