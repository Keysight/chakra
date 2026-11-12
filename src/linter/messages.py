"""
Rule message rendering: templates, placeholders and trace-wide values.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from contextvars import ContextVar
from functools import cache
from importlib.metadata import PackageNotFoundError, version

from .catalog import shipped_rules
from .index_builder import DEFAULT_STREAM
from .rule_config import Rule, RuleConfigError, master_placeholders

# Message template per rule ID
Messages = dict[str, str]


def rule_messages(rules: dict[str, Rule]) -> Messages:
    """Return the template per rule."""
    return {rule_id: rule.message for rule_id, rule in rules.items()}


@cache
def default_messages() -> Messages:
    """Return the templates of the shipped rules, built once."""
    return rule_messages(shipped_rules())


class Message(str):
    """Rule text that remembers how many items it covers."""

    total: int | None
    noun: tuple[str, str]

    def __new__(
        cls,
        text: str,
        total: int | None = None,
        noun: tuple[str, str] = ("node", "nodes"),
    ) -> "Message":
        message = super().__new__(cls, text)
        message.total, message.noun = total, noun
        return message


# Trace-wide placeholder values of the trace being scanned
TRACE_VALUES: ContextVar[dict[str, object]] = ContextVar("TRACE_VALUES", default={})

# Stand-in for a placeholder that a finding cannot fill
NOT_AVAILABLE = "n/a"


def remember(**values: object) -> None:
    """Record trace-wide values that any message may use as placeholders."""
    TRACE_VALUES.get().update({k: v for k, v in values.items() if v is not None})


def placeholder_text(value: object) -> str:
    """Format one placeholder value; integers get thousands separators."""
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value:,}"
    return str(value)


def render(messages: Messages, rule_id: str, *, noun: tuple[str, str] = ("node", "nodes"), **values: object) -> Message:
    """
    Fill a rule's message template; keep the count and its `noun` for the CLI suffix.

    Every placeholder of the schema list is available to every message:
    the finding's own values win, then trace-wide values (version, stream,
    start, finish, total, schema), then `n/a`.
    """
    merged = {name: NOT_AVAILABLE for name in master_placeholders()}
    merged |= {"version": chakra_version(), "stream": DEFAULT_STREAM}
    merged |= TRACE_VALUES.get() | values
    text = {key: placeholder_text(value) for key, value in merged.items()}
    count = values.get("count")
    try:
        body = messages[rule_id].format(**text)
    except KeyError as exc:
        raise RuleConfigError(f"rule {rule_id} message uses unknown placeholder {{{exc.args[0]}}}") from exc
    return Message(
        body,
        count if isinstance(count, int) and not isinstance(count, bool) else None,
        noun,
    )


def package_version(name: str) -> str:
    """Return an installed package version, or 'not installed'."""
    try:
        return version(name)
    except PackageNotFoundError:
        return "not installed"


@cache
def chakra_version() -> str:
    """Return the Chakra version; PyPI says mlc-chakra, source says chakra."""
    found = (package_version(name) for name in ("mlc-chakra", "chakra"))
    return next((v for v in found if v != "not installed"), "not installed")
