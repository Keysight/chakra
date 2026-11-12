"""
Base class and registry for rule families fed by one pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, TypeVar

from chakra.schema.protobuf.et_def_pb2 import Node

from .rule_config import (  # noqa: F401  (severity names are re-exported)
    ERROR,
    FATAL,
    INFO,
    PASSED,
    READY,
    WARNING,
    Rule,
    RuleConfigError,
    check_rule,
)

if TYPE_CHECKING:
    from .index_builder import TraceIndex

# Check method: reads the shared index, returns the defects it found
Check = Callable[..., "list[Hit]"]


@dataclass(frozen=True)
class Hit:
    """One defect found by a family; the linter renders its message."""

    rule: str
    ids: list[int] = field(default_factory=list)  # sample node IDs
    values: Mapping[str, object] = field(default_factory=dict)  # placeholders
    node_type: int | None = None  # node type the finding concerns, if any
    # Filled from the rule's severity; checks leave it empty
    severity: str = ""


def rule(
    rule_id: str,
    *,
    name: str,
    severity: str,
    message: str,
    description: str,
    replay: str = READY,
    simulator: str = READY,
    analysis: str = READY,
    enabled: bool = True,
    required: bool = False,
    exempt: Iterable[str] = (),
) -> Callable[[Check], Check]:
    """
    Mark a family method as the check of one rule and declare the rule.

    The arguments are the rule's shipped defaults; a user overrides them with
    `--set`. A consumer impact left out is READY, which means no effect.
    """
    spec = Rule(
        id=rule_id,
        name=name,
        description=description,
        enabled=enabled,
        severity=severity,
        message=message,
        consumer_impact={"replay": replay, "simulator": simulator, "analysis": analysis},
        exempt=list(exempt),
        required=required,
    )

    def mark(method: Check) -> Check:
        method.rule_id = rule_id  # type: ignore[attr-defined]
        method.rule_spec = spec  # type: ignore[attr-defined]
        return method

    return mark


class RuleFamily:
    """
    Rules that share accumulators during the single pass over a trace.

    Methods marked with `@rule` are the checks, and the decorator carries the
    rule's name, text, severity and consumer impact; `finish` dispatches enabled rules by ID. The
    builder calls `add` once per node, then `finish` once. A family keeps its
    own counters and never retains `node`.
    """

    # Rule ID to check method name, in report order; built per subclass
    checks: dict[str, str] = {}

    # Rule ID to the rule declared by its `@rule`; built per subclass
    rules: dict[str, Rule] = {}

    # Report position among families; lower runs first, integrity first
    order: int = 100

    # A gate family grades first; its fatal findings stop the scan
    gate: bool = False

    # Node types `add` needs; None means every node. Others skip the call.
    node_types: frozenset[int] | None = None

    # Shared index, bound by the builder; holds the facts of the current node
    index: "TraceIndex"

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Collect `@rule` methods and validate their IDs."""
        super().__init_subclass__(**kwargs)
        cls.checks, cls.rules = {}, {}
        for name, method in vars(cls).items():
            spec = getattr(method, "rule_spec", None)
            if spec is None:
                continue
            if spec.id in cls.checks:
                raise TypeError(f"{cls.__name__} repeats rule ID {spec.id}")
            try:
                check_rule(spec)
            except RuleConfigError as exc:
                raise TypeError(f"{cls.__name__}: {exc}") from exc
            cls.checks[spec.id] = name
            cls.rules[spec.id] = spec
        if not cls.checks:
            raise TypeError(f"{cls.__name__} declares no rules")

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Bind the family's rules; `disabled` IDs are skipped."""
        self.enabled = frozenset(self.checks) - frozenset(disabled)

    @classmethod
    def reads_nodes(cls) -> bool:
        """Tell whether the family overrides `add`; no-op families skip it."""
        return cls.add is not RuleFamily.add

    @classmethod
    def create(cls, disabled: Iterable[str], skip: Callable[[str], bool]) -> "RuleFamily":
        """Build the family for a scan; override to take `skip`."""
        return cls(disabled)

    def add(self, node: Node) -> None:
        """Update accumulators from one node."""

    def resolve(self, index: "TraceIndex") -> None:
        """Derive facts that need the whole index; runs once, before `finish`."""

    def facts(self) -> Mapping[str, object]:
        """Return trace-wide message placeholders this family counted."""
        return {}

    def finish(self, index: "TraceIndex") -> list[Hit]:
        """Run each enabled rule's check over the shared index."""
        hits: list[Hit] = []
        for rule_id, name in self.checks.items():
            if rule_id in self.enabled:
                for hit in getattr(self, name)(index):
                    hits.append(replace(hit, severity=hit.severity or self.rules[hit.rule].severity))
        return hits


# Registered family classes, in registration order
FAMILIES: list[type[RuleFamily]] = []
FamilyT = TypeVar("FamilyT", bound=RuleFamily)


def register(cls: type[FamilyT]) -> type[FamilyT]:
    """Class decorator that records a family; rule IDs must stay unique."""
    taken = {rule_id for family in FAMILIES for rule_id in family.checks}
    clash = sorted(taken & set(cls.checks))
    if clash:
        raise TypeError(f"{cls.__name__} reuses rule IDs {', '.join(clash)}")
    names = {r.name for family in FAMILIES for r in family.rules.values()}
    reused = sorted(names & {r.name for r in cls.rules.values()})
    if reused:
        raise TypeError(f"{cls.__name__} reuses rule names {', '.join(reused)}")
    FAMILIES.append(cls)
    return cls


def build_families(disabled: Iterable[str], skip: Callable[[str], bool]) -> list[RuleFamily]:
    """Instantiate every registered family in report order."""
    return [family.create(disabled, skip) for family in sorted(FAMILIES, key=lambda f: f.order)]
