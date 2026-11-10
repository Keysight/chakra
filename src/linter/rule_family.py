"""Base class and registry for rule families fed by one pass over a trace."""

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, TypeVar

from chakra.schema.protobuf.et_def_pb2 import Node

try:
    from .rule_config import RuleConfigError, shipped_rules
except ImportError:  # run as a top-level module, not a package
    from rule_config import RuleConfigError, shipped_rules  # type: ignore[no-redef]

if TYPE_CHECKING:
    try:
        from .index_builder import TraceIndex
    except ImportError:
        from index_builder import TraceIndex  # type: ignore[no-redef]

# Rule ID: two or three capital letters and three digits, such as DAG001
RULE_ID = re.compile(r"[A-Z]{2,3}[0-9]{3}")

# Severity of a hit: fatal stops the scan; error, warning and info show the
# message; pass shows nothing but still counts toward suitability
FATAL, ERROR, WARNING, INFO, PASSED = "fatal", "error", "warning", "info", "pass"

# Check method: reads the shared index, returns the defects it found
Check = Callable[..., "list[Hit]"]


@dataclass(frozen=True)
class Hit:
    """One defect found by a family; the linter renders its message."""

    rule: str
    ids: list[int] = field(default_factory=list)  # sample node IDs
    values: Mapping[str, object] = field(default_factory=dict)  # placeholders
    node_type: int | None = None  # node type the finding concerns, if any
    # Filled from the rule's severity in rules.toml; checks leave it empty
    severity: str = ""


def rule(rule_id: str) -> Callable[[Check], Check]:
    """Mark a family method as the check of one rule in `rules.toml`."""

    def mark(method: Check) -> Check:
        method.rule_id = rule_id  # type: ignore[attr-defined]
        return method

    return mark


class RuleFamily:
    """
    Rules that share accumulators during the single pass over a trace.

    Rule text, names and enabled state come from `rules.toml`. Methods marked
    with `@rule` are the checks; `finish` dispatches enabled rules by ID. The
    builder calls `add` once per node, then `finish` once. A family keeps its
    own counters and never retains `node`.
    """

    # Rule ID to check method name, in report order; built per subclass
    checks: dict[str, str] = {}

    # Report position among families; lower runs first, integrity first
    order: int = 100

    # Node types `add` needs; None means every node. Others skip the call.
    node_types: frozenset[int] | None = None

    # Shared index, bound by the builder; holds the facts of the current node
    index: "TraceIndex"

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Collect `@rule` methods and validate their IDs."""
        super().__init_subclass__(**kwargs)
        cls.checks = {}
        for name, method in vars(cls).items():
            rule_id = getattr(method, "rule_id", None)
            if rule_id is None:
                continue
            if not RULE_ID.fullmatch(rule_id):
                raise TypeError(f"{cls.__name__}: bad rule ID {rule_id!r}")
            if rule_id in cls.checks:
                raise TypeError(f"{cls.__name__} repeats rule ID {rule_id}")
            cls.checks[rule_id] = name
        if not cls.checks:
            raise TypeError(f"{cls.__name__} declares no rules")

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Bind the rules to `rules.toml`; `disabled` IDs are skipped."""
        known = shipped_rules()
        missing = sorted(set(self.checks) - set(known))
        if missing:
            raise RuleConfigError(f"{type(self).__name__}: rules missing from rules.toml: {', '.join(missing)}")
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

    def finish(self, index: "TraceIndex") -> list[Hit]:
        """Run each enabled rule's check over the shared index."""
        known = shipped_rules()
        hits: list[Hit] = []
        for rule_id, name in self.checks.items():
            if rule_id in self.enabled:
                for hit in getattr(self, name)(index):
                    hits.append(replace(hit, severity=hit.severity or known[hit.rule].severity))
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
    FAMILIES.append(cls)
    return cls


def build_families(disabled: Iterable[str], skip: Callable[[str], bool]) -> list[RuleFamily]:
    """Instantiate every registered family in report order."""
    return [family.create(disabled, skip) for family in sorted(FAMILIES, key=lambda f: f.order)]
