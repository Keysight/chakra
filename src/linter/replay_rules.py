"""
Replay rules fed by the single pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

import ast
import fnmatch
import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache

from chakra.schema.protobuf.et_def_pb2 import COMP_NODE, Node

try:
    from .index_builder import TraceIndex
    from .rule_family import Hit, RuleFamily, register, rule
    from .sampling import add_sample, keep_sample
except ImportError:  # run as a top-level module, not a package
    from index_builder import TraceIndex  # type: ignore[no-redef]
    from rule_family import Hit, RuleFamily, register, rule  # type: ignore[no-redef]
    from sampling import add_sample, keep_sample  # type: ignore[no-redef]

# Argument list of an op_schema, such as "aten::add.Tensor(...) -> Tensor"
SCHEMA_ARGS = re.compile(r"^[^(]*\((.*)\)\s*->")

# Families listed in a message; the rest fold into "N more"
FAMILY_LIST_LIMIT = 10

# Kernel name noise: leading return type, anonymous namespace, arguments
# The name stops at the first template, argument, tag or annotation marker
KERNEL_BASE = re.compile(r"^(?:void\s+)?(?:\(anonymous namespace\)::)?((?:[^<(#:;\[]|::)*)")

# Longest family label shown; longer names truncate with an ellipsis
FAMILY_LABEL_LIMIT = 48


@lru_cache(maxsize=65536)
def literal_list(text: str) -> list | None:
    """Parse a Python literal list; None when it is not one."""
    try:
        value = ast.literal_eval(text)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None
    return value if isinstance(value, list) else None


def parse_io(text: str) -> list | None:
    """Parse one I/O field; an empty string is an empty list, else None."""
    if not text:
        return []
    # Fields are Python literals; the C JSON parser is 3x faster when it fits
    try:
        value = json.loads(text.replace("'", '"'))
    except ValueError:
        # Slow path: embedded quotes break the JSON swap; cache repeats only
        return literal_list(text)
    return value if isinstance(value, list) else None


def io_values(info) -> list | None:
    """Return the I/O values; None when a field fails or lengths differ."""
    values, shapes = parse_io(info.values), parse_io(info.shapes)
    types = parse_io(info.types)
    if values is None or shapes is None or types is None:
        return None
    return values if len(values) == len(shapes) == len(types) else None


def op_family(name: str) -> str:
    """
    Name the group of a kernel or operator: the part before any tag.

    A namespaced name groups by namespace, a plain one by its first words;
    digits fold to #, and long labels truncate.
    """
    match = KERNEL_BASE.match(name.strip())
    base = (match.group(1).strip() if match else "") or name.strip()
    parts = base.split("::")
    family = parts[0] if len(parts) > 1 else "_".join(base.split("_")[:3])
    family = re.sub(r"\d+", "#", family) or "unnamed"
    if len(family) > FAMILY_LABEL_LIMIT:
        family = family[: FAMILY_LABEL_LIMIT - 1] + "\u2026"
    return family


@dataclass
class FamilyTally:
    """Node counts per family, with the first node ID of each as an example."""

    counts: Counter = field(default_factory=Counter)
    first: dict[str, int] = field(default_factory=dict)

    def add(self, name: str, node_id: int) -> None:
        """Count a node under its family."""
        family = op_family(name)
        self.counts[family] += 1
        self.first.setdefault(family, node_id)

    def entries(self) -> list[tuple[str, int, int]]:
        """
        Return (family, count, example node) for the largest families.

        Families beyond the limit fold into one closing "other names" entry.
        """
        top = self.counts.most_common(FAMILY_LIST_LIMIT)
        entries = [(name, count, self.first[name]) for name, count in top]
        rest = self.counts.most_common()[FAMILY_LIST_LIMIT:]
        if rest:
            label = f"{len(rest):,} other name{'' if len(rest) == 1 else 's'}"
            entries.append((label, sum(c for _, c in rest), self.first[rest[0][0]]))
        return entries


def has_schema_ancestor(
    node_id: int,
    parents: Mapping[int, tuple[int, ...]],
    cpu_set: set[int],
    schema_ids: set[int],
    under: dict[int, bool],
) -> bool:
    """
    Tell whether a CPU ancestor of the node carries an op_schema.

    Follows the first CPU parent upward; `under` memoizes the answers.
    """
    path = [node_id]
    while True:
        parent = next((p for p in parents.get(path[-1], ()) if p in cpu_set), None)
        if parent is None:
            found = False
        elif parent in schema_ids:
            found = True
        elif parent in under:
            found = under[parent]
        else:
            path.append(parent)
            continue
        break
    under.update(dict.fromkeys(path, found))
    return found


def exempt_matcher(patterns: Sequence[str]) -> Callable[[str], bool]:
    """Return a test for names that match any shell-style pattern."""
    if not patterns:
        return lambda name: False
    regex = re.compile("|".join(fnmatch.translate(p) for p in patterns))
    return lambda name: regex.match(name) is not None


@lru_cache(maxsize=65536)
def schema_arity(op_schema: str) -> int | None:
    """Count op_schema arguments, keyword-only included; None if unparseable."""
    match = SCHEMA_ARGS.match(op_schema)
    if not match:
        return None
    depth, count, token = 0, 0, ""
    for char in match.group(1) + ",":
        depth += (char in "([") - (char in ")]")
        if char == "," and depth == 0:
            # The bare * marks keyword-only arguments, not an argument
            count += token.strip() not in ("", "*")
            token = ""
        else:
            token += char
    return count


def check_io(node: Node, op_schema: str) -> str:
    """Return the I/O rule a CPU operator breaks, or an empty string."""
    inputs, outputs = io_values(node.inputs), io_values(node.outputs)
    if inputs is None or outputs is None:
        return "OPS007"
    if not op_schema:
        return ""  # OPS001 covers the node
    expected = schema_arity(op_schema)
    if not (inputs or outputs):
        # An operator without arguments may record no I/O
        return "" if expected == 0 else "OPS009"
    if expected is not None and expected != len(inputs):
        return "OPS008"
    return ""


@register
class ReplayRules(RuleFamily):
    """Operator schemas, recorded I/O, and idle compute nodes."""

    # Rule IDs; each must match an entry in rules.toml
    OPS001 = "OPS001"  # CPU operators without op_schema
    OPS002 = "OPS002"  # GPU kernels without op_schema
    OPS003 = "OPS003"  # no replayable CPU operators
    OPS004 = "OPS004"  # compute nodes without I/O or duration
    OPS005 = "OPS005"  # every CPU operator lacks op_schema
    OPS006 = "OPS006"  # no replayable CPU operators, synthetic trace

    order = 50

    @classmethod
    def create(cls, disabled: Iterable[str], skip: Callable[[str], bool]) -> "ReplayRules":
        """Build the family with the annotation matcher."""
        return cls(disabled, skip)

    def __init__(self, disabled: Iterable[str] = (), skip: Callable[[str], bool] = lambda name: False) -> None:
        """Start empty; `skip` names childless CPU annotations needing no schema."""
        super().__init__(disabled)
        self.skip = skip
        self.comp_schema = 0  # compute nodes with an op_schema
        self.cpu_ids: list[int] = []  # CPU compute nodes, in file order
        self.cpu_parents: set[int] = set()  # CPU nodes that parent a CPU node
        self.no_schema: dict[int, str] = {}  # CPU nodes lacking op_schema, by name
        self.schema_ids: set[int] = set()  # CPU nodes with an op_schema
        self.cpu_io: dict[int, str] = {}  # CPU nodes breaking an I/O rule
        self.kernels = FamilyTally()  # GPU kernels lacking op_schema
        self.gpu_comp = 0  # compute nodes flagged as not CPU
        self.idle = 0  # compute nodes with neither I/O nor duration
        self.idle_ids: list[int] = []
        self.type_ids: dict[int, list[int]] = {}  # sample node IDs per node type
        # Set by resolve(): replay units, those lacking a schema, and their names
        self.replayable = 0
        self.missing_ops = 0
        self.op_families = FamilyTally()
        self.io_hits: Counter = Counter()
        self.io_ids: dict[str, list[int]] = {}
        self.resolved = False

    def add(self, node: Node) -> None:
        """Record the schema, CPU status, and I/O of one node."""
        index, node_id = self.index, node.id
        add_sample(self.type_ids, node.type, node_id)  # type: ignore[arg-type]
        if node.type != COMP_NODE:
            return
        has_schema = node_id in index.op_schema
        self.comp_schema += has_schema
        cpu_flag = index.has_attr(node_id, "is_cpu_op")
        is_cpu = index.cpu_op.get(node_id, False)
        if cpu_flag and is_cpu:
            # Replay runs CPU operators; leaf status is known after the pass
            self.cpu_ids.append(node_id)
            self.cpu_parents.update(index.ctrl_deps[node_id])
            if has_schema:
                self.schema_ids.add(node_id)
            else:
                self.no_schema[node_id] = index.name[node_id]
            broken = check_io(node, index.op_schema.get(node_id, ""))
            if broken:
                self.cpu_io[node_id] = broken
        elif cpu_flag:
            # GPU kernels need no schema; the notes list them by family
            self.gpu_comp += 1
            if not has_schema:
                self.kernels.add(index.name[node_id], node_id)
        if node_id in index.no_tensor_io and node.duration_micros == 0:
            self.idle += 1
            keep_sample(self.idle_ids, node_id)

    def resolve(self, index: TraceIndex) -> None:
        """Find the replay units: outermost CPU nodes with a schema, or leaves."""
        if self.resolved:
            return
        self.resolved = True
        cpu_set = set(self.cpu_ids)
        under: dict[int, bool] = {}  # node has an op_schema ancestor
        for op_id in self.cpu_ids:
            if has_schema_ancestor(op_id, index.ctrl_deps, cpu_set, self.schema_ids, under):
                continue  # an ancestor replays this node as part of its subtree
            if op_id in self.schema_ids:
                # A replay unit: the outermost CPU node that carries an op_schema
                self.replayable += 1
                if op_id in self.cpu_io:
                    self.io_hits[self.cpu_io[op_id]] += 1
                    add_sample(self.io_ids, self.cpu_io[op_id], op_id)  # type: ignore[arg-type]
            elif op_id not in self.cpu_parents:
                # No schema and no children: replay finds nothing to call here
                name = self.no_schema[op_id]
                if not self.skip(name):
                    self.replayable += 1
                    self.missing_ops += 1
                    self.op_families.add(name, op_id)

    def finish(self, index: TraceIndex) -> list[Hit]:
        """Resolve replay units once, then run the checks."""
        self.resolve(index)
        return super().finish(index)

    @rule(OPS002)
    def kernel_schemas(self, index: TraceIndex) -> list[Hit]:
        """Note GPU kernels without op_schema, by family; replay needs none."""
        return [
            Hit(self.OPS002, [first], {"count": count, "total": self.gpu_comp, "family": family})
            for family, count, first in self.kernels.entries()
        ]

    def schema_hits(self, rule_id: str) -> list[Hit]:
        """Report CPU leaves without op_schema, one hit per operator family."""
        return [
            Hit(rule_id, [first], {"count": n, "total": self.replayable, "family": family}, COMP_NODE)
            for family, n, first in self.op_families.entries()
        ]

    @rule(OPS001)
    def missing_schema(self, index: TraceIndex) -> list[Hit]:
        """Report CPU leaves without op_schema when others have one."""
        if not self.missing_ops or self.missing_ops == self.replayable:
            return []
        return self.schema_hits(self.OPS001)

    @rule(OPS003)
    def no_cpu_ops(self, index: TraceIndex) -> list[Hit]:
        """Report a captured trace with no CPU operator to replay."""
        return [] if index.synthetic else self.no_cpu_hits(index, self.OPS003)

    def no_cpu_hits(self, index: TraceIndex, rule_id: str) -> list[Hit]:
        """Report a trace with no CPU operator to replay."""
        if self.missing_ops or self.replayable:
            return []
        values = {"total": index.type_counts[COMP_NODE], "schema": self.comp_schema}
        # Sample the compute nodes, or any node when none exist
        first_type = next(iter(index.type_counts))
        ids = self.type_ids.get(COMP_NODE) or self.type_ids.get(first_type) or []
        return [Hit(rule_id, ids, values, COMP_NODE)]

    def io_hit(self, rule_id: str) -> list[Hit]:
        """Report replay units that break one I/O rule."""
        if not self.io_hits[rule_id]:
            return []
        values = {"count": self.io_hits[rule_id], "total": self.replayable}
        return [Hit(rule_id, self.io_ids.get(rule_id, []), values, COMP_NODE)]

    @rule("OPS007")
    def malformed_io(self, index: TraceIndex) -> list[Hit]:
        """Report I/O fields that do not parse or disagree in length."""
        return self.io_hit("OPS007")

    @rule("OPS008")
    def arity_mismatch(self, index: TraceIndex) -> list[Hit]:
        """Report recorded inputs that do not fit the op_schema."""
        return self.io_hit("OPS008")

    @rule("OPS009")
    def missing_io(self, index: TraceIndex) -> list[Hit]:
        """Report operators that need arguments but recorded none."""
        return self.io_hit("OPS009")

    @rule(OPS004)
    def idle_compute(self, index: TraceIndex) -> list[Hit]:
        """Report compute nodes with no I/O and no duration; captured traces only."""
        # Modeled synthetic durations may be zero, so only captured traces count
        if self.idle and not index.synthetic:
            return [Hit(self.OPS004, self.idle_ids, {"count": self.idle}, COMP_NODE)]
        return []

    @rule(OPS005)
    def missing_schema_everywhere(self, index: TraceIndex) -> list[Hit]:
        """Report CPU leaves without op_schema when none has one."""
        if not self.missing_ops or self.missing_ops < self.replayable:
            return []
        return self.schema_hits(self.OPS005)

    @rule(OPS006)
    def no_cpu_ops_synthetic(self, index: TraceIndex) -> list[Hit]:
        """Report a synthetic trace with no CPU operator to replay."""
        return self.no_cpu_hits(index, self.OPS006) if index.synthetic else []
