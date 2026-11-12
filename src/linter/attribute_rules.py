"""
Attribute rules fed by the single pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections import Counter
from collections.abc import Iterable

from chakra.schema.protobuf.et_def_pb2 import Node

from .index_builder import TraceIndex
from .rule_config import REVIEW, WARNING
from .rule_family import Hit, RuleFamily, register, rule
from .sampling import add_sample, keep_sample


@register
class AttributeRules(RuleFamily):
    """Missing, mistyped, and invalid converter attributes."""

    order = 70

    # Rule IDs; each names the `@rule` that declares it
    ATT001 = "ATT001"  # missing converter attribute
    ATT002 = "ATT002"  # attribute of unexpected type or repeated
    ATT003 = "ATT003"  # invalid node ID or rf_id 0
    ATT004 = "ATT004"  # scope outside 0 to 9
    ATT005 = "ATT005"  # fw_tid set but fw_parent 0

    # Attributes the PyTorch converter writes on every CPU node it converts
    # Older converters wrote only is_cpu_op and tid on device nodes
    CONVERTER_ATTRS = frozenset(
        {
            "rf_id",
            "fw_parent",
            "seq_id",
            "scope",
            "tid",
            "fw_tid",
            "op_schema",
            "is_cpu_op",
        }
    )

    # Value field each known node attribute must use; readers assume it
    ATTR_KINDS = {
        **dict.fromkeys(("rf_id", "fw_parent", "seq_id", "scope", "tid", "fw_tid"), "int64_val"),
        **dict.fromkeys(("stream", "comm_type", "comm_size"), "int64_val"),
        **dict.fromkeys(("op_schema", "pg_name"), "string_val"),
        "is_cpu_op": "bool_val",
    }

    # RecordScope values 0 to 9; NUM_SCOPES (10) is a sentinel, not a scope
    MAX_SCOPE = 9

    # Thread root nodes the observer adds; they carry rf_id 0 by design
    ROOT_NAME_PREFIX = "[pytorch|"

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no attribute defects."""
        super().__init__(disabled)
        self.missing: Counter = Counter()  # converter attributes absent, by name
        self.missing_ids: dict[str, list[int]] = {}
        self.bad = 0  # nodes with a wrongly typed or repeated attribute
        self.bad_ids: list[int] = []
        self.values: Counter = Counter()  # ATT003 to ATT005 defects, by rule
        self.value_ids: dict[str, list[int]] = {}

    def value_rules(self, node_id: int) -> list[str]:
        """Return the value rules (ATT003 to ATT005) that a node breaks."""
        index = self.index

        def num(name: str) -> int | None:
            return index.int_attrs.get(name, {}).get(node_id)

        hits = []
        rf_id = num("rf_id")
        is_root = index.name[node_id].startswith(self.ROOT_NAME_PREFIX)
        if node_id == 0 or (rf_id == 0 and not is_root):
            hits.append(self.ATT003)
        scope = num("scope")
        if scope is not None and not 0 <= scope <= self.MAX_SCOPE:
            hits.append(self.ATT004)
        if num("fw_tid") and num("fw_parent") == 0:
            hits.append(self.ATT005)
        return hits

    def add(self, node: Node) -> None:
        """Record absent, mistyped, and invalid attributes of one node."""
        index, node_id = self.index, node.id
        required = self.CONVERTER_ATTRS if index.cpu_op.get(node_id, False) else ()
        for name in {"is_cpu_op", *required}:
            if not index.has_attr(node_id, name):
                self.missing[name] += 1
                add_sample(self.missing_ids, name, node_id)  # type: ignore[arg-type]
        # Only attributes with a declared kind can have the wrong one
        if node_id in index.bad_attr:
            self.bad += 1
            keep_sample(self.bad_ids, node_id)
        for rule_id in self.value_rules(node_id):
            self.values[rule_id] += 1
            add_sample(self.value_ids, rule_id, node_id)  # type: ignore[arg-type]

    @rule(
        ATT001,
        name="attr-missing-converter",
        severity=WARNING,
        message="missing {name} attr",
        description=(
            "A node of a PyTorch-derived trace lacks an attribute that the Chakra converter writes on every "
            "CPU node: rf_id, fw_parent, seq_id, scope, tid, fw_tid, op_schema or is_cpu_op. Only is_cpu_op "
            "is required on every node; the rest apply to CPU nodes, because older converters wrote little "
            "else on device nodes. Readers fall back to default values, which can misclassify the node. One "
            "finding per attribute name."
        ),
        replay=REVIEW,
        analysis=REVIEW,
    )
    def missing_attrs(self, index: TraceIndex) -> list[Hit]:
        """Report converter attributes absent from nodes; PyTorch traces only."""
        if not index.pytorch_nodes:
            return []
        return [
            Hit(self.ATT001, self.missing_ids[name], {"count": self.missing[name], "name": name})
            for name in sorted(self.missing)
        ]

    def value_hit(self, rule_id: str, index: TraceIndex) -> list[Hit]:
        """Report one invalid-value rule; PyTorch traces only."""
        if index.pytorch_nodes and self.values[rule_id]:
            return [Hit(rule_id, self.value_ids[rule_id], {"count": self.values[rule_id]})]
        return []

    @rule(
        ATT003,
        name="attr-invalid-id",
        severity=WARNING,
        message="node ID 0 or rf_id 0",
        description=(
            "A node of a PyTorch-derived trace has node ID 0 (uninitialized) or rf_id 0 (invalid). Thread "
            "root nodes, named [pytorch|*, carry rf_id 0 by design and are exempt. Readers use rf_id to pair "
            "nodes, so a sentinel breaks the link silently."
        ),
        replay=REVIEW,
        analysis=REVIEW,
    )
    def bad_rf_id(self, index: TraceIndex) -> list[Hit]:
        """Report a zero node ID, or a zero rf_id outside thread roots."""
        return self.value_hit(self.ATT003, index)

    @rule(
        ATT004,
        name="attr-invalid-scope",
        severity=WARNING,
        message="scope outside 0 to 9",
        description=(
            "A node of a PyTorch-derived trace has a scope outside the RecordScope values 0 to 9. RecordScope "
            "is the PyTorch enum that classifies a node, such as forward, backward or user annotation. The "
            "NUM_SCOPES sentinel is not a scope. Readers cannot classify the node."
        ),
        replay=REVIEW,
        analysis=REVIEW,
    )
    def bad_scope(self, index: TraceIndex) -> list[Hit]:
        """Report a scope outside the RecordScope range."""
        return self.value_hit(self.ATT004, index)

    @rule(
        ATT005,
        name="attr-backward-link",
        severity=WARNING,
        message="fw_tid set but fw_parent 0",
        description=(
            "A node of a PyTorch-derived trace has a non-zero fw_tid (forward thread ID) but a fw_parent "
            "(forward parent node ID) of 0. A backward node names its forward thread but no forward parent, "
            "so readers cannot pair it with the forward node."
        ),
        replay=REVIEW,
        analysis=REVIEW,
    )
    def bad_fw_parent(self, index: TraceIndex) -> list[Hit]:
        """Report a forward thread with fw_parent zero."""
        return self.value_hit(self.ATT005, index)

    @rule(
        ATT002,
        name="attr-unexpected-type",
        severity=WARNING,
        message="attribute of unexpected type or repeated attribute name",
        description=(
            "A node carries a known attribute with a value type that readers do not expect, such as stream as "
            "uint64, or the node repeats an attribute name. Readers read the expected field and see a default "
            "value instead of the stored one."
        ),
        replay=REVIEW,
        simulator=REVIEW,
        analysis=REVIEW,
    )
    def bad_type(self, index: TraceIndex) -> list[Hit]:
        """Report nodes with a wrongly typed or repeated attribute."""
        if self.bad:
            return [Hit(self.ATT002, self.bad_ids, {"count": self.bad})]
        return []
