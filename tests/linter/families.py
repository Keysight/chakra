"""Helpers that feed in-memory nodes to rule families through the builder."""

from pathlib import Path

from attribute_rules import AttributeRules
from chakra.schema.protobuf.et_def_pb2 import COMP_NODE, AttributeProto, Node
from index_builder import IndexBuilder, TraceIndex
from rule_family import Hit, RuleFamily


def attr(name: str, value: object) -> AttributeProto:
    """Build an attribute whose value field follows the Python type."""
    if isinstance(value, bool):
        return AttributeProto(name=name, bool_val=value)
    if isinstance(value, str):
        return AttributeProto(name=name, string_val=value)
    return AttributeProto(name=name, int64_val=value)


def node(node_id: int, node_type: int = COMP_NODE, duration: int = 5, name: str = "n", **attrs: object) -> Node:
    """Build a node; keyword arguments become attributes."""
    built = Node(id=node_id, name=name, type=node_type, duration_micros=duration)
    built.attr.extend(attr(k, v) for k, v in attrs.items())
    return built


def run(family: RuleFamily, nodes: list[Node], header: dict[str, object] | None = None) -> tuple[list[Hit], TraceIndex]:
    """Feed nodes to the family through a builder; return its hits and index."""
    builder = IndexBuilder(Path("t.et"), attr_kinds=AttributeRules.ATTR_KINDS, families=[family])
    builder.index.header = {"pid": 1} if header is None else header
    for built in nodes:
        builder.add(built)
    index = builder.index
    index.total = index.type_counts.total()
    return family.finish(index), index
