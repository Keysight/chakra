"""Integrity rules INT001 to INT004, judged on the index of one trace."""

from collections.abc import Iterable

from chakra.schema.protobuf.et_def_pb2 import Node, NodeType

try:
    from .index_builder import TraceIndex
    from .rule_family import Hit, RuleFamily, register, rule
    from .sampling import add_sample
except ImportError:  # run as a top-level module, not a package
    from index_builder import TraceIndex  # type: ignore[no-redef]
    from rule_family import Hit, RuleFamily, register, rule  # type: ignore[no-redef]
    from sampling import add_sample  # type: ignore[no-redef]


@register
class IntegrityRules(RuleFamily):
    """Unreadable files, empty traces, and unknown node types."""

    order = 10

    # Rule IDs; each must match an entry in rules.toml
    INT001 = "INT001"  # file cannot be decoded
    INT002 = "INT002"  # trace holds no nodes
    INT003 = "INT003"  # node type unknown to the schema
    INT004 = "INT004"  # node count of a readable trace

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no unknown types."""
        super().__init__(disabled)
        self.type_ids: dict[int, list[int]] = {}  # sample node IDs per unknown type

    def add(self, node: Node) -> None:
        """Sample the nodes of a type that the schema does not define."""
        if node.type not in NodeType.DESCRIPTOR.values_by_number:
            add_sample(self.type_ids, node.type, node.id)  # type: ignore[arg-type]

    @rule(INT001)
    def decode_failure(self, index: TraceIndex) -> list[Hit]:
        """Report a file that the decoder could not read."""
        return [Hit(self.INT001, [], {"error": index.error})] if index.error else []

    @rule(INT002)
    def empty_trace(self, index: TraceIndex) -> list[Hit]:
        """Report a readable trace that holds no nodes."""
        return [Hit(self.INT002, [], {"count": 0})] if not index.error and not index.total else []

    @rule(INT003)
    def unknown_types(self, index: TraceIndex) -> list[Hit]:
        """Report each unknown node type with its node count."""
        return [
            Hit(self.INT003, self.type_ids.get(t, []), {"type": t, "count": count})
            for t, count in index.type_counts.items()
            if t not in NodeType.DESCRIPTOR.values_by_number
        ]

    @rule(INT004)
    def node_count(self, index: TraceIndex) -> list[Hit]:
        """Report the node total of a trace that holds nodes."""
        return [Hit(self.INT004, [], {"count": index.total})] if not index.error and index.total else []
