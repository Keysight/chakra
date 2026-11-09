"""Communication rules COM001 to COM007, fed by the single pass over a trace."""

from collections import Counter
from collections.abc import Iterable

from chakra.schema.protobuf.et_def_pb2 import COMM_COLL_NODE, COMM_RECV_NODE, COMM_SEND_NODE, Node

try:
    from .index_builder import DEFAULT_STREAM, TraceIndex
    from .rule_family import Hit, RuleFamily, register, rule
    from .sampling import add_sample, keep_sample
except ImportError:  # run as a top-level module, not a package
    from index_builder import DEFAULT_STREAM, TraceIndex  # type: ignore[no-redef]
    from rule_family import Hit, RuleFamily, register, rule  # type: ignore[no-redef]
    from sampling import add_sample, keep_sample  # type: ignore[no-redef]


@register
class CommRules(RuleFamily):
    """Missing communication attributes, zero sizes, default-stream collectives."""

    # Rule IDs; each must match an entry in rules.toml
    COM001 = "COM001"  # missing comm_type
    COM002 = "COM002"  # missing comm_size
    COM003 = "COM003"  # missing pg_name
    COM004 = "COM004"  # missing comm_src
    COM005 = "COM005"  # missing comm_dst
    COM006 = "COM006"  # zero comm_size
    COM007 = "COM007"  # all nodes on the default stream

    # Attributes every collective node must carry for replay
    COLL_ATTRS = ("comm_type", "comm_size", "pg_name")

    # Point-to-point nodes must declare a nonzero transfer size and both peers
    P2P_TYPES = (COMM_SEND_NODE, COMM_RECV_NODE)
    P2P_ATTRS = ("comm_size", "comm_src", "comm_dst")

    # Report order of node types
    TYPE_ORDER = (COMM_COLL_NODE, *P2P_TYPES)

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no communication defects."""
        super().__init__(disabled)
        # Per node type: count of nodes missing each attribute or size
        self.missing: dict[int, Counter] = {t: Counter() for t in self.TYPE_ORDER}
        self.ids: dict[tuple[int, str], list[int]] = {}
        self.coll_streamed = 0
        self.coll_default = 0
        self.default_ids: list[int] = []

    def add(self, node: Node, attrs: dict[str, object]) -> None:
        """Record missing attributes and zero sizes of one communication node."""
        node_type, node_id, index = node.type, node.id, self.index
        if node_type not in self.TYPE_ORDER:
            return
        required = self.COLL_ATTRS if node_type == COMM_COLL_NODE else self.P2P_ATTRS
        missing = [name for name in required if not index.has_attr(node_id, name)]
        if index.int_attrs.get("comm_size", {}).get(node_id) == 0:
            missing.append("zero_size")
        self.missing[node_type].update(missing)
        for name in missing:
            add_sample(self.ids, (node_type, name), node_id)  # type: ignore[arg-type]
        if node_type == COMM_COLL_NODE and index.has_attr(node_id, "stream"):
            self.coll_streamed += 1
            if index.stream[node_id] == DEFAULT_STREAM:
                self.coll_default += 1
                keep_sample(self.default_ids, node_id)

    def missing_hits(self, rule_id: str, key: str) -> list[Hit]:
        """List one hit per node type that lacks the named attribute."""
        return [
            Hit(rule_id, self.ids.get((t, key), []), {"count": self.missing[t][key]}, t)
            for t in self.TYPE_ORDER
            if self.missing[t][key]
        ]

    @rule(COM001)
    def missing_type(self, index: TraceIndex) -> list[Hit]:
        """Report collectives without comm_type."""
        return self.missing_hits(self.COM001, "comm_type")

    @rule(COM002)
    def missing_size(self, index: TraceIndex) -> list[Hit]:
        """Report communication nodes without comm_size."""
        return self.missing_hits(self.COM002, "comm_size")

    @rule(COM003)
    def missing_group(self, index: TraceIndex) -> list[Hit]:
        """Report collectives without pg_name."""
        return self.missing_hits(self.COM003, "pg_name")

    @rule(COM004)
    def missing_source(self, index: TraceIndex) -> list[Hit]:
        """Report point-to-point nodes without comm_src."""
        return self.missing_hits(self.COM004, "comm_src")

    @rule(COM005)
    def missing_destination(self, index: TraceIndex) -> list[Hit]:
        """Report point-to-point nodes without comm_dst."""
        return self.missing_hits(self.COM005, "comm_dst")

    @rule(COM006)
    def zero_size(self, index: TraceIndex) -> list[Hit]:
        """Report communication nodes that declare a size of zero."""
        return self.missing_hits(self.COM006, "zero_size")

    @rule(COM007)
    def default_stream(self, index: TraceIndex) -> list[Hit]:
        """Report collectives that all report the default stream."""
        if self.coll_streamed == self.coll_default > 0:
            values = {"count": self.coll_streamed, "stream": DEFAULT_STREAM}
            return [Hit(self.COM007, self.default_ids, values, COMM_COLL_NODE)]
        return []

    def finish(self, index: TraceIndex) -> list[Hit]:
        """Run the checks, then group findings by node type in report order."""
        hits = super().finish(index)
        return sorted(hits, key=lambda h: self.TYPE_ORDER.index(h.node_type))  # type: ignore[arg-type]
