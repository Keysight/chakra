"""
Kineto rules fed by the single pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections import Counter
from collections.abc import Iterable

from chakra.schema.protobuf.et_def_pb2 import Node

try:
    from .index_builder import DEFAULT_STREAM, TraceIndex
    from .rule_family import Hit, RuleFamily, register, rule
    from .sampling import keep_sample, tally
except ImportError:  # run as a top-level module, not a package
    from index_builder import DEFAULT_STREAM, TraceIndex  # type: ignore[no-redef]
    from rule_family import Hit, RuleFamily, register, rule  # type: ignore[no-redef]
    from sampling import keep_sample, tally  # type: ignore[no-redef]


@register
class KinetoRules(RuleFamily):
    """Stream, duration, and parent links of device nodes; captured traces only."""

    order = 80

    # Rule IDs; each must match an entry in rules.toml
    KIN001 = "KIN001"  # no stream attribute on any node
    KIN002 = "KIN002"  # streams present, no durations
    KIN003 = "KIN003"  # device node without host parent
    KIN004 = "KIN004"  # device node with several host parents
    KIN005 = "KIN005"  # device node without host parent, no durations
    KIN006 = "KIN006"  # device node with several host parents, no durations

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no stream data."""
        super().__init__(disabled)
        self.streams: Counter = Counter()
        self.timed = 0  # nodes on a stream with a nonzero duration
        self.no_stream_ids: list[int] = []
        self.zero_ids: list[int] = []  # streamed nodes with zero duration
        self.device_parents: dict[int, tuple[int, ...]] = {}  # off the default stream

    def add(self, node: Node) -> None:
        """Record the stream, duration, and parents of one node."""
        index, node_id = self.index, node.id
        if not index.has_attr(node_id, "stream"):
            keep_sample(self.no_stream_ids, node_id)
            return
        stream = index.stream[node_id]
        self.streams[stream] += 1
        self.timed += node.duration_micros > 0
        if node.duration_micros == 0:
            keep_sample(self.zero_ids, node_id)
        if stream != DEFAULT_STREAM:
            self.device_parents[node_id] = index.ctrl_deps[node_id]

    @rule(KIN001)
    def no_streams(self, index: TraceIndex) -> list[Hit]:
        """Report a trace in which no node has a stream attribute."""
        if index.synthetic or self.streams:
            return []
        return [Hit(self.KIN001, self.no_stream_ids, {})]

    @rule(KIN002)
    def no_durations(self, index: TraceIndex) -> list[Hit]:
        """Report streams whose nodes all lack a duration."""
        if index.synthetic or not self.streams or self.timed:
            return []
        return [Hit(self.KIN002, self.zero_ids, {})]

    def parent_hit(self, rule_id: str, multi: bool, untimed: bool, index: TraceIndex) -> list[Hit]:
        """Report device nodes with no parent, or several; split by timing."""
        if index.synthetic or not self.streams or bool(self.timed) == untimed:
            return []
        ids = index.ctrl_deps
        if multi:
            count, sample = tally((n, sum(p in ids for p in ps) > 1) for n, ps in self.device_parents.items())
        else:
            count, sample = tally((n, not any(p in ids for p in ps)) for n, ps in self.device_parents.items())
        return [Hit(rule_id, sample, {"count": count})] if count else []

    @rule(KIN003)
    def orphan_device_nodes(self, index: TraceIndex) -> list[Hit]:
        """Report device nodes with no parent; some nodes carry durations."""
        return self.parent_hit(self.KIN003, multi=False, untimed=False, index=index)

    @rule(KIN004)
    def multi_parent_device_nodes(self, index: TraceIndex) -> list[Hit]:
        """Report device nodes with several parents; some carry durations."""
        return self.parent_hit(self.KIN004, multi=True, untimed=False, index=index)

    @rule(KIN005)
    def orphan_device_nodes_untimed(self, index: TraceIndex) -> list[Hit]:
        """Report device nodes with no parent; no node carries a duration."""
        return self.parent_hit(self.KIN005, multi=False, untimed=True, index=index)

    @rule(KIN006)
    def multi_parent_device_nodes_untimed(self, index: TraceIndex) -> list[Hit]:
        """Report device nodes with several parents; no node carries a duration."""
        return self.parent_hit(self.KIN006, multi=True, untimed=True, index=index)
