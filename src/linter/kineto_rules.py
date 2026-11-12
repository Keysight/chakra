"""
Kineto rules fed by the single pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections import Counter
from collections.abc import Iterable

from chakra.schema.protobuf.et_def_pb2 import COMM_COLL_NODE, COMM_RECV_NODE, COMM_SEND_NODE, COMP_NODE, Node

from .index_builder import DEFAULT_STREAM, TraceIndex
from .rule_config import ERROR, LIMITED, NOT_SUITABLE, REVIEW, WARNING
from .rule_family import Hit, RuleFamily, register, rule
from .sampling import add_sample, keep_sample, tally

# Share of zero-duration nodes above which timing is absent for a trace
ZERO_WARN_RATIO = 0.5

# Share above which timing is partial; healthy samples stay below 5%
ZERO_PARTIAL_RATIO = 0.05

# Node types whose durations must not all be zero
CHECKED_TYPES = {
    COMP_NODE: "compute",
    COMM_COLL_NODE: "collective",
    COMM_SEND_NODE: "send",
    COMM_RECV_NODE: "receive",
}


@register
class KinetoRules(RuleFamily):
    """Device links of captured traces, and absent, partial, or unknown durations."""

    order = 80

    # Rule IDs; each names the `@rule` that declares it
    KIN001 = "KIN001"  # no stream attribute on any node
    KIN002 = "KIN002"  # streams present, no durations
    KIN003 = "KIN003"  # device node without host parent
    KIN004 = "KIN004"  # device node with several host parents
    KIN005 = "KIN005"  # device node without host parent, no durations
    KIN006 = "KIN006"  # device node with several host parents, no durations
    KIN007 = "KIN007"  # no node has a duration
    KIN008 = "KIN008"  # some nodes lack a duration
    KIN009 = "KIN009"  # synthetic trace without durations

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no stream data."""
        super().__init__(disabled)
        self.streams: Counter = Counter()
        self.timed = 0  # nodes on a stream with a nonzero duration
        self.no_stream_ids: list[int] = []
        self.zero_ids: list[int] = []  # streamed nodes with zero duration
        self.device_parents: dict[int, tuple[int, ...]] = {}  # off the default stream
        self.zero = 0  # nodes with zero duration, streamed or not
        self.zero_by_type: Counter = Counter()
        self.zero_node_ids: list[int] = []
        self.zero_type_ids: dict[int, list[int]] = {}

    def add(self, node: Node) -> None:
        """Record the stream, duration, and parents of one node."""
        index, node_id = self.index, node.id
        if node.duration_micros == 0:
            self.zero += 1
            self.zero_by_type[node.type] += 1
            keep_sample(self.zero_node_ids, node_id)
            add_sample(self.zero_type_ids, node.type, node_id)  # type: ignore[arg-type]
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

    @rule(
        KIN001,
        name="kineto-no-stream",
        severity=ERROR,
        message="no node has a stream attribute (no device data); disable KIN001 for CPU-only captures",
        description=(
            "No node has a stream attribute. The trace holds no device data, so the host trace was not linked "
            "to the Kineto device trace. A genuine CPU-only capture also triggers this rule; disable it for "
            "such traces."
        ),
        simulator=REVIEW,
        analysis=NOT_SUITABLE,
    )
    def no_streams(self, index: TraceIndex) -> list[Hit]:
        """Report a trace in which no node has a stream attribute."""
        if index.synthetic or self.streams:
            return []
        return [Hit(self.KIN001, self.no_stream_ids, {})]

    @rule(
        KIN002,
        name="kineto-no-duration",
        severity=ERROR,
        message="stream data present but no node has a duration",
        description=(
            "Nodes carry stream data but none has a duration. Device activity was linked without timing, so "
            "timing analysis is impossible."
        ),
        simulator=REVIEW,
        analysis=NOT_SUITABLE,
    )
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

    @rule(
        KIN003,
        name="kineto-orphan",
        severity=WARNING,
        message="device node has no host parent",
        description=(
            "A device node (a GPU operation on a stream other than 0) has no host parent in the trace, so it "
            "is an orphan, while some nodes carry durations. The link between host operator and device kernel "
            "is lost. KIN005 covers a trace without durations."
        ),
        simulator=LIMITED,
        analysis=LIMITED,
    )
    def orphan_device_nodes(self, index: TraceIndex) -> list[Hit]:
        """Report device nodes with no parent; some nodes carry durations."""
        return self.parent_hit(self.KIN003, multi=False, untimed=False, index=index)

    @rule(
        KIN004,
        name="kineto-multi-parent",
        severity=WARNING,
        message="device node has multiple host parents",
        description=(
            "A device node has more than one host parent, while some nodes carry durations. The link between "
            "host operator and device kernel is ambiguous. KIN006 covers a trace without durations."
        ),
        simulator=LIMITED,
        analysis=LIMITED,
    )
    def multi_parent_device_nodes(self, index: TraceIndex) -> list[Hit]:
        """Report device nodes with several parents; some carry durations."""
        return self.parent_hit(self.KIN004, multi=True, untimed=False, index=index)

    @rule(
        KIN005,
        name="kineto-orphan-untimed",
        severity=ERROR,
        message="device node has no host parent and no node has a duration",
        description=(
            "A device node (a GPU operation on a stream other than 0) has no host parent, so it is an orphan, "
            "and no node carries a duration. The link between host operator and device kernel is lost, and "
            "the device data holds no timing. KIN003 covers a trace with durations."
        ),
        simulator=REVIEW,
        analysis=NOT_SUITABLE,
    )
    def orphan_device_nodes_untimed(self, index: TraceIndex) -> list[Hit]:
        """Report device nodes with no parent; no node carries a duration."""
        return self.parent_hit(self.KIN005, multi=False, untimed=True, index=index)

    @rule(
        KIN006,
        name="kineto-multi-parent-untimed",
        severity=ERROR,
        message="device node has multiple host parents and no node has a duration",
        description=(
            "A device node has more than one host parent, and no node carries a duration. The link between "
            "host operator and device kernel is ambiguous, and the device data holds no timing. KIN004 covers "
            "a trace with durations."
        ),
        simulator=REVIEW,
        analysis=NOT_SUITABLE,
    )
    def multi_parent_device_nodes_untimed(self, index: TraceIndex) -> list[Hit]:
        """Report device nodes with several parents; no node carries a duration."""
        return self.parent_hit(self.KIN006, multi=True, untimed=True, index=index)

    def absent_types(self, index: TraceIndex) -> list[tuple[int, int]]:
        """List (type, count) of checked types whose nodes all lack duration."""
        # A trace with no durations at all reports once, at trace level
        if index.synthetic or self.zero == index.total:
            return []
        return [
            (node_type, count)
            for node_type, count in index.type_counts.items()
            if node_type in CHECKED_TYPES and self.zero_by_type[node_type] == count
        ]

    @rule(
        KIN007,
        name="timing-absent",
        severity=WARNING,
        message="zero duration; timing absent",
        description=(
            "Timing is absent. More than 50% of all nodes have zero duration, or every node of one checked "
            "type does (compute, collective, send or receive). The merge of host and device data likely did "
            "not complete. Analysis cannot use the trace, and the simulator needs review."
        ),
        simulator=REVIEW,
        analysis=NOT_SUITABLE,
    )
    def timing_absent(self, index: TraceIndex) -> list[Hit]:
        """Report types with no durations first, then trace-wide absence."""
        absent = self.absent_types(index)
        hits = [
            Hit(self.KIN007, self.zero_type_ids.get(t, []), {"count": count, "total": count}, t) for t, count in absent
        ]
        if index.synthetic:
            return hits
        ratio = {"count": self.zero, "total": index.total}
        # Per-type reports already cover the trace; only a full-zero trace adds one
        if self.zero == index.total or (not absent and self.zero / index.total > ZERO_WARN_RATIO):
            hits.append(Hit(self.KIN007, self.zero_node_ids, ratio))
        return hits

    @rule(
        KIN008,
        name="timing-partial",
        severity=WARNING,
        message="zero duration; timing partial",
        description=(
            "Timing is partial. Between 5% and 50% of all nodes have zero duration; healthy traces stay at or "
            "below 5%. Analysis fidelity drops, while replay and simulation still work."
        ),
        analysis=LIMITED,
    )
    def timing_partial(self, index: TraceIndex) -> list[Hit]:
        """Report a share of zero durations between the partial and absent bars."""
        if index.synthetic or self.absent_types(index):
            return []
        if self.zero / index.total > ZERO_WARN_RATIO or self.zero / index.total <= ZERO_PARTIAL_RATIO:
            return []
        return [Hit(self.KIN008, self.zero_node_ids, {"count": self.zero, "total": index.total})]

    @rule(
        KIN009,
        name="synthetic-timing-unknown",
        severity=WARNING,
        message="zero duration on all nodes; modeled values unknown",
        description=(
            "A synthetic (generated) trace has zero duration on every node. The linter cannot tell whether "
            "the generator models durations, so a reviewer decides whether analysis applies."
        ),
        analysis=REVIEW,
    )
    def synthetic_timing(self, index: TraceIndex) -> list[Hit]:
        """Report a generated trace whose every duration is zero."""
        if index.synthetic and self.zero == index.total:
            return [Hit(self.KIN009, self.zero_node_ids, {"count": self.zero, "total": index.total})]
        return []
