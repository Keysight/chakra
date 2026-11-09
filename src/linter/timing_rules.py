"""Timing rules TIM001 to TIM003, fed by the single pass over a trace."""

from collections import Counter
from collections.abc import Iterable

from chakra.schema.protobuf.et_def_pb2 import COMM_COLL_NODE, COMM_RECV_NODE, COMM_SEND_NODE, COMP_NODE, Node

try:
    from .index_builder import TraceIndex
    from .rule_family import Hit, RuleFamily, register, rule
    from .sampling import add_sample, keep_sample
except ImportError:  # run as a top-level module, not a package
    from index_builder import TraceIndex  # type: ignore[no-redef]
    from rule_family import Hit, RuleFamily, register, rule  # type: ignore[no-redef]
    from sampling import add_sample, keep_sample  # type: ignore[no-redef]

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
class TimingRules(RuleFamily):
    """Absent, partial, and unknown durations."""

    # Rule IDs; each must match an entry in rules.toml
    TIM001 = "TIM001"  # no node has a duration
    TIM002 = "TIM002"  # some nodes lack a duration
    TIM003 = "TIM003"  # synthetic trace without durations

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no zero-duration nodes."""
        super().__init__(disabled)
        self.zero = 0
        self.zero_by_type: Counter = Counter()
        self.zero_ids: list[int] = []
        self.zero_type_ids: dict[int, list[int]] = {}

    def add(self, node: Node, attrs: dict[str, object]) -> None:
        """Count a node with zero duration, in total and by node type."""
        if node.duration_micros == 0:
            self.zero += 1
            self.zero_by_type[node.type] += 1
            keep_sample(self.zero_ids, node.id)
            add_sample(self.zero_type_ids, node.type, node.id)  # type: ignore[arg-type]

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

    @rule(TIM001)
    def timing_absent(self, index: TraceIndex) -> list[Hit]:
        """Report types with no durations first, then trace-wide absence."""
        absent = self.absent_types(index)
        hits = [
            Hit(self.TIM001, self.zero_type_ids.get(t, []), {"count": count, "total": count}, t) for t, count in absent
        ]
        if index.synthetic:
            return hits
        ratio = {"count": self.zero, "total": index.total}
        # Per-type reports already cover the trace; only a full-zero trace adds one
        if self.zero == index.total or (not absent and self.zero / index.total > ZERO_WARN_RATIO):
            hits.append(Hit(self.TIM001, self.zero_ids, ratio))
        return hits

    @rule(TIM002)
    def timing_partial(self, index: TraceIndex) -> list[Hit]:
        """Report a share of zero durations between the partial and absent bars."""
        if index.synthetic or self.absent_types(index):
            return []
        if self.zero / index.total > ZERO_WARN_RATIO or self.zero / index.total <= ZERO_PARTIAL_RATIO:
            return []
        return [Hit(self.TIM002, self.zero_ids, {"count": self.zero, "total": index.total})]

    @rule(TIM003)
    def synthetic_timing(self, index: TraceIndex) -> list[Hit]:
        """Report a generated trace whose every duration is zero."""
        if index.synthetic and self.zero == index.total:
            return [Hit(self.TIM003, self.zero_ids, {"count": self.zero, "total": index.total})]
        return []
