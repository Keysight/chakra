"""
Grading of a trace per consumer; policy comes from the rule catalog.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections import Counter
from dataclasses import dataclass, field

from chakra.schema.protobuf.et_def_pb2 import NodeType

from .catalog import shipped_rules
from .rule_config import (  # noqa: F401  (names are re-exported)
    ANALYSIS,
    CONSUMERS,
    LIMITED,
    NOT_SUITABLE,
    READY,
    REPLAY,
    REVIEW,
    SIMULATOR,
    Rule,
)
from .rule_family import Hit
from .sampling import SAMPLE_LIMIT

CONSUMER_LABELS = [c.capitalize() for c in CONSUMERS]

# Impact value to rank; the worst impact across findings wins
SEVERITY = {READY: 0, LIMITED: 1, REVIEW: 2, NOT_SUITABLE: 3}


@dataclass
class Consumer:
    """One consumer of a trace and the text that explains its verdict."""

    id: str
    name: str
    description: str


# Suitability entry per consumer; each rule's impact sets the verdict
# The first sentence is the short summary; later sentences state the contract
CONSUMER_INFO = {
    REPLAY: Consumer(
        "SUI001",
        REPLAY,
        "Suitability (replay) for Replay: re-executing the recorded operators on hardware. "
        "Replay calls the real operators again, so it needs each operator to be callable "
        "and its inputs to be reconstructable. "
        "It requires collective and point-to-point communication attributes. "
        "Replay reads them from the host-side `record_param_comms` operators (call name, "
        "process group, sizes and dtype), so it needs no device-side communication node. "
        "It also requires replay units: the outermost CPU nodes (`is_cpu_op` true) that carry "
        "a non-empty `op_schema`, with I/O that fits that schema. "
        "Replay runs a unit together with its whole subtree, so descendants are not graded. "
        "GPU kernels need no schema, because replay runs the CPU operator that launches them. "
        "Durations may be zero, because replay runs the operator and does not model its time. "
        "The verdict is the worst replay value in the consumer impact of the rules that fired; "
        "the report lists which rules caused it.",
    ),
    SIMULATOR: Consumer(
        "SUI002",
        SIMULATOR,
        "Suitability (simulator) for Simulator: modeling execution time from the graph. "
        "The simulator does not run any operator; it predicts the run time, possibly for "
        "different hardware or a different configuration, from the structure of the graph "
        "and the cost of each node. "
        "It requires communication attributes (type, size and groups) to model collectives "
        "and point-to-point transfers. "
        "It also requires a duration or an I/O size for each compute node, so that the "
        "simulator can assign a cost to every node. "
        "It does not need an `op_schema` or a device link. "
        "Synthetic traces skip the timing and Kineto checks, so they favor the simulator. "
        "The verdict is the worst simulator value in the consumer impact of the rules that fired; "
        "the report lists which rules caused it.",
    ),
    ANALYSIS: Consumer(
        "SUI003",
        ANALYSIS,
        "Suitability (analysis) for Analysis: studying the timing and structure of a captured run. "
        "Analysis predicts and executes nothing; it reads the measured timing and the graph "
        "structure of a run that already happened, to show where the time went. "
        "It requires nonzero durations, because it computes from the measured times. "
        "It also requires a device link, so that it can attribute time to kernels on the device. "
        "It also reads the capture metadata, the header block that describes the recording "
        "session (rules MET003-MET007): "
        "`pid` (process ID of the captured program) ties the capture to its source process; "
        "`time` (wall-clock date and time) places the capture in time; "
        "`start_ts` and `finish_ts` (capture window in microseconds on the profiler clock) "
        "give the capture duration, and `finish_ts` must not precede `start_ts`. "
        "Missing metadata lowers the analysis verdict to LIMITED. "
        "Replay and the simulator do not use the capture metadata. "
        "It does not need an `op_schema`. "
        "The verdict is the worst analysis value in the consumer impact of the rules that fired; "
        "the report lists which rules caused it.",
    ),
}

# --- Findings and issues -------------------------------------------------


class Sampled:
    """Mixin for records that render a message with sample node IDs."""

    @staticmethod
    def sample_text(message: str, ids: list[int] | None) -> str:
        """Append the count and sample node IDs, as (17 nodes, 9, 41...65)."""
        count = getattr(message, "total", None)
        ids = ids or []
        parts = []
        if count:
            noun = getattr(message, "noun", ("node", "nodes"))[count != 1]
            parts.append(f"{count:,} {noun}")
        if count and count > len(ids) and len(ids) == SAMPLE_LIMIT:
            parts.append(f"{ids[0]}, {ids[1]}...{ids[2]}")  # head, second, last
        elif ids:
            parts.append(", ".join(map(str, ids)))
        return f"{message} ({', '.join(parts)})" if parts else str(message)


@dataclass
class Finding(Sampled):
    """One CLI finding; node_ids is empty for a trace-level finding."""

    severity: str
    message: str
    rule: str
    node_ids: list[int] = field(default_factory=list)

    def text(self) -> str:
        """Return the message with its node count and sample node IDs."""
        return self.sample_text(self.message, self.node_ids)


@dataclass
class Issue(Sampled):
    """An integrity defect or warning with a rule ID and sample node IDs."""

    rule: str
    message: str
    ids: list[int] = field(default_factory=list)

    def text(self) -> str:
        """Return the message with its sample node IDs."""
        return self.sample_text(self.message, self.ids)


# --- Gaps ----------------------------------------------------------------


@dataclass
class Gap(Sampled):
    """A capability gap and the consumers it affects."""

    message: str
    consumer_impact: dict[str, str]
    node_type: int | None = None
    ids: list[int] = field(default_factory=list)  # sample affected node IDs
    rule: str = ""  # stable rule ID for CLI output

    def text(self) -> str:
        """Return the message, led by the node type the gap concerns."""
        text = self.sample_text(self.message, self.ids)
        if self.node_type is None:
            return text
        return f"{self.type_name(self.node_type)}: {text}"

    def severity(self) -> int:
        """Return the worst impact the gap sets across its consumers."""
        return max(SEVERITY[impact] for impact in self.consumer_impact.values())

    @staticmethod
    def type_name(node_type: int) -> str:
        """Name a node type, tolerating values missing from the schema."""
        try:
            return NodeType.Name(node_type)
        except ValueError:
            return f"UNKNOWN({node_type})"

    @staticmethod
    def impact_of(rule: str, rules: dict[str, Rule] | None = None) -> dict[str, str]:
        """Return the impact a finding of `rule` sets per consumer it affects."""
        impact = (rules or shipped_rules())[rule].consumer_impact
        return {consumer: value for consumer, value in impact.items() if value != READY}

    @classmethod
    def from_hit(cls, hit: Hit, message: str, rules: dict[str, Rule] | None = None) -> "Gap":
        """Turn a family hit and its rendered message into the gap it implies."""
        return cls(message, cls.impact_of(hit.rule, rules), hit.node_type, ids=hit.ids, rule=hit.rule)


# --- Trace result --------------------------------------------------------


@dataclass
class TraceResult:
    """Outcome of linting one trace."""

    problems: list[str] = field(default_factory=list)
    values: dict[str, object] = field(default_factory=dict)  # trace-wide placeholders
    total: int = 0
    elapsed: float = 0.0
    type_counts: Counter = field(default_factory=Counter)
    gaps: list[Gap] = field(default_factory=list)
    notes: list[Issue] = field(default_factory=list)  # informational only
    synthetic: bool = False  # generated, not captured; no device merge
    pytorch_nodes: int = 0  # nodes carrying PyTorch-only attributes
    fatal_rule: str = ""  # rule that stopped the scan, if any
    findings: list[Finding] = field(default_factory=list)  # shown hits

    @staticmethod
    def aggregates() -> dict[str, Consumer]:
        """Return the suitability entries in consumer order."""
        return {consumer: CONSUMER_INFO[consumer] for consumer in CONSUMERS}

    def status(self, consumer: str) -> tuple[str, list[str]]:
        """Return a consumer's impact and the reasons for it."""
        hits = []
        # A fatal finding stops the scan and rules out every consumer
        if self.problems:
            hits.append((NOT_SUITABLE, self.problems[0]))
        hits += [(g.consumer_impact[consumer], g.text()) for g in self.gaps if consumer in g.consumer_impact]
        if not hits:
            return READY, []
        worst = max((impact for impact, _ in hits), key=SEVERITY.__getitem__)
        return worst, [reason for impact, reason in hits if impact == worst]

    def causes(self, consumer: str) -> list[str]:
        """Return the distinct rule IDs that set a consumer's impact."""
        impact = self.status(consumer)[0]
        if impact == READY:
            return []
        rules = []
        # A fatal finding sets NOT SUITABLE, so it causes only that impact
        if impact == NOT_SUITABLE and self.problems:
            rules.append(self.fatal_rule)
        rules += [g.rule for g in self.gaps if g.consumer_impact.get(consumer) == impact]
        return list(dict.fromkeys(rules))
