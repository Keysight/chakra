"""Grading of a trace per consumer; policy comes from `rules.toml`."""

from collections import Counter
from dataclasses import dataclass, field

from chakra.schema.protobuf.et_def_pb2 import NodeType

try:
    from .rule_config import Consumer, shipped_consumers, shipped_rules
    from .rule_family import Hit
    from .sampling import SAMPLE_LIMIT
except ImportError:  # run as a top-level module, not a package
    from rule_config import Consumer, shipped_consumers, shipped_rules  # type: ignore[no-redef]
    from rule_family import Hit  # type: ignore[no-redef]
    from sampling import SAMPLE_LIMIT  # type: ignore[no-redef]

# Consumers a trace may serve; each reports its own impact
REPLAY, SIMULATOR, ANALYSIS = "replay", "simulator", "analysis"
CONSUMERS = (REPLAY, SIMULATOR, ANALYSIS)
CONSUMER_LABELS = [c.capitalize() for c in CONSUMERS]

# Consumer impact values; LIMITED: known gap, REVIEW: linter cannot decide
READY, LIMITED, REVIEW, NOT_SUITABLE = "READY", "LIMITED", "REVIEW", "NOT SUITABLE"
SEVERITY = {READY: 0, LIMITED: 1, REVIEW: 2, NOT_SUITABLE: 3}

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
    def impact_of(rule: str) -> dict[str, str]:
        """Return the impact a finding of `rule` sets per consumer it affects."""
        impact = shipped_rules()[rule].consumer_impact
        return {consumer: value for consumer, value in impact.items() if value != READY}

    @classmethod
    def from_hit(cls, hit: Hit, message: str) -> "Gap":
        """Turn a family hit and its rendered message into the gap it implies."""
        return cls(message, cls.impact_of(hit.rule), hit.node_type, ids=hit.ids, rule=hit.rule)


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
        """Return the shipped aggregates in consumer order."""
        shipped = shipped_consumers()
        return {consumer: shipped[consumer] for consumer in CONSUMERS}

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
