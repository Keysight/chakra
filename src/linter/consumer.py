"""Grading of a trace per consumer; policy comes from `rules.toml`."""

from collections import Counter
from dataclasses import dataclass, field

from chakra.schema.protobuf.et_def_pb2 import NodeType

try:
    from .rule_config import Consumer, shipped_consumers, shipped_remediations, shipped_rules
    from .rule_family import Hit
    from .sampling import SAMPLE_LIMIT
except ImportError:  # run as a top-level module, not a package
    from rule_config import Consumer, shipped_consumers, shipped_remediations, shipped_rules  # type: ignore[no-redef]
    from rule_family import Hit  # type: ignore[no-redef]
    from sampling import SAMPLE_LIMIT  # type: ignore[no-redef]

# Consumers a trace may serve; each reports its own impact
REPLAY, SIMULATOR, ANALYSIS = "replay", "simulator", "analysis"
CONSUMERS = (REPLAY, SIMULATOR, ANALYSIS)
CONSUMER_LABELS = [c.capitalize() for c in CONSUMERS]

# Consumer impact values; LIMITED: known gap, REVIEW: linter cannot decide
READY, LIMITED, REVIEW, NOT_SUITABLE = "READY", "LIMITED", "REVIEW", "NOT SUITABLE"
SEVERITY = {READY: 0, LIMITED: 1, REVIEW: 2, NOT_SUITABLE: 3}

# Evidence groups; each gap lowers one group to a named level
TIMING, KINETO, COMM, OP_SCHEMA = "TIMING", "KINETO", "COMM", "OP_SCHEMA"
IO, META, ATTR = "IO", "META", "ATTR"
NOT_APPLICABLE, NO_CPU = "N/A", "NO CPU OPS"

# Integrity checks; any failure makes the trace fail integrity
DECODE, CONTENT, SCHEMA, DAG = "DECODE", "CONTENT", "SCHEMA", "DAG"
PASS, FAIL = "PASS", "FAIL"


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
    group: str | None = None  # evidence group the gap lowers, if any
    level: str = ""  # level the gap sets for its group
    ids: list[int] = field(default_factory=list)  # sample affected node IDs
    fix: str = ""  # next step from rules.toml
    rule: str = ""  # stable rule ID for CLI output

    def remediation(self) -> str:
        """Return the next step that closes this gap."""
        return self.fix

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
        rule = shipped_rules()[hit.rule]
        fix = rule.remediation or shipped_remediations().get(rule.remediation_key(), "")
        return cls(
            message,
            cls.impact_of(hit.rule),
            hit.node_type,
            rule.group or None,
            rule.level,
            ids=hit.ids,
            fix=fix,
            rule=hit.rule,
        )


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
    schema_problems: dict[int, Issue] = field(default_factory=dict)
    dag_problems: list[Issue] | None = None  # None when not checked
    readable: bool = True
    synthetic: bool = False  # generated, not captured; no device merge
    pytorch_nodes: int = 0  # nodes carrying PyTorch-only attributes
    fatal_rule: str = ""  # rule that stopped the scan, if any
    findings: list[Finding] = field(default_factory=list)  # shown hits

    @staticmethod
    def aggregates() -> dict[str, Consumer]:
        """Return the shipped aggregates in consumer order."""
        shipped = shipped_consumers()
        return {consumer: shipped[consumer] for consumer in CONSUMERS}

    def invalid(self) -> bool:
        """Return True on an integrity defect; gaps never invalidate."""
        return bool(self.problems or self.dag_problems or self.schema_problems)

    def integrity(self) -> str:
        """Return PASS when every integrity check passes, else FAIL."""
        return FAIL if self.invalid() else PASS

    def failed_checks(self) -> list[str]:
        """Name the integrity checks that fail."""
        checks = []
        if self.problems:
            checks.append(CONTENT if self.readable else DECODE)
        if self.schema_problems:
            checks.append(SCHEMA)
        if self.dag_problems:
            checks.append(DAG)
        return checks

    def next_steps(self) -> list[str]:
        """Return distinct next steps, integrity first, then by gap severity."""
        shared = shipped_remediations()
        steps = [shared[check] for check in self.failed_checks()]
        by_severity = sorted(self.gaps, key=Gap.severity, reverse=True)
        steps += [gap.remediation() for gap in by_severity]
        return list(dict.fromkeys(step for step in steps if step))

    def status(self, consumer: str) -> tuple[str, list[str]]:
        """Return a consumer's impact and the reasons for it."""
        hits = []
        failed = ", ".join(self.failed_checks())
        if failed:
            hits.append((NOT_SUITABLE, f"integrity defect: {failed}"))
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
        # Integrity defects set NOT SUITABLE, so they cause only that impact
        if impact == NOT_SUITABLE:
            if self.problems:
                rules.append(self.fatal_rule)
            rules += [issue.rule for issue in self.schema_problems.values()]
            rules += [issue.rule for issue in self.dag_problems or []]
        rules += [g.rule for g in self.gaps if g.consumer_impact.get(consumer) == impact]
        return list(dict.fromkeys(rules))
