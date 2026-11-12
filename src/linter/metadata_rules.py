"""
Metadata rules fed by the single pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections.abc import Iterable

from chakra.schema.protobuf.et_def_pb2 import Node, NodeType

from .index_builder import TraceIndex
from .rule_config import ERROR, FATAL, INFO, LIMITED, NOT_SUITABLE, REVIEW, WARNING
from .rule_family import Hit, RuleFamily, register, rule
from .sampling import add_sample


@register
class MetadataRules(RuleFamily):
    """Unreadable files, empty traces, unknown node types, and capture metadata."""

    # Leads the report: the fatal rules MET009 and MET010 run before the others
    order = 10

    # Rule IDs; each names the `@rule` that declares it
    MET001 = "MET001"  # version: required, every trace
    MET002 = "MET002"  # schema
    MET003 = "MET003"  # pid
    MET004 = "MET004"  # time
    MET005 = "MET005"  # start_ts
    MET006 = "MET006"  # finish_ts
    MET007 = "MET007"  # finish_ts before start_ts
    MET008 = "MET008"  # schema the converter does not support
    MET009 = "MET009"  # file cannot be decoded
    MET010 = "MET010"  # trace holds no nodes
    MET011 = "MET011"  # node type unknown to the schema
    MET012 = "MET012"  # node count of a readable trace

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no unknown types."""
        super().__init__(disabled)
        self.type_ids: dict[int, list[int]] = {}  # sample node IDs per unknown type

    def add(self, node: Node) -> None:
        """Sample the nodes of a type that the schema does not define."""
        if node.type not in NodeType.DESCRIPTOR.values_by_number:
            add_sample(self.type_ids, node.type, node.id)  # type: ignore[arg-type]

    # Schema values the converter accepts; a test pins them to PyTorchNode
    SUPPORTED_SCHEMAS = (
        "1.0.2-chakra.0.0.4",
        "1.0.3-chakra.0.0.4",
        "1.1.0-chakra.0.0.4",
        "1.1.1-chakra.0.0.4",
        "1.1.1-chakra.1.0.0",
    )

    # Global metadata attributes the PyTorch converter writes, by rule
    METADATA_ATTRS = {
        MET002: "schema",
        MET003: "pid",
        MET004: "time",
        MET005: "start_ts",
        MET006: "finish_ts",
    }

    def missing_attr(self, index: TraceIndex, rule_id: str) -> list[Hit]:
        """Report one converter attribute absent from a PyTorch header."""
        name = self.METADATA_ATTRS[rule_id]
        if index.pytorch_nodes and name not in index.header:
            return [Hit(rule_id, [], {"name": name})]
        return []

    @rule(
        MET001,
        name="meta-missing-version",
        severity=WARNING,
        message="global metadata lacks a version number",
        description=(
            "The global metadata of the trace carries no schema version. Readers cannot tell which Chakra "
            "schema wrote the trace, so no consumer can trust how to decode it. This is the only required "
            "metadata attribute."
        ),
        replay=REVIEW,
        simulator=REVIEW,
        analysis=REVIEW,
    )
    def missing_version(self, index: TraceIndex) -> list[Hit]:
        """Report a header that carries no schema version."""
        if "version" not in index.header:
            return [Hit(self.MET001, [], {})]
        return []

    @rule(
        MET002,
        name="meta-missing-schema",
        severity=WARNING,
        message="global metadata lacks {name} attribute",
        description=(
            "The global metadata of a PyTorch-derived trace lacks the schema attribute, the version string of "
            "the PyTorch execution trace format (for example 1.1.1-chakra.0.0.4). The Chakra converter copies "
            "it from the host trace header. Reviewers cannot confirm which format produced the capture."
        ),
        replay=REVIEW,
        simulator=REVIEW,
        analysis=REVIEW,
    )
    def missing_schema(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the schema attribute."""
        return self.missing_attr(index, self.MET002)

    @rule(
        MET003,
        name="meta-missing-pid",
        severity=WARNING,
        message="global metadata lacks {name} attribute",
        description=(
            "The global metadata of a PyTorch-derived trace lacks the pid attribute, the process ID of the "
            "captured program. The Chakra converter copies it from the host trace header; the Kineto device "
            "trace carries the same pid. Analysis cannot tie the capture to its source process. Replay and "
            "simulation do not use it."
        ),
        analysis=LIMITED,
    )
    def missing_pid(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the pid attribute."""
        return self.missing_attr(index, self.MET003)

    @rule(
        MET004,
        name="meta-missing-time",
        severity=WARNING,
        message="global metadata lacks {name} attribute",
        description=(
            "The global metadata of a PyTorch-derived trace lacks the time attribute, the wall-clock date and "
            "time of the capture (for example 2026-11-03 09:49:39). The Chakra converter copies it from the "
            "host trace header. Analysis cannot place the capture in time. Replay and simulation do not use "
            "it."
        ),
        analysis=LIMITED,
    )
    def missing_time(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the time attribute."""
        return self.missing_attr(index, self.MET004)

    @rule(
        MET005,
        name="meta-missing-start-ts",
        severity=WARNING,
        message="global metadata lacks {name} attribute",
        description=(
            "The global metadata of a PyTorch-derived trace lacks the start_ts attribute, the start of the "
            "capture window in microseconds on the profiler clock. The Chakra converter copies it from the "
            "host trace header. Analysis cannot compute the capture duration. MET007 checks the order of "
            "start_ts and finish_ts."
        ),
        analysis=LIMITED,
    )
    def missing_start_ts(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the start_ts attribute."""
        return self.missing_attr(index, self.MET005)

    @rule(
        MET006,
        name="meta-missing-finish-ts",
        severity=WARNING,
        message="global metadata lacks {name} attribute",
        description=(
            "The global metadata of a PyTorch-derived trace lacks the finish_ts attribute, the end of the "
            "capture window in microseconds on the profiler clock. The Chakra converter copies it from the "
            "host trace header. Analysis cannot compute the capture duration. MET007 checks the order of "
            "start_ts and finish_ts."
        ),
        analysis=LIMITED,
    )
    def missing_finish_ts(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the finish_ts attribute."""
        return self.missing_attr(index, self.MET006)

    @rule(
        MET007,
        name="meta-time-order",
        severity=WARNING,
        message="global metadata finish_ts {finish} precedes start_ts {start}",
        description=(
            "The finish_ts of a PyTorch-derived trace precedes its start_ts. The capture window is "
            "inconsistent, so timing analysis cannot rely on it."
        ),
        analysis=LIMITED,
    )
    def inverted_times(self, index: TraceIndex) -> list[Hit]:
        """Report a capture that finishes before it starts."""
        start, finish = index.header.get("start_ts"), index.header.get("finish_ts")
        if index.pytorch_nodes and isinstance(start, int) and isinstance(finish, int) and finish < start:
            return [Hit(self.MET007, [], {"start": start, "finish": finish})]
        return []

    @rule(
        MET008,
        name="meta-unsupported-schema",
        severity=WARNING,
        message="global metadata schema {value} is not supported by the converter",
        description=(
            "The schema attribute of a PyTorch-derived trace names a PyTorch execution trace format that the "
            "Chakra converter does not support. The converter rejects such a trace, so this one came from "
            "another or a newer converter. Readers may misread its attributes."
        ),
        replay=REVIEW,
        simulator=REVIEW,
        analysis=REVIEW,
    )
    def unsupported_schema(self, index: TraceIndex) -> list[Hit]:
        """Report a schema value that the converter does not support."""
        value = index.header.get("schema")
        if index.pytorch_nodes and isinstance(value, str) and value not in self.SUPPORTED_SCHEMAS:
            return [Hit(self.MET008, [], {"value": value})]
        return []

    @rule(
        MET009,
        name="decode-failure",
        severity=FATAL,
        required=True,
        message="decode failure: {error}",
        description=(
            "The Chakra protobuf decoder cannot read the file. Causes include a corrupt, truncated or "
            "non-Chakra file. Every use is unsuitable because no node can be read."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=NOT_SUITABLE,
    )
    def decode_failure(self, index: TraceIndex) -> list[Hit]:
        """Report a file that the decoder could not read."""
        return [Hit(self.MET009, [], {"error": index.error})] if index.error else []

    @rule(
        MET010,
        name="empty-trace",
        severity=FATAL,
        required=True,
        message="trace holds a metadata header node but no other nodes",
        description=(
            "The trace holds a metadata header but no nodes. Consumers have nothing to replay, simulate or " "analyze."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=NOT_SUITABLE,
    )
    def empty_trace(self, index: TraceIndex) -> list[Hit]:
        """Report a readable trace that holds no nodes."""
        return [Hit(self.MET010, [], {"count": 0})] if not index.error and not index.total else []

    @rule(
        MET011,
        name="schema-unknown-type",
        severity=ERROR,
        message="node type {type} not in Chakra schema version {version}",
        description=(
            "A node carries a type that the installed mlc-chakra schema does not define. The trace likely "
            "comes from a newer or foreign schema. Consumers may misread the node, so no consumer is "
            "suitable."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=NOT_SUITABLE,
    )
    def unknown_types(self, index: TraceIndex) -> list[Hit]:
        """Report each unknown node type with its node count."""
        return [
            Hit(self.MET011, self.type_ids.get(t, []), {"type": t, "count": count})
            for t, count in index.type_counts.items()
            if t not in NodeType.DESCRIPTOR.values_by_number
        ]

    @rule(
        MET012,
        name="node-count",
        severity=INFO,
        message="read and decoded {count} nodes using schema version {version}",
        description=(
            "The trace decoded and holds nodes. The row reports the node total and the installed schema "
            "version. It informs only and lowers no consumer."
        ),
    )
    def node_count(self, index: TraceIndex) -> list[Hit]:
        """Report the node total of a trace that holds nodes."""
        return [Hit(self.MET012, [], {"count": index.total})] if not index.error and index.total else []
