"""
Metadata rules fed by the single pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

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
class MetadataRules(RuleFamily):
    """Unreadable files, empty traces, unknown node types, and capture metadata."""

    # Leads the report: the fatal rules MET009 and MET010 run before the others
    order = 10

    # Rule IDs; each must match an entry in rules.toml
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

    @rule(MET001)
    def missing_version(self, index: TraceIndex) -> list[Hit]:
        """Report a header that carries no schema version."""
        if "version" not in index.header:
            return [Hit(self.MET001, [], {})]
        return []

    @rule(MET002)
    def missing_schema(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the schema attribute."""
        return self.missing_attr(index, self.MET002)

    @rule(MET003)
    def missing_pid(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the pid attribute."""
        return self.missing_attr(index, self.MET003)

    @rule(MET004)
    def missing_time(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the time attribute."""
        return self.missing_attr(index, self.MET004)

    @rule(MET005)
    def missing_start_ts(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the start_ts attribute."""
        return self.missing_attr(index, self.MET005)

    @rule(MET006)
    def missing_finish_ts(self, index: TraceIndex) -> list[Hit]:
        """Report a PyTorch header without the finish_ts attribute."""
        return self.missing_attr(index, self.MET006)

    @rule(MET007)
    def inverted_times(self, index: TraceIndex) -> list[Hit]:
        """Report a capture that finishes before it starts."""
        start, finish = index.header.get("start_ts"), index.header.get("finish_ts")
        if index.pytorch_nodes and isinstance(start, int) and isinstance(finish, int) and finish < start:
            return [Hit(self.MET007, [], {"start": start, "finish": finish})]
        return []

    @rule(MET008)
    def unsupported_schema(self, index: TraceIndex) -> list[Hit]:
        """Report a schema value that the converter does not support."""
        value = index.header.get("schema")
        if index.pytorch_nodes and isinstance(value, str) and value not in self.SUPPORTED_SCHEMAS:
            return [Hit(self.MET008, [], {"value": value})]
        return []

    @rule(MET009)
    def decode_failure(self, index: TraceIndex) -> list[Hit]:
        """Report a file that the decoder could not read."""
        return [Hit(self.MET009, [], {"error": index.error})] if index.error else []

    @rule(MET010)
    def empty_trace(self, index: TraceIndex) -> list[Hit]:
        """Report a readable trace that holds no nodes."""
        return [Hit(self.MET010, [], {"count": 0})] if not index.error and not index.total else []

    @rule(MET011)
    def unknown_types(self, index: TraceIndex) -> list[Hit]:
        """Report each unknown node type with its node count."""
        return [
            Hit(self.MET011, self.type_ids.get(t, []), {"type": t, "count": count})
            for t, count in index.type_counts.items()
            if t not in NodeType.DESCRIPTOR.values_by_number
        ]

    @rule(MET012)
    def node_count(self, index: TraceIndex) -> list[Hit]:
        """Report the node total of a trace that holds nodes."""
        return [Hit(self.MET012, [], {"count": index.total})] if not index.error and index.total else []
