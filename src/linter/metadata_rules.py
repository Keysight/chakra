"""Metadata rules MET001 to MET007, judged from the trace header."""

try:
    from .index_builder import TraceIndex
    from .rule_family import Hit, RuleFamily, register, rule
except ImportError:  # run as a top-level module, not a package
    from index_builder import TraceIndex  # type: ignore[no-redef]
    from rule_family import Hit, RuleFamily, register, rule  # type: ignore[no-redef]


@register
class MetadataRules(RuleFamily):
    """Missing and inconsistent capture metadata."""

    order = 60

    # Rule IDs; each must match an entry in rules.toml
    MET001 = "MET001"  # version: required, every trace
    MET002 = "MET002"  # schema
    MET003 = "MET003"  # pid
    MET004 = "MET004"  # time
    MET005 = "MET005"  # start_ts
    MET006 = "MET006"  # finish_ts
    MET007 = "MET007"  # finish_ts before start_ts

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
