"""
Communication rules fed by the single pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections import Counter
from collections.abc import Iterable

from chakra.schema.protobuf.et_def_pb2 import (
    COMM_COLL_NODE,
    COMM_RECV_NODE,
    COMM_SEND_NODE,
    COMP_NODE,
    CollectiveCommType,
    Node,
)

from .index_builder import TraceIndex
from .rule_config import ERROR, LIMITED, NOT_SUITABLE, REVIEW, WARNING
from .rule_family import Hit, RuleFamily, register, rule
from .sampling import add_sample, keep_sample


@register
class CommRules(RuleFamily):
    """Missing communication attributes, zero sizes, absent device-side data."""

    order = 40

    # Rule IDs; each names the `@rule` that declares it
    COM001 = "COM001"  # host-side comm operators, no device-side comm node
    COM002 = "COM002"  # missing comm_type
    COM003 = "COM003"  # missing comm_size
    COM004 = "COM004"  # missing pg_name
    COM005 = "COM005"  # missing comm_src
    COM006 = "COM006"  # missing comm_dst
    COM007 = "COM007"  # zero comm_size
    COM008 = "COM008"  # comm_type outside the schema enum

    # Attributes every collective node must carry for replay
    COLL_ATTRS = ("comm_type", "comm_size", "pg_name")

    # Point-to-point nodes must declare a nonzero transfer size and both peers
    P2P_TYPES = (COMM_SEND_NODE, COMM_RECV_NODE)
    P2P_ATTRS = ("comm_size", "comm_src", "comm_dst")

    # comm_type values that the Chakra schema defines
    COMM_TYPES = frozenset(CollectiveCommType.values())

    # Report order of node types
    TYPE_ORDER = (COMM_COLL_NODE, *P2P_TYPES)
    # Compute nodes are visited to find host-side communication operators
    node_types = frozenset((*TYPE_ORDER, COMP_NODE))

    # Name fragment of the host-side operator that launches a communication
    HOST_COMM_NAME = "record_param_comms"

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no communication defects."""
        super().__init__(disabled)
        # Per node type: count of nodes missing each attribute or size
        self.missing: dict[int, Counter] = {t: Counter() for t in self.TYPE_ORDER}
        self.ids: dict[tuple[int, str], list[int]] = {}
        self.device_comm = 0  # device-side communication nodes
        self.host_comm = 0  # host-side communication operators
        self.host_ids: list[int] = []

    def add(self, node: Node) -> None:
        """Record missing attributes and zero sizes of one communication node."""
        node_type, node_id, index = node.type, node.id, self.index
        if node_type == COMP_NODE:
            if self.HOST_COMM_NAME in index.name[node_id]:
                self.host_comm += 1
                keep_sample(self.host_ids, node_id)
            return
        self.device_comm += 1
        required = self.COLL_ATTRS if node_type == COMM_COLL_NODE else self.P2P_ATTRS
        missing = [name for name in required if not index.has_attr(node_id, name)]
        if index.int_attrs.get("comm_size", {}).get(node_id) == 0:
            missing.append("zero_size")
        comm_type = index.int_attrs.get("comm_type", {}).get(node_id)
        if node_type == COMM_COLL_NODE and comm_type is not None and comm_type not in self.COMM_TYPES:
            missing.append("unknown_type")
        self.missing[node_type].update(missing)
        for name in missing:
            add_sample(self.ids, (node_type, name), node_id)  # type: ignore[arg-type]

    def missing_hits(self, rule_id: str, key: str) -> list[Hit]:
        """List one hit per node type that lacks the named attribute."""
        return [
            Hit(rule_id, self.ids.get((t, key), []), {"count": self.missing[t][key]}, t)
            for t in self.TYPE_ORDER
            if self.missing[t][key]
        ]

    @rule(
        COM001,
        name="comm-no-device-data",
        severity=ERROR,
        message="{count} host-side communication operators, no device-side communication node",
        description=(
            "The trace holds host-side communication operators (record_param_comms) but no device-side "
            "communication node, so the Kineto device data for them is absent. The communication type, size "
            "and process group are missing. Replay and simulation cannot model the communications, and "
            "analysis cannot attribute their execution time."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=LIMITED,
    )
    def no_device_data(self, index: TraceIndex) -> list[Hit]:
        """Report host-side communication operators without device-side nodes."""
        if self.host_comm and not self.device_comm:
            return [Hit(self.COM001, self.host_ids, {"count": self.host_comm}, COMM_COLL_NODE)]
        return []

    @rule(
        COM002,
        name="comm-missing-type",
        severity=ERROR,
        message="missing comm_type attr",
        description=(
            "A collective node lacks comm_type. Replay and simulation cannot tell which collective to run, "
            "such as all-reduce or all-gather."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=REVIEW,
    )
    def missing_type(self, index: TraceIndex) -> list[Hit]:
        """Report collectives without comm_type."""
        return self.missing_hits(self.COM002, "comm_type")

    @rule(
        COM003,
        name="comm-missing-size",
        severity=ERROR,
        message="missing comm_size attr",
        description=(
            "A collective, send or receive node lacks comm_size. Replay and simulation cannot size the " "transfer."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=REVIEW,
    )
    def missing_size(self, index: TraceIndex) -> list[Hit]:
        """Report communication nodes without comm_size."""
        return self.missing_hits(self.COM003, "comm_size")

    @rule(
        COM004,
        name="comm-missing-pg-name",
        severity=WARNING,
        message="missing pg_name attr",
        description=(
            "A collective node lacks the pg_name attribute, which names its process group. Consumers assume "
            "that all nodes participate in a single process group, so a run with several groups may be "
            "modeled incorrectly."
        ),
        replay=REVIEW,
        simulator=REVIEW,
        analysis=REVIEW,
    )
    def missing_group(self, index: TraceIndex) -> list[Hit]:
        """Report collectives without pg_name."""
        return self.missing_hits(self.COM004, "pg_name")

    @rule(
        COM005,
        name="comm-missing-src",
        severity=ERROR,
        message="missing comm_src attr",
        description="A send or receive node lacks comm_src. Replay and simulation cannot identify the sending peer.",
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=REVIEW,
    )
    def missing_source(self, index: TraceIndex) -> list[Hit]:
        """Report point-to-point nodes without comm_src."""
        return self.missing_hits(self.COM005, "comm_src")

    @rule(
        COM006,
        name="comm-missing-dst",
        severity=ERROR,
        message="missing comm_dst attr",
        description="A send or receive node lacks comm_dst. Replay and simulation cannot identify the receiving peer.",
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=REVIEW,
    )
    def missing_destination(self, index: TraceIndex) -> list[Hit]:
        """Report point-to-point nodes without comm_dst."""
        return self.missing_hits(self.COM006, "comm_dst")

    @rule(
        COM007,
        name="comm-zero-size",
        severity=ERROR,
        message="zero comm_size",
        description=(
            "A communication node declares a comm_size of zero. Replay and simulation cannot model a transfer "
            "with no payload."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=REVIEW,
    )
    def zero_size(self, index: TraceIndex) -> list[Hit]:
        """Report communication nodes that declare a size of zero."""
        return self.missing_hits(self.COM007, "zero_size")

    @rule(
        COM008,
        name="comm-unknown-type",
        severity=ERROR,
        message="comm_type is not a defined collective type",
        description=(
            "A collective node carries a comm_type that the Chakra schema does not define "
            "(CollectiveCommType). The converter derives the type from the kernel name and rejects an unknown "
            "name, so this value came from another producer. Replay and simulation cannot tell which "
            "collective to run."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=REVIEW,
    )
    def unknown_type(self, index: TraceIndex) -> list[Hit]:
        """Report collectives whose comm_type the schema does not define."""
        return self.missing_hits(self.COM008, "unknown_type")

    def finish(self, index: TraceIndex) -> list[Hit]:
        """Run the checks, then group findings by node type in report order."""
        hits = super().finish(index)
        return sorted(hits, key=lambda h: self.TYPE_ORDER.index(h.node_type))  # type: ignore[arg-type]
