"""
Storage rules fed by the single pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections import Counter
from collections.abc import Iterable

from chakra.schema.protobuf.et_def_pb2 import (
    DATA_OP_NODE,
    STORAGE_NODE,
    DataOpType,
    Node,
)
from chakra.schema.protobuf.storage_pb2 import BlockOp, FsOp, PageOp, StorageLevel

try:
    from .index_builder import TraceIndex
    from .rule_family import Hit, RuleFamily, register, rule
    from .sampling import add_sample
except ImportError:  # run as a top-level module, not a package
    from index_builder import TraceIndex  # type: ignore[no-redef]
    from rule_family import Hit, RuleFamily, register, rule  # type: ignore[no-redef]
    from sampling import add_sample  # type: ignore[no-redef]

# Oneof field of Node that carries type-specific information
OP_INFO = "op_info"

# Storage level to the detail message it requires; DEVICE has none
LEVEL_DETAIL = {
    StorageLevel.STORAGE_LEVEL_FS: "fs",
    StorageLevel.STORAGE_LEVEL_PAGE: "page",
    StorageLevel.STORAGE_LEVEL_BLOCK: "block",
}

# op_info field that each node type may carry
PAYLOAD_OF_TYPE = {STORAGE_NODE: "storage", DATA_OP_NODE: "data_op"}

# File operations that move bytes and so must name a size
FS_DATA_OPS = frozenset((FsOp.FS_OP_READ, FsOp.FS_OP_WRITE, FsOp.FS_OP_PREAD, FsOp.FS_OP_PWRITE))

# Block operations that carry a data payload; a flush has none
BLOCK_DATA_OPS = frozenset((BlockOp.BLOCK_OP_READ, BlockOp.BLOCK_OP_WRITE))


@register
class StorageRules(RuleFamily):
    """Malformed storage nodes and storage-related data operation nodes."""

    order = 45

    # Rule IDs; each must match an entry in rules.toml
    STO001 = "STO001"  # storage node without StorageInfo
    STO002 = "STO002"  # op_info payload that does not fit the node type
    STO003 = "STO003"  # unknown storage level
    STO004 = "STO004"  # detail message does not match the level
    STO005 = "STO005"  # unknown operation type
    STO006 = "STO006"  # file open without pathname
    STO007 = "STO007"  # file data operation of zero bytes
    STO008 = "STO008"  # block operation without device
    STO009 = "STO009"  # block data operation of zero sectors
    STO010 = "STO010"  # block operation with unknown queue event
    STO011 = "STO011"  # page operation of zero pages
    STO012 = "STO012"  # data operation node without a defined type

    # STO002 compares every node's payload with its type, so read all nodes
    node_types = None

    # Report order of the node types that rules attribute findings to
    TYPE_ORDER = (STORAGE_NODE, DATA_OP_NODE)

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no storage defects."""
        super().__init__(disabled)
        self.counts: Counter = Counter()  # (rule ID, node type) to nodes
        self.ids: dict[object, list[int]] = {}

    def flag(self, rule_id: str, node: Node) -> None:
        """Count one defective node and keep a sample of its ID."""
        self.counts[(rule_id, node.type)] += 1
        add_sample(self.ids, (rule_id, node.type), node.id)

    def add(self, node: Node) -> None:
        """Record the storage defects of one node."""
        payload = node.WhichOneof(OP_INFO)
        expected = PAYLOAD_OF_TYPE.get(node.type)
        if payload is not None and payload != expected:
            self.flag(self.STO002, node)
        if node.type == DATA_OP_NODE:
            if payload != "data_op" or node.data_op == DataOpType.DATA_OP_UNKNOWN:
                self.flag(self.STO012, node)
        elif node.type == STORAGE_NODE:
            self.add_storage(node, payload)

    def add_storage(self, node: Node, payload: str | None) -> None:
        """Record the defects of one storage node."""
        if payload != "storage":
            self.flag(self.STO001, node)
            return
        info = node.storage
        level = info.level
        if level not in StorageLevel.values() or level == StorageLevel.STORAGE_LEVEL_UNKNOWN:
            self.flag(self.STO003, node)
            return
        detail = info.WhichOneof("detail")
        if detail != LEVEL_DETAIL.get(level):
            self.flag(self.STO004, node)
            return
        if detail == "fs":
            self.add_fs(node, info.fs)
        elif detail == "page":
            self.add_page(node, info.page)
        elif detail == "block":
            self.add_block(node, info.block)

    def add_fs(self, node: Node, fs: FsOp) -> None:
        """Record the defects of one file operation."""
        if fs.op not in FsOp.OpType.values() or fs.op == FsOp.FS_OP_UNKNOWN:
            self.flag(self.STO005, node)
        elif fs.op == FsOp.FS_OP_OPEN and not fs.pathname:
            self.flag(self.STO006, node)
        elif fs.op in FS_DATA_OPS and not fs.size_bytes:
            self.flag(self.STO007, node)

    def add_page(self, node: Node, page: PageOp) -> None:
        """Record the defects of one page-cache operation."""
        if page.op not in PageOp.OpType.values() or page.op == PageOp.PAGE_OP_UNKNOWN:
            self.flag(self.STO005, node)
        elif not page.nr_pages:
            self.flag(self.STO011, node)

    def add_block(self, node: Node, block: BlockOp) -> None:
        """Record the defects of one block-layer operation."""
        if block.op not in BlockOp.OpType.values() or block.op == BlockOp.BLOCK_OP_UNKNOWN:
            self.flag(self.STO005, node)
            return
        if not block.device:
            self.flag(self.STO008, node)
        if block.op in BLOCK_DATA_OPS and not block.nr_sectors:
            self.flag(self.STO009, node)
        if block.queue_event not in BlockOp.QueueEvent.values() or block.queue_event == BlockOp.BLOCK_EVENT_UNKNOWN:
            self.flag(self.STO010, node)

    def hits(self, rule_id: str) -> list[Hit]:
        """List one hit per node type that the rule flagged."""
        node_types = sorted({t for r, t in self.counts if r == rule_id}, key=self.order_of)
        return [Hit(rule_id, self.ids[(rule_id, t)], {"count": self.counts[(rule_id, t)]}, t) for t in node_types]

    def order_of(self, node_type: int) -> tuple[int, int]:
        """Sort storage and data operation nodes first, then by type value."""
        known = node_type in self.TYPE_ORDER
        return (self.TYPE_ORDER.index(node_type) if known else len(self.TYPE_ORDER), node_type)

    @rule(STO001)
    def missing_info(self, index: TraceIndex) -> list[Hit]:
        """Report storage nodes without StorageInfo."""
        return self.hits(self.STO001)

    @rule(STO002)
    def payload_mismatch(self, index: TraceIndex) -> list[Hit]:
        """Report nodes whose op_info does not belong to their type."""
        return self.hits(self.STO002)

    @rule(STO003)
    def unknown_level(self, index: TraceIndex) -> list[Hit]:
        """Report storage nodes whose level is unknown or undefined."""
        return self.hits(self.STO003)

    @rule(STO004)
    def detail_mismatch(self, index: TraceIndex) -> list[Hit]:
        """Report storage nodes whose detail does not match the level."""
        return self.hits(self.STO004)

    @rule(STO005)
    def unknown_op(self, index: TraceIndex) -> list[Hit]:
        """Report storage operations whose type is unknown or undefined."""
        return self.hits(self.STO005)

    @rule(STO006)
    def open_without_path(self, index: TraceIndex) -> list[Hit]:
        """Report file opens without a pathname."""
        return self.hits(self.STO006)

    @rule(STO007)
    def zero_size(self, index: TraceIndex) -> list[Hit]:
        """Report file reads and writes of zero bytes."""
        return self.hits(self.STO007)

    @rule(STO008)
    def block_no_device(self, index: TraceIndex) -> list[Hit]:
        """Report block operations without a device."""
        return self.hits(self.STO008)

    @rule(STO009)
    def block_zero_sectors(self, index: TraceIndex) -> list[Hit]:
        """Report block reads and writes of zero sectors."""
        return self.hits(self.STO009)

    @rule(STO010)
    def block_unknown_event(self, index: TraceIndex) -> list[Hit]:
        """Report block operations without a defined queue event."""
        return self.hits(self.STO010)

    @rule(STO011)
    def page_zero_pages(self, index: TraceIndex) -> list[Hit]:
        """Report page-cache operations that cover zero pages."""
        return self.hits(self.STO011)

    @rule(STO012)
    def data_op_undefined(self, index: TraceIndex) -> list[Hit]:
        """Report data operation nodes without a defined data_op."""
        return self.hits(self.STO012)
