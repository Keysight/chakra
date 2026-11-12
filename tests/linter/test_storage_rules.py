"""StorageRules reports every storage defect that the rule text names."""

import pytest
from chakra.schema.protobuf.et_def_pb2 import COMP_NODE, DATA_OP_NODE, STORAGE_NODE, DataOpType, Node
from chakra.schema.protobuf.storage_pb2 import BlockOp, FsOp, PageOp, StorageInfo, StorageLevel
from chakra.src.linter.storage_rules import StorageRules
from families import run

FS, PAGE, BLOCK = StorageLevel.STORAGE_LEVEL_FS, StorageLevel.STORAGE_LEVEL_PAGE, StorageLevel.STORAGE_LEVEL_BLOCK
DEVICE = StorageLevel.STORAGE_LEVEL_DEVICE


def storage(level: int, **detail: object) -> Node:
    """Build a storage node; each keyword names a detail message to fill."""
    info = StorageInfo(level=level)
    for name, message in detail.items():
        getattr(info, name).CopyFrom(message)
    return Node(id=1, name="s", type=STORAGE_NODE, storage=info)


def rules_of(node: Node) -> set[str]:
    """Run the family on one node; return the rule IDs that fired."""
    hits, _ = run(StorageRules(), [node])
    return {h.rule for h in hits}


GOOD_FS = FsOp(op=FsOp.FS_OP_READ, fd=3, size_bytes=4096)
GOOD_PAGE = PageOp(op=PageOp.PAGE_OP_DIRTY, nr_pages=1)
GOOD_BLOCK = BlockOp(op=BlockOp.BLOCK_OP_WRITE, queue_event=BlockOp.BLOCK_EVENT_QUEUE, device="nvme0n1", nr_sectors=8)


@pytest.mark.parametrize(
    "node",
    [
        storage(FS, fs=GOOD_FS),
        storage(PAGE, page=GOOD_PAGE),
        storage(BLOCK, block=GOOD_BLOCK),
        storage(DEVICE),
        storage(BLOCK, block=BlockOp(op=BlockOp.BLOCK_OP_FLUSH, queue_event=BlockOp.BLOCK_EVENT_QUEUE, device="d")),
        Node(id=1, type=DATA_OP_NODE, data_op=DataOpType.DATA_OP_CHECKPOINT),
        Node(id=1, type=COMP_NODE),
    ],
)
def test_well_formed_nodes_are_clean(node: Node) -> None:
    assert not rules_of(node)


@pytest.mark.parametrize(
    ("node", "expected"),
    [
        (Node(id=1, type=STORAGE_NODE), {"STO001"}),
        (Node(id=1, type=STORAGE_NODE, data_op=DataOpType.DATA_OP_DATALOADER), {"STO001", "STO002"}),
        (Node(id=1, type=COMP_NODE, storage=StorageInfo(level=DEVICE)), {"STO002"}),
        (storage(StorageLevel.STORAGE_LEVEL_UNKNOWN), {"STO003"}),
        (storage(9), {"STO003"}),
        (storage(FS), {"STO004"}),
        (storage(FS, page=GOOD_PAGE), {"STO004"}),
        (storage(DEVICE, fs=GOOD_FS), {"STO004"}),
        (storage(FS, fs=FsOp(fd=3, size_bytes=1)), {"STO005"}),
        (storage(PAGE, page=PageOp(nr_pages=1)), {"STO005"}),
        (storage(BLOCK, block=BlockOp(device="d", nr_sectors=1)), {"STO005"}),
        (storage(FS, fs=FsOp(op=FsOp.FS_OP_OPEN)), {"STO006"}),
        (storage(FS, fs=FsOp(op=FsOp.FS_OP_PWRITE, fd=3)), {"STO007"}),
        (storage(PAGE, page=PageOp(op=PageOp.PAGE_OP_ADD_TO_CACHE)), {"STO011"}),
        (Node(id=1, type=DATA_OP_NODE), {"STO012"}),
        (Node(id=1, type=DATA_OP_NODE, data_op=DataOpType.DATA_OP_UNKNOWN), {"STO012"}),
    ],
)
def test_defects_fire_their_rule(node: Node, expected: set[str]) -> None:
    assert rules_of(node) == expected


def test_fs_ops_without_data_need_no_size() -> None:
    for op in (FsOp.FS_OP_CLOSE, FsOp.FS_OP_FSYNC, FsOp.FS_OP_FDATASYNC, FsOp.FS_OP_SYNC_FILE_RANGE):
        assert not rules_of(storage(FS, fs=FsOp(op=op, fd=3)))


def test_block_defects_fire_independently() -> None:
    block = BlockOp(op=BlockOp.BLOCK_OP_READ)
    assert rules_of(storage(BLOCK, block=block)) == {"STO008", "STO009", "STO010"}


def test_hit_counts_nodes_per_type_and_samples_ids() -> None:
    nodes = [Node(id=i, type=STORAGE_NODE) for i in range(1, 6)] + [Node(id=9, type=DATA_OP_NODE)]
    hits, _ = run(StorageRules(), nodes)
    got = {(h.rule, h.node_type): (h.values["count"], h.ids) for h in hits}
    assert got[("STO001", STORAGE_NODE)] == (5, [1, 2, 5])
    assert got[("STO012", DATA_OP_NODE)] == (1, [9])


def test_disabled_rule_emits_nothing_and_changes_no_other() -> None:
    node = storage(BLOCK, block=BlockOp(op=BlockOp.BLOCK_OP_READ))
    hits, _ = run(StorageRules({"STO008"}), [node])
    assert {h.rule for h in hits} == {"STO009", "STO010"}
