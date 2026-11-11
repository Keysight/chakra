"""
Single-pass trace ingestion that builds the dictionaries rules read.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, cast

from chakra.schema.protobuf.et_def_pb2 import GlobalMetadata, Node
from chakra.src.third_party.utils.protolib import decodeMessage, openFileRd

try:
    from .rule_family import RuleFamily
except ImportError:  # run as a top-level module, not a package
    from rule_family import RuleFamily  # type: ignore[no-redef]

# Node count between progress callbacks
PROGRESS_STEP = 50_000

# Bytes read per block while counting nodes
SCAN_BLOCK = 1 << 22

# Stream that host (CPU) operators report; inferred from sample traces
DEFAULT_STREAM = 0

# Integer attributes whose values rules read
INT_ATTRS = ("rf_id", "scope", "fw_tid", "fw_parent", "comm_size", "comm_type")

# Attributes only PyTorch-derived traces carry; synthetic traces lack them
PYTORCH_ATTRS = ("rf_id", "tid")

# Attributes whose values the index stores
TRACKED_ATTRS = frozenset(("stream", "is_cpu_op", "op_schema", *INT_ATTRS))

# Chakra attributes carry one populated value field, named by `value`
IS_CPU_OP = "is_cpu_op"
OP_SCHEMA = "op_schema"
STREAM = "stream"


@dataclass
class TraceIndex:
    """Compact per-node facts, one dictionary per fact, keyed by node ID."""

    path: Path = field(default_factory=Path)
    file_name: str = ""
    file_size: int = 0  # bytes
    expected_nodes: int | None = None  # prescan count; None if unscannable
    header: dict[str, object] = field(default_factory=dict)
    node_type: dict[int, int] = field(default_factory=dict)
    duration: dict[int, int] = field(default_factory=dict)
    name: dict[int, str] = field(default_factory=dict)
    ctrl_deps: dict[int, tuple[int, ...]] = field(default_factory=dict)
    data_deps: dict[int, tuple[int, ...]] = field(default_factory=dict)
    # Bit i is set when attribute attr_bits[i] is present on the node
    attr_mask: dict[int, int] = field(default_factory=dict)
    attr_bits: dict[str, int] = field(default_factory=dict)
    stream: dict[int, int] = field(default_factory=dict)
    cpu_op: dict[int, bool] = field(default_factory=dict)
    op_schema: dict[int, str] = field(default_factory=dict)  # non-empty only
    # Integer attribute values, by attribute name then node ID
    int_attrs: dict[str, dict[int, int]] = field(default_factory=dict)
    # Nodes with a wrongly typed or repeated attribute
    bad_attr: set[int] = field(default_factory=set)
    # Nodes recording neither input nor output values
    no_tensor_io: set[int] = field(default_factory=set)
    type_counts: Counter = field(default_factory=Counter)
    duplicate_ids: list[int] = field(default_factory=list)
    pytorch_nodes: int = 0  # nodes carrying PyTorch-only attributes
    total: int = 0
    elapsed: float = 0.0
    error: Exception | None = None  # why the file could not be read

    @property
    def synthetic(self) -> bool:
        """Tell whether the trace was generated: no capture markers, no streams."""
        return not (self.header or self.pytorch_nodes or self.stream)

    def has_attr(self, node_id: int, name: str) -> bool:
        """Tell whether the node carries the named attribute."""
        bit = self.attr_bits.get(name)
        return bit is not None and bool(self.attr_mask[node_id] >> bit & 1)


class IndexBuilder:
    """Prescan a trace for its node count, then read it once into an index."""

    def __init__(
        self,
        path: Path,
        on_progress: Callable[[int, int], None] | None = None,
        attr_kinds: Mapping[str, str] | None = None,
        families: Sequence[RuleFamily] = (),
    ) -> None:
        """
        Bind the trace path and optional collaborators.

        `on_progress` receives (nodes read, total) and needs the prescan.
        `attr_kinds` maps attribute names to their required value field.
        `families` receive every node through `add` during the single pass.
        """
        self.on_progress = on_progress
        self.attr_kinds = attr_kinds or {}
        self.families = tuple(f for f in families if f.reads_nodes())
        # Families to call per node type; filled on first sight of a type
        self.dispatch: dict[int, tuple[RuleFamily, ...]] = {}
        self.index = TraceIndex(path=path, file_name=path.name)
        for family in families:
            family.index = self.index

    @property
    def path(self) -> Path:
        """Trace file being processed."""
        return self.index.path

    @property
    def file_name(self) -> str:
        """Base name of the trace file."""
        return self.index.file_name

    @property
    def file_size(self) -> int:
        """Trace size in bytes."""
        return self.index.file_size

    @staticmethod
    def count_nodes(path: Path) -> int | None:
        """
        Count the nodes of a trace from its length prefixes, decoding none.

        The first message is the metadata header, so it does not count.
        Returns None when the file cannot be scanned; lint_trace reports why.
        """
        count = skip = 0
        try:
            with openFileRd(str(path)) as raw:
                handle = cast(BinaryIO, raw)  # opened "rb", so reads give bytes
                data, i = handle.read(SCAN_BLOCK), 0
                while True:
                    if skip:
                        step = min(skip, len(data) - i)
                        i, skip = i + step, skip - step
                    if i >= len(data):
                        data, i = handle.read(SCAN_BLOCK), 0
                        if not data:
                            # A cut final message is not a whole node
                            return max(count - 1 - bool(skip), 0)
                        continue
                    if len(data) - i < 10:
                        # A varint may span two blocks; join them
                        data, i = data[i:] + handle.read(SCAN_BLOCK), 0
                    size = shift = 0
                    while True:
                        byte = data[i]
                        i += 1
                        size |= (byte & 0x7F) << shift
                        shift += 7
                        if not byte & 0x80 or i >= len(data):
                            break
                    if size == 0:
                        return max(count - 1, 0)  # the decoder stops on size 0
                    count += 1
                    skip = size
        except (OSError, EOFError, IndexError, SystemExit):
            return None

    def prescan(self) -> None:
        """Record file size and count nodes from length prefixes, no decode."""
        index = self.index
        index.file_size = index.path.stat().st_size
        index.expected_nodes = self.count_nodes(index.path)

    def build(self) -> TraceIndex:
        """Decode every node once; a read failure leaves `error` on the index."""
        try:
            self.decode()
        except SystemExit:  # the protobuf helper exits when a file will not open
            self.index.error = OSError(f"cannot open {self.index.path}")
        except Exception as exc:  # noqa: BLE001 - any decode error is a defect
            self.index.error = exc
        return self.index

    def decode(self) -> None:
        """Decode every node exactly once; prescan only for progress."""
        index = self.index
        if self.on_progress:
            self.prescan()
        handle = openFileRd(str(index.path))
        # The first message is the metadata header, not a node
        metadata = GlobalMetadata()
        decodeMessage(handle, metadata)
        index.header = {a.name: _value(a) for a in metadata.attr}
        # The version is a field of the message, not an attribute
        if metadata.version:
            index.header["version"] = metadata.version
        expected = index.expected_nodes
        start = time.perf_counter()
        seen = 0
        # A fresh Node per read; a reused upb Node grows its arena unbounded
        while True:
            node = Node()
            if not decodeMessage(handle, node):
                break
            self.add(node)
            seen += 1
            # Progress needs the prescan total; skip it when unscannable
            if self.on_progress and expected and seen % PROGRESS_STEP == 0:
                self.on_progress(seen, expected)
        # Decode time only; the prescan runs before the timer starts
        index.elapsed = time.perf_counter() - start
        index.total = index.type_counts.total()

    def add(self, node: Node) -> None:
        """Copy the compact facts of one node into the index dictionaries."""
        index = self.index
        node_id = node.id
        index.type_counts[node.type] += 1
        if not (node.inputs.values or node.outputs.values):
            index.no_tensor_io.add(node_id)
        # A repeated ID overwrites the earlier node; record it for DAG rules
        if node_id in index.node_type:
            index.duplicate_ids.append(node_id)
        index.node_type[node_id] = node.type
        index.duration[node_id] = node.duration_micros
        # Intern names so repeated operators share one string object
        index.name[node_id] = sys.intern(node.name)
        # Most nodes have no dependencies; skip building a tuple for them
        ctrl, data = node.ctrl_deps, node.data_deps
        index.ctrl_deps[node_id] = tuple(ctrl) if ctrl else ()
        index.data_deps[node_id] = tuple(data) if data else ()
        # One pass over attributes: presence bits plus the few values rules read
        index.attr_mask[node_id] = self._add_attrs(node)
        families = self.dispatch.get(node.type)
        if families is None:
            families = self.dispatch[node.type] = tuple(
                f for f in self.families if f.node_types is None or node.type in f.node_types
            )
        for family in families:
            family.add(node)

    def _add_attrs(self, node: Node) -> int:
        """Record attribute facts of one node; return its presence mask."""
        index = self.index
        node_id = node.id
        mask = 0
        names: set[str] = set()
        bad = pytorch = False
        kinds, bits = self.attr_kinds, index.attr_bits
        for attr in node.attr:
            name = attr.name
            pytorch |= name in PYTORCH_ATTRS
            bit = bits.get(name)
            if bit is None:
                bit = bits[name] = len(bits)
            mask |= 1 << bit
            names.add(name)
            # Read the value kind only for attributes that a rule checks
            if name in kinds:
                bad |= attr.WhichOneof("value") != kinds[name]
            if name in TRACKED_ATTRS:
                self._track(node_id, name, attr)
        # A repeated name shrinks the set below the attribute count
        bad |= len(names) != len(node.attr)
        if bad:
            index.bad_attr.add(node_id)
        index.pytorch_nodes += pytorch
        return mask

    def _track(self, node_id: int, name: str, attr: object) -> None:
        """Store the value of an attribute that rules read."""
        index = self.index
        if name == STREAM:
            index.stream[node_id] = attr.int64_val  # type: ignore[attr-defined]
        elif name == IS_CPU_OP:
            index.cpu_op[node_id] = bool(_value(attr))
        elif name == OP_SCHEMA:
            if _value(attr):  # empty schema is absent
                index.op_schema[node_id] = sys.intern(str(_value(attr)))
        elif attr.WhichOneof("value") == "int64_val":  # type: ignore[attr-defined]
            index.int_attrs.setdefault(name, {})[node_id] = attr.int64_val  # type: ignore[attr-defined]


def _value(attr: object) -> object:
    """Return the populated value of a Chakra attribute."""
    kind = attr.WhichOneof("value")  # type: ignore[attr-defined]
    return getattr(attr, kind) if kind else None
