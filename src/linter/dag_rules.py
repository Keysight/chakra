"""
Directed Acyclic Graph rules fed by the single pass over a trace.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections.abc import Iterable, Mapping
from itertools import chain

from chakra.schema.protobuf.et_def_pb2 import Node

from .index_builder import TraceIndex
from .rule_config import ERROR, NOT_SUITABLE
from .rule_family import Hit, RuleFamily, register, rule
from .sampling import keep_sample, tally


@register
class DagRules(RuleFamily):
    """Duplicate IDs, dangling, self and repeated dependencies, cycles."""

    order = 20

    # Rule IDs; each names the `@rule` that declares it
    DAG001 = "DAG001"  # duplicate node ID
    DAG002 = "DAG002"  # dependency on a missing node
    DAG003 = "DAG003"  # node depends on itself
    DAG004 = "DAG004"  # repeated dependency ID
    DAG005 = "DAG005"  # dependency cycle

    @staticmethod
    def count_blocked(deps: Mapping[int, tuple[int, ...]]) -> tuple[int, list[int]]:
        """
        Count nodes in or behind a cycle using Kahn's algorithm.

        `deps` maps each node ID to its parent IDs in one field. Parents that are
        missing or equal to the node are ignored; other rules report them.
        Returns (count, sample node IDs).
        """
        pending = {n: sum(p in deps and p != n for p in parents) for n, parents in deps.items()}
        children: dict[int, list[int]] = {}
        for node_id, parents in deps.items():
            for parent in parents:
                if parent in deps and parent != node_id:
                    children.setdefault(parent, []).append(node_id)
        ready = [n for n, count in pending.items() if count == 0]
        while ready:
            for child in children.get(ready.pop(), ()):
                pending[child] -= 1
                if pending[child] == 0:
                    ready.append(child)
        return tally((n, count > 0) for n, count in pending.items())

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        """Start with no self-references and no repeated dependencies."""
        super().__init__(disabled)
        self.self_refs = 0
        self.self_ids: list[int] = []
        self.dup_edges = 0
        self.dup_edge_ids: list[int] = []

    def add(self, node: Node) -> None:
        """Count a node that lists itself or repeats a parent in one field."""
        # A node with no dependencies breaks neither rule
        if not (node.ctrl_deps or node.data_deps):
            return
        node_id = node.id
        if self.DAG003 in self.enabled and (node_id in node.ctrl_deps or node_id in node.data_deps):
            self.self_refs += 1
            keep_sample(self.self_ids, node_id)
        # Same ID in both fields is valid; repeats within one field are not
        if self.DAG004 in self.enabled and any(len(set(d)) != len(d) for d in (node.ctrl_deps, node.data_deps)):
            self.dup_edges += 1
            keep_sample(self.dup_edge_ids, node_id)

    @rule(
        DAG001,
        name="dag-duplicate-node",
        severity=ERROR,
        message="node ID reuses an earlier node ID",
        description="Two or more nodes share one ID. Dependencies become ambiguous, so the graph cannot be trusted.",
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=NOT_SUITABLE,
    )
    def duplicate_nodes(self, index: TraceIndex) -> list[Hit]:
        """Report node IDs that appear more than once."""
        ids: list[int] = []
        for node_id in index.duplicate_ids:
            keep_sample(ids, node_id)
        return [Hit(self.DAG001, ids, {"count": len(index.duplicate_ids)})] if ids else []

    @rule(
        DAG002,
        name="dag-dangling-dep",
        severity=ERROR,
        message="node references a missing node",
        description=(
            "A node depends on an ID that no node carries. The rule checks every ID in both ctrl_deps and "
            "data_deps. Dependency 0 is excluded because it marks a root node. The report shows the number of "
            "dangling dependencies. The missing parent breaks execution order."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=NOT_SUITABLE,
    )
    def dangling_deps(self, index: TraceIndex) -> list[Hit]:
        """Report dependencies on IDs that no node carries."""
        edges = index.ctrl_deps
        # Dependency 0 marks a root node with no parent, not a real node
        dangling, ids = tally(
            (n, sum(bool(p) and p not in edges for p in chain(ctrl, index.data_deps[n]))) for n, ctrl in edges.items()
        )
        return [Hit(self.DAG002, ids, {"count": dangling})] if dangling else []

    @rule(
        DAG003,
        name="dag-self-dep",
        severity=ERROR,
        message="node references itself",
        description=(
            "A node lists its own ID as a dependency. The node can never become ready, so replay and "
            "simulation stall."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=NOT_SUITABLE,
    )
    def self_deps(self, index: TraceIndex) -> list[Hit]:
        """Report nodes that list their own ID as a dependency."""
        return [Hit(self.DAG003, self.self_ids, {"count": self.self_refs})] if self.self_refs else []

    @rule(
        DAG004,
        name="dag-duplicate-dep",
        severity=ERROR,
        message="repeated dependency ID within ctrl_deps or within data_deps",
        description=(
            "A node repeats the same parent within ctrl_deps or within data_deps. The same parent once in "
            "each field is valid. The cycle check (DAG005) accepts a repeat, so the defect would pass "
            "unnoticed. A repeat signals a generator defect."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=NOT_SUITABLE,
    )
    def repeated_deps(self, index: TraceIndex) -> list[Hit]:
        """Report nodes that repeat a parent within one field."""
        return [Hit(self.DAG004, self.dup_edge_ids, {"count": self.dup_edges})] if self.dup_edges else []

    @rule(
        DAG005,
        name="dag-cycle",
        severity=ERROR,
        message="in or blocked by a {field} cycle",
        description=(
            "Nodes form a dependency loop within ctrl_deps or within data_deps. The count includes nodes "
            "blocked behind the loop. A cyclic graph has no valid execution order."
        ),
        replay=NOT_SUITABLE,
        simulator=NOT_SUITABLE,
        analysis=NOT_SUITABLE,
    )
    def cycles(self, index: TraceIndex) -> list[Hit]:
        """Report nodes in or behind a cycle; each field is its own graph."""
        hits: list[Hit] = []
        for name, deps in (("ctrl_deps", index.ctrl_deps), ("data_deps", index.data_deps)):
            stuck, ids = self.count_blocked(deps)
            if stuck:
                hits.append(Hit(self.DAG005, ids, {"count": stuck, "field": name}))
        return hits
