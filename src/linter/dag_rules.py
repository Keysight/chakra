"""Directed Acyclic Graph rules fed by the single pass over a trace."""

from collections.abc import Iterable, Mapping
from itertools import chain

from chakra.schema.protobuf.et_def_pb2 import Node

try:
    from .index_builder import TraceIndex
    from .rule_family import Hit, RuleFamily, register, rule
    from .sampling import keep_sample, tally
except ImportError:  # run as a top-level module, not a package
    from index_builder import TraceIndex  # type: ignore[no-redef]
    from rule_family import Hit, RuleFamily, register, rule  # type: ignore[no-redef]
    from sampling import keep_sample, tally  # type: ignore[no-redef]


@register
class DagRules(RuleFamily):
    """Duplicate IDs, dangling, self and repeated dependencies, cycles."""

    # Rule IDs; each must match an entry in rules.toml
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

    def add(self, node: Node, attrs: dict[str, object]) -> None:
        """Count a node that lists itself or repeats a parent in one field."""
        node_id = node.id
        if self.DAG003 in self.enabled and (node_id in node.ctrl_deps or node_id in node.data_deps):
            self.self_refs += 1
            keep_sample(self.self_ids, node_id)
        # Same ID in both fields is valid; repeats within one field are not
        if self.DAG004 in self.enabled and any(len(set(d)) != len(d) for d in (node.ctrl_deps, node.data_deps)):
            self.dup_edges += 1
            keep_sample(self.dup_edge_ids, node_id)

    @rule(DAG001)
    def duplicate_nodes(self, index: TraceIndex) -> list[Hit]:
        """Report node IDs that appear more than once."""
        ids: list[int] = []
        for node_id in index.duplicate_ids:
            keep_sample(ids, node_id)
        return [Hit(self.DAG001, ids, {"count": len(index.duplicate_ids)})] if ids else []

    @rule(DAG002)
    def dangling_deps(self, index: TraceIndex) -> list[Hit]:
        """Report dependencies on IDs that no node carries."""
        edges = index.ctrl_deps
        # Dependency 0 marks a root node with no parent, not a real node
        dangling, ids = tally(
            (n, sum(bool(p) and p not in edges for p in chain(ctrl, index.data_deps[n]))) for n, ctrl in edges.items()
        )
        return [Hit(self.DAG002, ids, {"count": dangling})] if dangling else []

    @rule(DAG003)
    def self_deps(self, index: TraceIndex) -> list[Hit]:
        """Report nodes that list their own ID as a dependency."""
        return [Hit(self.DAG003, self.self_ids, {"count": self.self_refs})] if self.self_refs else []

    @rule(DAG004)
    def repeated_deps(self, index: TraceIndex) -> list[Hit]:
        """Report nodes that repeat a parent within one field."""
        return [Hit(self.DAG004, self.dup_edge_ids, {"count": self.dup_edges})] if self.dup_edges else []

    @rule(DAG005)
    def cycles(self, index: TraceIndex) -> list[Hit]:
        """Report nodes in or behind a cycle; each field is its own graph."""
        hits: list[Hit] = []
        for name, deps in (("ctrl_deps", index.ctrl_deps), ("data_deps", index.data_deps)):
            stuck, ids = self.count_blocked(deps)
            if stuck:
                hits.append(Hit(self.DAG005, ids, {"count": stuck, "field": name}))
        return hits
