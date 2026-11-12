"""DagRules and the RuleFamily base class behave as the DAG rules specify."""

from pathlib import Path

import pytest
from chakra.schema.protobuf.et_def_pb2 import Node
from chakra.src.linter import index_builder, linter, rule_family
from chakra.src.linter.dag_rules import DagRules
from chakra.src.linter.index_builder import IndexBuilder
from families import write_trace


def node(node_id: int, ctrl: tuple[int, ...] = (), data: tuple[int, ...] = ()) -> Node:
    """Build a node with the given dependencies."""
    return Node(id=node_id, name="aten::add", type=4, duration_micros=5, ctrl_deps=ctrl, data_deps=data)


def dag(tmp_path: Path, nodes: list[Node]) -> dict[str, int | None]:
    """Return each reported DAG rule with its count."""
    result = linter.scan_trace(write_trace(tmp_path / "t.et", nodes))
    return {g.rule: g.message.total for g in result.gaps if g.rule.startswith("DAG")}


def test_clean_graph_reports_nothing(tmp_path) -> None:
    assert dag(tmp_path, [node(1), node(2, (1,)), node(3, (1,), (2,))]) == {}


def test_duplicate_id(tmp_path) -> None:
    assert dag(tmp_path, [node(1), node(1)]) == {"DAG001": 1}


def test_dangling_counts_dependencies_and_skips_root(tmp_path) -> None:
    # Dependency 0 is a root marker; 9 and 8 are missing
    assert dag(tmp_path, [node(1, (0,)), node(2, (9,), (8,))]) == {"DAG002": 2}


def test_self_dependency(tmp_path) -> None:
    assert dag(tmp_path, [node(1), node(2, (2,))]) == {"DAG003": 1}


def test_repeat_within_one_field_only(tmp_path) -> None:
    assert dag(tmp_path, [node(1), node(2, (1, 1))]) == {"DAG004": 1}
    # The same parent once in each field is valid
    assert dag(tmp_path, [node(1), node(2, (1,), (1,))]) == {}


def test_cycle_counts_blocked_nodes_per_field(tmp_path) -> None:
    nodes = [node(1, (2,)), node(2, (1,)), node(3, (2,))]
    assert dag(tmp_path, nodes) == {"DAG005": 3}
    # Opposite edges in different fields do not form a cycle
    assert dag(tmp_path, [node(1, (2,)), node(2, (), (1,))]) == {}


def test_count_blocked_ignores_self_and_missing_parents() -> None:
    assert DagRules.count_blocked({1: (1,), 2: (7,)}) == (0, [])


def test_builder_feeds_each_node_once(tmp_path) -> None:
    path = write_trace(tmp_path / "t.et", [node(1), node(2, (2,)), node(3, (3, 3))])
    family = DagRules()
    IndexBuilder(path, families=[family]).build()
    assert (family.self_refs, family.dup_edges) == (2, 1)


def probe_rule(rule_id: str, **overrides: str) -> object:
    """Declare a valid probe rule; `overrides` replace its fields."""
    fields = {
        "name": f"probe-{rule_id.lower()}",
        "severity": "warning",
        "message": "probe",
        "description": "Probe rule.",
        **overrides,
    }
    return rule_family.rule(rule_id, **fields)(lambda self, index: [])


def family(*ids: str) -> type:
    """Build a family class whose checks carry the given rule IDs."""
    body = {f"check_{i}": probe_rule(i) for i in ids}
    return type("Probe", (rule_family.RuleFamily,), body)


def test_family_needs_valid_unique_rule_ids() -> None:
    for bad in ((), ("dag1",)):
        with pytest.raises(TypeError):
            family(*bad)


def test_registry_rejects_reused_rule_ids() -> None:
    with pytest.raises(TypeError):
        rule_family.register(family("DAG001"))


@pytest.mark.parametrize(
    "bad",
    [
        {"name": "Not Kebab"},
        {"severity": "loud"},
        {"description": "no final period"},
        {"message": "uses {bogus}"},
        {"replay": "GREAT"},
    ],
)
def test_family_rules_must_meet_the_catalog_conventions(bad) -> None:
    with pytest.raises(TypeError):
        type("Probe", (rule_family.RuleFamily,), {"check": probe_rule("ZZZ999", **bad)})


def test_registry_rejects_reused_rule_names() -> None:
    reuse = type("Probe", (rule_family.RuleFamily,), {"check": probe_rule("ZZZ999", name="dag-cycle")})
    with pytest.raises(TypeError, match="names"):
        rule_family.register(reuse)


def test_checks_follow_declaration_order() -> None:
    assert list(DagRules.checks) == ["DAG001", "DAG002", "DAG003", "DAG004", "DAG005"]


def test_disabled_rule_is_skipped(tmp_path) -> None:
    path = write_trace(tmp_path / "t.et", [node(1, (2,)), node(2, (1,)), node(3, (3,))])
    for disabled, expected in ((set(), {"DAG003", "DAG005"}), ({"DAG005"}, {"DAG003"}), ({"DAG003"}, {"DAG005"})):
        family_ = DagRules(disabled)
        index = IndexBuilder(path, families=[family_]).build()
        assert {h.rule for h in family_.finish(index)} == expected
    # A disabled per-node rule never accumulates
    off = DagRules({"DAG003"})
    IndexBuilder(path, families=[off]).build()
    assert off.self_refs == 0


def test_scan_reads_the_file_once(tmp_path, monkeypatch) -> None:
    """The trace opens once; only the optional progress prescan reads again."""
    opened: list[str] = []
    real = index_builder.openFileRd
    monkeypatch.setattr(index_builder, "openFileRd", lambda p: opened.append(p) or real(p))
    linter.scan_trace(write_trace(tmp_path / "t.et", [node(1), node(2, (1,))]))
    assert len(opened) == 1
