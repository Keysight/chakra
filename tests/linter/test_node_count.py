"""The fast node counter matches the full decode and feeds the CLI early."""

from pathlib import Path

import index_builder
import linter
import pytest
from families import node, write_trace
from messages import chakra_version, default_messages, render, rule_messages


def trace(path: Path, count: int, pad: int = 0) -> Path:
    """Write a trace of `count` nodes, each padded by `pad` name bytes."""
    name = "aten::add" + "x" * pad
    return write_trace(path, [node(i, name=name) for i in range(1, count + 1)])


@pytest.mark.parametrize("nodes", [0, 1, 7, 300])
def test_count_matches_full_decode(tmp_path, nodes) -> None:
    path = trace(tmp_path / "t.et", nodes)
    expected = linter.lint_trace(path).total
    assert index_builder.IndexBuilder.count_nodes(path) == expected == nodes


def test_count_spans_block_boundaries(tmp_path, monkeypatch) -> None:
    # A tiny block forces prefixes and skips to straddle block edges
    monkeypatch.setattr(index_builder, "SCAN_BLOCK", 7)
    path = trace(tmp_path / "t.et", 50, pad=130)
    assert index_builder.IndexBuilder.count_nodes(path) == 50


def test_truncated_final_node_is_not_counted(tmp_path) -> None:
    path = trace(tmp_path / "t.et", 5)
    path.write_bytes(path.read_bytes()[:-3])
    assert index_builder.IndexBuilder.count_nodes(path) == 4


def test_unreadable_file_returns_none(tmp_path) -> None:
    assert index_builder.IndexBuilder.count_nodes(tmp_path / "missing.et") is None


def test_progress_reports_nodes_read_and_total(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(index_builder, "PROGRESS_STEP", 10)
    path = trace(tmp_path / "t.et", 25)
    steps = []
    result = linter.lint_trace(path, on_progress=lambda d, t: steps.append((d, t)))
    assert steps == [(10, 25), (20, 25)]
    assert result.total == 25


def test_block_lists_path_then_count_then_rules(tmp_path) -> None:
    path = trace(tmp_path / "t.et", 3)
    rows = linter.stylish_block(path, linter.lint_trace(path), color=False)
    assert rows[0] == str(path)
    assert any("MET012  info" in r and "read and decoded 3 nodes" in r for r in rows)


def test_count_and_empty_trace_are_separate_rules(tmp_path) -> None:
    messages = default_messages()
    assert messages["MET012"] == "read and decoded {count} nodes using schema version {version}"
    text = render(messages, "MET012", count=1234)
    assert text == f"read and decoded 1,234 nodes using schema version {chakra_version()}"
    empty = trace(tmp_path / "e.et", 0)
    rows = linter.stylish_block(empty, linter.lint_trace(empty), color=False)
    assert any("MET010  error    trace holds a metadata header node but no other nodes" in r for r in rows)


def test_count_wording_comes_from_the_rules_file(tmp_path) -> None:
    original = "read and decoded {count} nodes using schema version {version}"
    custom = linter.DEFAULT_RULES.read_text().replace(original, "{count} read")
    path = tmp_path / "rules.toml"
    path.write_text(custom)
    messages = rule_messages(linter.load_rules(path))
    assert render(messages, "MET012", count=1234) == "1,234 read"
