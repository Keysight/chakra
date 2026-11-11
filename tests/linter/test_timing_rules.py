"""TimingRules reports absent, partial, and unknown durations per rule."""

from itertools import product
from pathlib import Path

import linter
import pytest
from chakra.schema.protobuf.et_def_pb2 import COMM_COLL_NODE, COMP_NODE, Node
from families import node, write_trace
from index_builder import TraceIndex
from timing_rules import CHECKED_TYPES, TimingRules


def trace(path: Path, durations: list[tuple[int, int]], captured: bool = True) -> Path:
    """Write nodes from (type, duration) pairs; captured traces get a header."""
    nodes = [node(i, kind, micros) for i, (kind, micros) in enumerate(durations, 1)]
    return write_trace(path, nodes, None if captured else [])


def gaps(tmp_path: Path, durations, captured: bool = True, disabled=frozenset()) -> set[tuple]:
    """Return timing gaps as {(rule, node type)}."""
    result = linter.scan_trace(trace(tmp_path / "t.et", durations, captured), disabled=disabled)
    return {(g.rule, g.node_type) for g in result.gaps if g.rule.startswith("TIM")}


def mix(zeros: int, total: int, node_type: int = COMP_NODE) -> list[tuple[int, int]]:
    """Return `total` nodes of one type, the first `zeros` with no duration."""
    return [(node_type, 0 if i < zeros else 5) for i in range(total)]


def test_all_zero_is_absent_at_trace_level(tmp_path) -> None:
    assert gaps(tmp_path, mix(10, 10)) == {("TIM001", None)}


def test_majority_zero_is_absent_at_trace_level(tmp_path) -> None:
    mixed = [(COMP_NODE, 0)] * 3 + [(COMP_NODE, 5)] * 2 + [(COMM_COLL_NODE, 5)] * 5
    # 3 of 10 zero, below the bar, but COMP is not entirely zero either
    assert gaps(tmp_path, mixed) == {("TIM002", None)}
    assert gaps(tmp_path, mix(6, 10)) == {("TIM001", None)}


def test_type_wholly_zero_reports_that_type_only(tmp_path) -> None:
    # Per-type finding replaces the trace-level partial finding
    durations = [(COMP_NODE, 0)] * 3 + [(COMM_COLL_NODE, 5)] * 7
    assert gaps(tmp_path, durations) == {("TIM001", COMP_NODE)}


def test_partial_share_between_the_bars(tmp_path) -> None:
    assert gaps(tmp_path, mix(1, 10)) == {("TIM002", None)}


def test_healthy_trace_reports_nothing(tmp_path) -> None:
    assert gaps(tmp_path, mix(1, 100)) == set()


def test_synthetic_all_zero_is_unknown(tmp_path) -> None:
    assert gaps(tmp_path, mix(10, 10), captured=False) == {("TIM003", None)}
    assert gaps(tmp_path, mix(5, 10), captured=False) == set()


def test_disabled_type_rule_still_suppresses_partial(tmp_path) -> None:
    durations = [(COMP_NODE, 0)] * 3 + [(COMM_COLL_NODE, 5)] * 7
    assert gaps(tmp_path, durations, disabled=frozenset({"TIM001"})) == set()


@pytest.mark.parametrize("rule", ["TIM001", "TIM002", "TIM003"])
def test_family_owns_the_timing_rules(rule) -> None:
    assert rule in TimingRules.checks


# --- Exhaustive checks: every small trace shape against the rule text ---

OTHER = 99  # a node type outside CHECKED_TYPES


def run(synthetic: bool, groups: dict[int, tuple[int, int]], disabled: frozenset[str] = frozenset()) -> list:
    """Feed {type: (nodes, zero-duration nodes)} to the family; return hits."""
    family = TimingRules(disabled)
    index = TraceIndex(header={} if synthetic else {"pid": 1})
    node_id = 0
    for node_type, (count, zeros) in groups.items():
        index.type_counts[node_type] = count
        for i in range(count):
            node_id += 1
            family.add(Node(id=node_id, type=node_type, duration_micros=0 if i < zeros else 5))
    index.total = node_id
    return family.finish(index) if node_id else []


def spec(synthetic: bool, groups: dict[int, tuple[int, int]]) -> set[tuple[str, int | None]]:
    """State the findings the rules.toml descriptions require."""
    total = sum(n for n, _ in groups.values())
    zero = sum(z for _, z in groups.values())
    if synthetic:
        # TIM003: a generated trace with zero duration on every node
        return {("TIM003", None)} if zero == total else set()
    found: set[tuple[str, int | None]] = set()
    # TIM001: a checked type whose nodes all lack duration, unless the
    # whole trace lacks it, which reports once at trace level
    typed = {t for t, (n, z) in groups.items() if t in CHECKED_TYPES and n and z == n and zero != total}
    found |= {("TIM001", t) for t in typed}
    # TIM001: most or all nodes lack duration; TIM002: 5% to 50% do
    if zero == total or (not typed and zero / total > 0.5):
        found.add(("TIM001", None))
    elif not typed and zero / total > 0.05:
        found.add(("TIM002", None))
    return found


def shapes(counts: dict[int, list[int]]):
    """Yield every {type: (nodes, zeros)} over the given node counts."""
    options = [[(t, (n, z)) for n in ns for z in range(n + 1)] for t, ns in counts.items()]
    for combo in product(*options):
        groups = {t: nz for t, nz in combo if nz[0]}
        if groups:
            yield groups


@pytest.mark.parametrize("synthetic", [False, True])
def test_every_small_shape_matches_the_spec(synthetic) -> None:
    # Up to 3 nodes of each of 3 types; reaches the 50% boundary
    for groups in shapes({COMP_NODE: [0, 1, 2, 3], COMM_COLL_NODE: [0, 1, 2, 3], OTHER: [0, 1, 2, 3]}):
        hits = {(h.rule, h.node_type) for h in run(synthetic, groups)}
        assert hits == spec(synthetic, groups), groups


@pytest.mark.parametrize("synthetic", [False, True])
def test_every_ratio_around_the_bars_matches_the_spec(synthetic) -> None:
    # 20, 40 and 100 nodes put exact 5% and 50% shares in reach
    for groups in shapes({COMP_NODE: [1, 20, 40, 100], COMM_COLL_NODE: [0, 1, 20]}):
        hits = {(h.rule, h.node_type) for h in run(synthetic, groups)}
        assert hits == spec(synthetic, groups), groups


def test_hits_carry_their_counts_and_totals() -> None:
    groups = {COMP_NODE: (4, 4), COMM_COLL_NODE: (6, 0)}
    (hit,) = run(False, groups)
    assert (hit.rule, hit.node_type, hit.values) == ("TIM001", COMP_NODE, {"count": 4, "total": 4})
    (hit,) = run(False, {COMP_NODE: (10, 6)})
    assert (hit.rule, hit.values) == ("TIM001", {"count": 6, "total": 10})
    (hit,) = run(False, {COMP_NODE: (10, 1)})
    assert (hit.rule, hit.values) == ("TIM002", {"count": 1, "total": 10})


def test_sample_ids_keep_first_two_then_latest() -> None:
    (hit,) = run(False, {COMP_NODE: (10, 6)})
    assert hit.ids == [1, 2, 6]
    (hit,) = run(False, {COMP_NODE: (3, 1), COMM_COLL_NODE: (3, 0)})
    assert hit.ids == [1]


def test_at_most_one_trace_level_hit() -> None:
    for synthetic in (False, True):
        for groups in shapes({COMP_NODE: [0, 1, 2, 3], COMM_COLL_NODE: [0, 1, 2, 3]}):
            levels = [h for h in run(synthetic, groups) if h.node_type is None]
            assert len(levels) <= 1, groups


@pytest.mark.parametrize("off", ["TIM001", "TIM002", "TIM003"])
def test_disabled_rule_emits_nothing_and_changes_no_other(off) -> None:
    for synthetic in (False, True):
        for groups in shapes({COMP_NODE: [0, 1, 2, 3], COMM_COLL_NODE: [0, 1, 2, 3]}):
            hits = {(h.rule, h.node_type) for h in run(synthetic, groups, frozenset({off}))}
            assert hits == {h for h in spec(synthetic, groups) if h[0] != off}, (off, groups)
