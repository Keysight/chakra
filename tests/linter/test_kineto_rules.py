"""KinetoRules judges device links and durations of a captured trace."""

from itertools import product
from pathlib import Path

import pytest
from chakra.schema.protobuf.et_def_pb2 import COMM_COLL_NODE, COMP_NODE, Node
from chakra.src.linter import linter
from chakra.src.linter.index_builder import TraceIndex
from chakra.src.linter.kineto_rules import CHECKED_TYPES, KinetoRules
from families import node, run, write_trace

# A node: None (no stream data) or (stream, duration, parent IDs)
STREAMS = (0, 3)
DURATIONS = (0, 5)
PARENTS = ((), (1,), (9,), (1, 2))
NODE_OPTIONS = [None, *product(STREAMS, DURATIONS, PARENTS)]


# The link tests leave out the timing rules KIN007 to KIN009
TIMING = frozenset({"KIN007", "KIN008", "KIN009"})


def build(options: list) -> list:
    """Make nodes 1..n; a captured trace's host parent is node 1."""
    nodes = []
    for node_id, option in enumerate(options, 1):
        if option is None:
            nodes.append(node(node_id, duration=5))
        else:
            stream, duration, parents = option
            built = node(node_id, duration=duration, stream=stream)
            built.ctrl_deps.extend(parents)
            nodes.append(built)
    return nodes


def spec(options: list, header: bool) -> dict[str, int | None]:
    """State the findings the rule descriptions require."""
    streamed = [o for o in options if o is not None]
    # No capture marker, no PyTorch attribute, no stream: a generated trace
    if not header and not streamed:
        return {}
    if not streamed:
        return {"KIN001": None}
    found: dict[str, int | None] = {}
    # KIN002: stream data without any duration
    if not any(duration > 0 for _, duration, _ in streamed):
        found["KIN002"] = None
    ids = set(range(1, len(options) + 1))
    # Device nodes are those off the default stream
    device = [parents for stream, _, parents in streamed if stream != 0]
    orphans = sum(not any(p in ids for p in parents) for parents in device)
    multi = sum(sum(p in ids for p in parents) > 1 for parents in device)
    # KIN005 and KIN006 take the place of KIN003 and KIN004 without durations
    untimed = "KIN002" in found
    if orphans:
        found["KIN005" if untimed else "KIN003"] = orphans
    if multi:
        found["KIN006" if untimed else "KIN004"] = multi
    return found


def hits_of(options: list, header: bool) -> dict[str, int | None]:
    """Run the family; return {rule: count}."""
    hits, _ = run(KinetoRules(TIMING), build(options), {"pid": 1} if header else {})
    return {h.rule: h.values.get("count") for h in hits}


@pytest.mark.parametrize("header", [False, True])
def test_every_small_trace_matches_the_spec(header) -> None:
    for length in (1, 2, 3):
        pool = NODE_OPTIONS if length < 3 else NODE_OPTIONS[::3]
        for options in product(pool, repeat=length):
            assert hits_of(list(options), header) == spec(list(options), header), options


def test_parent_defects_split_on_whether_durations_exist() -> None:
    assert hits_of([(3, 0, (9,))], True) == {"KIN002": None, "KIN005": 1}
    assert hits_of([(3, 5, (9,))], True) == {"KIN003": 1}
    assert hits_of([(3, 0, (1, 2)), (0, 0, ())], True) == {"KIN002": None, "KIN006": 1}
    assert hits_of([(3, 5, (1, 2)), (0, 5, ())], True) == {"KIN004": 1}


def test_sample_ids_for_each_rule() -> None:
    hits, _ = run(KinetoRules(TIMING), build([None, None]), {"pid": 1})
    assert hits[0].ids == [1, 2]
    hits, _ = run(KinetoRules(TIMING), build([(3, 0, (9,)), (3, 0, (9,))]), {"pid": 1})
    assert {h.rule: h.ids for h in hits} == {"KIN002": [1, 2], "KIN005": [1, 2]}


@pytest.mark.parametrize("off", ["KIN001", "KIN002", "KIN003", "KIN004", "KIN005", "KIN006"])
def test_disabled_rule_emits_nothing(off) -> None:
    for options in ([None], [(3, 0, (1, 2)), (3, 0, (9,))]):
        hits, _ = run(KinetoRules(TIMING | {off}), build(options), {"pid": 1})
        want = {k: v for k, v in spec(options, True).items() if k != off}
        assert {h.rule: h.values.get("count") for h in hits} == want


# --- Timing rules KIN007 to KIN009 ---


def write_timing_trace(path: Path, durations: list[tuple[int, int]], captured: bool = True) -> Path:
    """Write nodes from (type, duration) pairs; captured traces get a header."""
    nodes = [node(i, kind, micros) for i, (kind, micros) in enumerate(durations, 1)]
    return write_trace(path, nodes, None if captured else [])


def timing_gaps(tmp_path: Path, durations, captured: bool = True, disabled=frozenset()) -> set[tuple]:
    """Return timing gaps as {(rule, node type)}."""
    result = linter.scan_trace(write_timing_trace(tmp_path / "t.et", durations, captured), disabled=disabled)
    return {(g.rule, g.node_type) for g in result.gaps if g.rule in {"KIN007", "KIN008", "KIN009"}}


def mix_durations(zeros: int, total: int, node_type: int = COMP_NODE) -> list[tuple[int, int]]:
    """Return `total` nodes of one type, the first `zeros` with no duration."""
    return [(node_type, 0 if i < zeros else 5) for i in range(total)]


def test_all_zero_is_absent_at_trace_level(tmp_path) -> None:
    assert timing_gaps(tmp_path, mix_durations(10, 10)) == {("KIN007", None)}


def test_majority_zero_is_absent_at_trace_level(tmp_path) -> None:
    mixed = [(COMP_NODE, 0)] * 3 + [(COMP_NODE, 5)] * 2 + [(COMM_COLL_NODE, 5)] * 5
    # 3 of 10 zero, below the bar, but COMP is not entirely zero either
    assert timing_gaps(tmp_path, mixed) == {("KIN008", None)}
    assert timing_gaps(tmp_path, mix_durations(6, 10)) == {("KIN007", None)}


def test_type_wholly_zero_reports_that_type_only(tmp_path) -> None:
    # Per-type finding replaces the trace-level partial finding
    durations = [(COMP_NODE, 0)] * 3 + [(COMM_COLL_NODE, 5)] * 7
    assert timing_gaps(tmp_path, durations) == {("KIN007", COMP_NODE)}


def test_partial_share_between_the_bars(tmp_path) -> None:
    assert timing_gaps(tmp_path, mix_durations(1, 10)) == {("KIN008", None)}


def test_healthy_trace_reports_nothing(tmp_path) -> None:
    assert timing_gaps(tmp_path, mix_durations(1, 100)) == set()


def test_synthetic_all_zero_is_unknown(tmp_path) -> None:
    assert timing_gaps(tmp_path, mix_durations(10, 10), captured=False) == {("KIN009", None)}
    assert timing_gaps(tmp_path, mix_durations(5, 10), captured=False) == set()


def test_disabled_type_rule_still_suppresses_partial(tmp_path) -> None:
    durations = [(COMP_NODE, 0)] * 3 + [(COMM_COLL_NODE, 5)] * 7
    assert timing_gaps(tmp_path, durations, disabled=frozenset({"KIN007"})) == set()


@pytest.mark.parametrize("rule", ["KIN007", "KIN008", "KIN009"])
def test_family_owns_the_timing_rules(rule) -> None:
    assert rule in KinetoRules.checks


# --- Exhaustive checks: every small trace shape against the rule text ---

OTHER = 99  # a node type outside CHECKED_TYPES


def run_timing(synthetic: bool, groups: dict[int, tuple[int, int]], disabled: frozenset[str] = frozenset()) -> list:
    """Feed {type: (nodes, zero-duration nodes)} to the family; return hits."""
    # Device-link rules need streams; this test covers the timing rules only
    family = KinetoRules(disabled | {f"KIN00{n}" for n in range(1, 7)})
    index = TraceIndex(header={} if synthetic else {"pid": 1})
    family.index = index
    node_id = 0
    for node_type, (count, zeros) in groups.items():
        index.type_counts[node_type] = count
        for i in range(count):
            node_id += 1
            family.add(Node(id=node_id, type=node_type, duration_micros=0 if i < zeros else 5))
    index.total = node_id
    return family.finish(index) if node_id else []


def timing_spec(synthetic: bool, groups: dict[int, tuple[int, int]]) -> set[tuple[str, int | None]]:
    """State the findings the rule descriptions require."""
    total = sum(n for n, _ in groups.values())
    zero = sum(z for _, z in groups.values())
    if synthetic:
        # KIN009: a generated trace with zero duration on every node
        return {("KIN009", None)} if zero == total else set()
    found: set[tuple[str, int | None]] = set()
    # KIN007: a checked type whose nodes all lack duration, unless the
    # whole trace lacks it, which reports once at trace level
    typed = {t for t, (n, z) in groups.items() if t in CHECKED_TYPES and n and z == n and zero != total}
    found |= {("KIN007", t) for t in typed}
    # KIN007: most or all nodes lack duration; KIN008: 5% to 50% do
    if zero == total or (not typed and zero / total > 0.5):
        found.add(("KIN007", None))
    elif not typed and zero / total > 0.05:
        found.add(("KIN008", None))
    return found


def timing_shapes(counts: dict[int, list[int]]):
    """Yield every {type: (nodes, zeros)} over the given node counts."""
    options = [[(t, (n, z)) for n in ns for z in range(n + 1)] for t, ns in counts.items()]
    for combo in product(*options):
        groups = {t: nz for t, nz in combo if nz[0]}
        if groups:
            yield groups


@pytest.mark.parametrize("synthetic", [False, True])
def test_every_small_shape_matches_the_spec(synthetic) -> None:
    # Up to 3 nodes of each of 3 types; reaches the 50% boundary
    for groups in timing_shapes({COMP_NODE: [0, 1, 2, 3], COMM_COLL_NODE: [0, 1, 2, 3], OTHER: [0, 1, 2, 3]}):
        hits = {(h.rule, h.node_type) for h in run_timing(synthetic, groups)}
        assert hits == timing_spec(synthetic, groups), groups


@pytest.mark.parametrize("synthetic", [False, True])
def test_every_ratio_around_the_bars_matches_the_spec(synthetic) -> None:
    # 20, 40 and 100 nodes put exact 5% and 50% shares in reach
    for groups in timing_shapes({COMP_NODE: [1, 20, 40, 100], COMM_COLL_NODE: [0, 1, 20]}):
        hits = {(h.rule, h.node_type) for h in run_timing(synthetic, groups)}
        assert hits == timing_spec(synthetic, groups), groups


def test_hits_carry_their_counts_and_totals() -> None:
    groups = {COMP_NODE: (4, 4), COMM_COLL_NODE: (6, 0)}
    (hit,) = run_timing(False, groups)
    assert (hit.rule, hit.node_type, hit.values) == ("KIN007", COMP_NODE, {"count": 4, "total": 4})
    (hit,) = run_timing(False, {COMP_NODE: (10, 6)})
    assert (hit.rule, hit.values) == ("KIN007", {"count": 6, "total": 10})
    (hit,) = run_timing(False, {COMP_NODE: (10, 1)})
    assert (hit.rule, hit.values) == ("KIN008", {"count": 1, "total": 10})


def test_timing_sample_ids_keep_first_two_then_latest() -> None:
    (hit,) = run_timing(False, {COMP_NODE: (10, 6)})
    assert hit.ids == [1, 2, 6]
    (hit,) = run_timing(False, {COMP_NODE: (3, 1), COMM_COLL_NODE: (3, 0)})
    assert hit.ids == [1]


def test_at_most_one_trace_level_hit() -> None:
    for synthetic in (False, True):
        for groups in timing_shapes({COMP_NODE: [0, 1, 2, 3], COMM_COLL_NODE: [0, 1, 2, 3]}):
            levels = [h for h in run_timing(synthetic, groups) if h.node_type is None]
            assert len(levels) <= 1, groups


@pytest.mark.parametrize("off", ["KIN007", "KIN008", "KIN009"])
def test_disabled_timing_rule_emits_nothing_and_changes_no_other(off) -> None:
    for synthetic in (False, True):
        for groups in timing_shapes({COMP_NODE: [0, 1, 2, 3], COMM_COLL_NODE: [0, 1, 2, 3]}):
            hits = {(h.rule, h.node_type) for h in run_timing(synthetic, groups, frozenset({off}))}
            assert hits == {h for h in timing_spec(synthetic, groups) if h[0] != off}, (off, groups)
