"""KinetoRules judges whether device data was linked into a captured trace."""

from itertools import product

import pytest
from families import node, run
from kineto_rules import KinetoRules

# A node: None (no stream data) or (stream, duration, parent IDs)
STREAMS = (0, 3)
DURATIONS = (0, 5)
PARENTS = ((), (1,), (9,), (1, 2))
NODE_OPTIONS = [None, *product(STREAMS, DURATIONS, PARENTS)]


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
    """State the findings the rules.toml descriptions require."""
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
    hits, _ = run(KinetoRules(), build(options), {"pid": 1} if header else {})
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
    hits, _ = run(KinetoRules(), build([None, None]), {"pid": 1})
    assert hits[0].ids == [1, 2]
    hits, _ = run(KinetoRules(), build([(3, 0, (9,)), (3, 0, (9,))]), {"pid": 1})
    assert {h.rule: h.ids for h in hits} == {"KIN002": [1, 2], "KIN005": [1, 2]}


@pytest.mark.parametrize("off", ["KIN001", "KIN002", "KIN003", "KIN004", "KIN005", "KIN006"])
def test_disabled_rule_emits_nothing(off) -> None:
    for options in ([None], [(3, 0, (1, 2)), (3, 0, (9,))]):
        hits, _ = run(KinetoRules({off}), build(options), {"pid": 1})
        want = {k: v for k, v in spec(options, True).items() if k != off}
        assert {h.rule: h.values.get("count") for h in hits} == want
