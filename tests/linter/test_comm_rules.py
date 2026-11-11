"""CommRules reports every communication defect that the rule text names."""

from itertools import product

import pytest
from chakra.schema.protobuf.et_def_pb2 import COMM_COLL_NODE, COMM_RECV_NODE, COMM_SEND_NODE, COMP_NODE
from comm_rules import CommRules
from families import node, run

SIZES = (None, 0, 8)  # absent, zero, nonzero comm_size
STREAMS = (None, 0, 3)  # absent, default, device


def variants(node_type: int) -> list[dict]:
    """List every attribute combination a node of the type may carry."""
    peers = ("comm_src", "comm_dst") if node_type != COMM_COLL_NODE else ("comm_type", "pg_name")
    out = []
    for flags in product((False, True), repeat=2):
        for size, stream in product(SIZES, STREAMS):
            attrs = {name: 1 if name != "pg_name" else "g" for name, on in zip(peers, flags, strict=False) if on}
            if size is not None:
                attrs["comm_size"] = size
            if stream is not None and node_type == COMM_COLL_NODE:
                attrs["stream"] = stream
            out.append(attrs)
    return out


def spec(nodes: list[tuple[int, dict]]) -> dict[tuple[str, int], int]:  # noqa: C901
    """State the counts the rules.toml descriptions require."""
    found: dict[tuple[str, int], int] = {}

    def count(rule: str, node_type: int) -> None:
        found[(rule, node_type)] = found.get((rule, node_type), 0) + 1

    for node_type, attrs in nodes:
        coll = node_type == COMM_COLL_NODE
        if coll and "comm_type" not in attrs:
            count("COM002", node_type)
        if "comm_size" not in attrs:
            count("COM003", node_type)
        if coll and "pg_name" not in attrs:
            count("COM004", node_type)
        if not coll and "comm_src" not in attrs:
            count("COM005", node_type)
        if not coll and "comm_dst" not in attrs:
            count("COM006", node_type)
        if attrs.get("comm_size") == 0:
            count("COM007", node_type)
    return found


def hits_of(nodes: list[tuple[int, dict]]) -> dict[tuple[str, int], int]:
    """Run the family; return {(rule, node type): count}."""
    built = [node(i, t, **a) for i, (t, a) in enumerate(nodes, 1)]
    hits, _ = run(CommRules(), built)
    return {(h.rule, h.node_type): h.values["count"] for h in hits}


TYPES = (COMM_COLL_NODE, COMM_SEND_NODE, COMM_RECV_NODE)


@pytest.mark.parametrize("node_type", TYPES)
def test_every_single_node_matches_the_spec(node_type) -> None:
    for attrs in variants(node_type):
        assert hits_of([(node_type, attrs)]) == spec([(node_type, attrs)]), attrs


def test_every_pair_of_nodes_matches_the_spec() -> None:
    # A spread of attribute shapes per type keeps the pair count small
    pool = [(t, v) for t in TYPES for v in variants(t)[::5]]
    for first, second in product(pool, repeat=2):
        assert hits_of([first, second]) == spec([first, second]), (first, second)


def test_other_node_types_are_ignored() -> None:
    assert hits_of([(COMP_NODE, {"stream": 0})]) == {}


def test_host_operators_without_device_nodes_are_reported_once() -> None:
    host = [node(i, COMP_NODE, name="record_param_comms") for i in (1, 2, 3)]
    hits, _ = run(CommRules(), [*host, node(4, COMP_NODE, name="aten::add")])
    assert [(h.rule, h.values["count"], h.ids) for h in hits] == [("COM001", 3, [1, 2, 3])]


@pytest.mark.parametrize("device_type", TYPES)
def test_any_device_communication_node_clears_the_finding(device_type) -> None:
    built = [node(1, COMP_NODE, name="record_param_comms"), node(2, device_type)]
    hits, _ = run(CommRules(), built)
    assert "COM001" not in {h.rule for h in hits}


def test_device_nodes_alone_do_not_trigger_the_finding() -> None:
    assert "COM001" not in {h.rule for h in run(CommRules(), [node(1, COMM_COLL_NODE)])[0]}


def test_hits_group_by_node_type_in_report_order() -> None:
    nodes = [(COMM_RECV_NODE, {}), (COMM_SEND_NODE, {}), (COMM_COLL_NODE, {})]
    hits, _ = run(CommRules(), [node(i, t) for i, (t, _) in enumerate(nodes, 1)])
    order = [h.node_type for h in hits]
    assert order == sorted(order, key=(COMM_COLL_NODE, COMM_SEND_NODE, COMM_RECV_NODE).index)


def test_sample_ids_and_values() -> None:
    built = [node(i, COMM_COLL_NODE, pg_name="g", comm_size=8) for i in range(1, 6)]
    hits, _ = run(CommRules(), built)
    hit = next(h for h in hits if h.rule == "COM002")
    assert (hit.ids, hit.values) == ([1, 2, 5], {"count": 5})


@pytest.mark.parametrize("off", ["COM002", "COM003", "COM004", "COM005", "COM006", "COM007", "COM001"])
def test_disabled_rule_emits_nothing_and_changes_no_other(off) -> None:
    pool = [(t, v) for t in TYPES for v in variants(t)[::7]]
    for nodes in ([p] for p in pool):
        built = [node(i, t, **a) for i, (t, a) in enumerate(nodes, 1)]
        hits, _ = run(CommRules({off}), built)
        got = {(h.rule, h.node_type): h.values["count"] for h in hits}
        assert got == {k: v for k, v in spec(nodes).items() if k[0] != off}
