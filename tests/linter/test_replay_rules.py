"""ReplayRules reports schema, I/O, and idle-compute defects of replay units."""

from itertools import product

import pytest
from chakra.schema.protobuf.et_def_pb2 import COMM_COLL_NODE, COMP_NODE
from chakra.src.linter.replay_rules import ReplayRules
from families import node, run

SCHEMA = "aten::add(Tensor a) -> Tensor"  # one argument
OK_IO = {"values": "[1]", "shapes": "[[1]]", "types": "['T']"}
TWO_IO = {"values": "[1, 2]", "shapes": "[[1], [1]]", "types": "['T', 'T']"}

# kind: (is_cpu_op, op_schema, name, duration, inputs, rule the I/O breaks)
KINDS = {
    "cpu_ok": (True, SCHEMA, "ok", 5, OK_IO, ""),
    "cpu_bad_io": (True, SCHEMA, "bad", 5, {"values": "x[", "shapes": "", "types": ""}, "OPS007"),
    "cpu_arity": (True, SCHEMA, "arity", 5, TWO_IO, "OPS008"),
    "cpu_no_io": (True, SCHEMA, "noio", 5, None, "OPS009"),
    "cpu_no_args": (True, "aten::x() -> Tensor", "noargs", 5, None, ""),
    "cpu_bare": (True, "", "bare", 5, None, ""),
    "cpu_exempt": (True, "", "nccl:x", 5, None, ""),
    "gpu_kernel": (False, "", "kern", 5, None, ""),
    "gpu_idle": (False, "", "kern", 0, None, ""),
    "other": None,
}
CPU_KINDS = [k for k, v in KINDS.items() if v and v[0]]


def skip(name: str) -> bool:
    """Exempt the communication wrappers."""
    return name.startswith("nccl:")


def build(kinds: tuple, parented: tuple) -> list:
    """Make a chain: node i has node i-1 as its only control parent."""
    nodes = []
    for i, (kind, has_parent) in enumerate(zip(kinds, parented, strict=False), 1):
        spec_ = KINDS[kind]
        if spec_ is None:
            built = node(i, COMM_COLL_NODE)
        else:
            is_cpu, schema, name, duration, io, _ = spec_
            attrs = {"is_cpu_op": is_cpu, **({"op_schema": schema} if schema else {})}
            built = node(i, COMP_NODE, duration, name, **attrs)
            if io:
                for field in (built.inputs, built.outputs):
                    field.values, field.shapes, field.types = io["values"], io["shapes"], io["types"]
        if has_parent and i > 1:
            built.ctrl_deps.append(i - 1)
        nodes.append(built)
    return nodes


def spec(kinds: tuple, parented: tuple, captured: bool) -> dict:  # noqa: C901
    """State the findings the rule descriptions require."""
    ids = range(1, len(kinds) + 1)
    parent = {i: (i - 1 if parented[i - 1] and i > 1 else None) for i in ids}
    kind = {i: kinds[i - 1] for i in ids}
    cpu = {i for i in ids if kind[i] in CPU_KINDS}
    schema = {i for i in cpu if KINDS[kind[i]][1]}
    parents_of_cpu = {parent[i] for i in cpu if parent[i] is not None}
    units, missing = [], []
    for i in sorted(cpu):
        up = parent[i]
        covered = False
        # An ancestor with a schema replays the node as part of its subtree
        while up in cpu:
            if up in schema:
                covered = True
                break
            up = parent[up]
        if covered:
            continue
        if i in schema:
            units.append(i)
        elif i not in parents_of_cpu and not skip(KINDS[kind[i]][2]):
            units.append(i)
            missing.append(i)
    found: dict = {}
    if missing:
        # OPS005 takes the place of OPS001 when no operator has a schema
        found["OPS001" if len(missing) < len(units) else "OPS005"] = (len(missing), len(units))
    elif not units:
        comp = [i for i in ids if KINDS[kind[i]] is not None]
        # OPS006 takes the place of OPS003 in a synthetic trace
        found["OPS003" if captured else "OPS006"] = (len(comp), len([i for i in comp if KINDS[kind[i]][1]]))
    for rule in ("OPS007", "OPS008", "OPS009"):
        count = sum(1 for i in units if i in schema and KINDS[kind[i]][5] == rule)
        if count:
            found[rule] = (count, len(units))
    gpu = [i for i in ids if kind[i] in ("gpu_kernel", "gpu_idle")]
    if gpu:
        found["OPS002"] = (len(gpu), len(gpu))
    if captured and "gpu_idle" in kind.values():
        found["OPS004"] = (list(kind.values()).count("gpu_idle"),)
    return found


def hits_of(kinds: tuple, parented: tuple, captured: bool = True) -> dict:
    """Run the family; return {rule: values tuple} comparable to `spec`."""
    hits, _ = run(ReplayRules(skip=skip), build(kinds, parented), {"pid": 1} if captured else {})
    out = {}
    for h in hits:
        v = h.values
        if h.rule in ("OPS001", "OPS005"):
            out[h.rule] = (v["count"], v["total"])
        elif h.rule in ("OPS003", "OPS006"):
            out[h.rule] = (v["total"], v["schema"])
        elif h.rule == "OPS002" or h.rule in {"OPS007", "OPS008", "OPS009"}:
            out[h.rule] = (v["count"], v["total"])
        else:
            out[h.rule] = (v["count"],)
    return out


@pytest.mark.parametrize("length", [1, 2, 3])
def test_every_small_forest_matches_the_spec(length) -> None:
    for kinds in product(KINDS, repeat=length):
        for parented in product((False, True), repeat=length):
            assert hits_of(kinds, parented) == spec(kinds, parented, True), (kinds, parented)


def test_synthetic_traces_never_report_idle_compute() -> None:
    for kinds in product(KINDS, repeat=2):
        assert hits_of(kinds, (False, True), captured=False) == spec(kinds, (False, True), False), kinds


def test_io_checks_cover_only_the_outermost_schema_node() -> None:
    # The inner node has bad I/O but its parent already replays the subtree
    assert "OPS007" not in hits_of(("cpu_ok", "cpu_bad_io"), (False, True))
    assert "OPS007" in hits_of(("cpu_ok", "cpu_bad_io"), (False, False))


def test_ops001_reports_one_hit_per_operator_family_with_first_node() -> None:
    # Node 3 has a schema, so the gap is partial and OPS001 applies
    hits, _ = run(
        ReplayRules(),
        [
            node(1, COMP_NODE, 5, "a_b_c_1", is_cpu_op=True),
            node(2, name="x::y", is_cpu_op=True),
            node(3, name="ok", is_cpu_op=True, op_schema="aten::ok() -> ()"),
        ],
    )
    by_family = {h.values["family"]: (h.values["count"], h.ids) for h in hits if h.rule == "OPS001"}
    assert by_family == {"a_b_c": (1, [1]), "x": (1, [2])}


def test_ops003_samples_compute_nodes_else_the_first_type() -> None:
    hits, _ = run(ReplayRules(), [node(1, COMM_COLL_NODE), node(2, COMM_COLL_NODE)])
    assert [(h.rule, h.ids) for h in hits] == [("OPS003", [1, 2])]
    hits, _ = run(ReplayRules(), [node(1, COMM_COLL_NODE), node(2, COMP_NODE, is_cpu_op=False)])
    assert [(h.rule, h.ids) for h in hits if h.rule == "OPS003"] == [("OPS003", [2])]


@pytest.mark.parametrize(
    "off", ["OPS001", "OPS002", "OPS003", "OPS004", "OPS005", "OPS006", "OPS007", "OPS008", "OPS009"]
)
def test_disabled_rule_emits_nothing(off) -> None:
    kinds = ("cpu_bad_io", "cpu_arity", "cpu_no_io", "cpu_bare", "gpu_idle")
    hits, _ = run(ReplayRules({off}, skip), build(kinds, (False,) * 5))
    want = set(spec(kinds, (False,) * 5, True)) - {off}
    assert {h.rule for h in hits} == want
