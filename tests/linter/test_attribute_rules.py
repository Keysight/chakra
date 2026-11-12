"""AttributeRules reports missing, mistyped, and invalid converter attributes."""

from itertools import product

import pytest
from chakra.schema.protobuf.et_def_pb2 import AttributeProto
from chakra.src.linter.attribute_rules import AttributeRules
from families import attr, node, run

CPU = {"is_cpu_op": True, "rf_id": 1, "fw_parent": 1, "seq_id": 1, "scope": 1, "tid": 1, "fw_tid": 1}
CPU["op_schema"] = "aten::add() -> Tensor"


def hits_of(nodes: list) -> dict[tuple[str, str | None], tuple]:
    """Run the family; return {rule: (count, sample ids)}."""
    hits, _ = run(AttributeRules(), nodes)
    return {(h.rule, h.values.get("name")): (h.values["count"], h.ids) for h in hits}


def test_every_converter_attribute_subset_matches_the_spec() -> None:
    names = sorted(AttributeRules.CONVERTER_ATTRS - {"is_cpu_op"})
    for cpu, subset in product((None, False, True), product((False, True), repeat=len(names))):
        attrs = {n: CPU[n] for n, on in zip(names, subset, strict=False) if on}
        if cpu is not None:
            attrs["is_cpu_op"] = cpu
        # A node needs a PyTorch-only attribute for ATT001 to apply
        built = [node(1, **attrs), node(2, rf_id=1)]
        # ATT001: is_cpu_op on every node; the rest only on CPU nodes
        want = {("ATT001", n): 1 for n in names if n not in attrs and cpu is True}
        # The second node lacks is_cpu_op too, so the count starts at one
        want[("ATT001", "is_cpu_op")] = 1 + ("is_cpu_op" not in attrs)
        got = {k: v[0] for k, v in hits_of(built).items() if k[0] == "ATT001"}
        assert got == want, attrs


def test_missing_attributes_are_ignored_without_pytorch_attributes() -> None:
    assert hits_of([node(1), node(2, is_cpu_op=True)]) == {}


def test_every_value_combination_matches_the_spec() -> None:
    options = {
        "rf_id": (None, 0, 1),
        "scope": (None, -1, 5, 9, 10),
        "fw_tid": (None, 0, 1),
        "fw_parent": (None, 0, 1),
    }
    for combo in product(*options.values()):
        for node_id, name in product((0, 1), ("n", f"{AttributeRules.ROOT_NAME_PREFIX}x]")):
            attrs = {k: v for k, v in zip(options, combo, strict=False) if v is not None}
            # tid marks the trace as PyTorch-derived whatever rf_id says
            got = hits_of([node(node_id, name=name, tid=1, **attrs)])
            rf_id, scope, fw_tid, fw_parent = combo
            root = name.startswith(AttributeRules.ROOT_NAME_PREFIX)
            want = {}
            # ATT003: node ID 0, or rf_id 0 outside thread roots
            if node_id == 0 or (rf_id == 0 and not root):
                want[("ATT003", None)] = (1, [node_id])
            # ATT004: scope outside 0 to 9
            if scope is not None and not 0 <= scope <= 9:
                want[("ATT004", None)] = (1, [node_id])
            # ATT005: non-zero fw_tid with fw_parent 0
            if fw_tid and fw_parent == 0:
                want[("ATT005", None)] = (1, [node_id])
            got = {k: v for k, v in got.items() if k[0] in ("ATT003", "ATT004", "ATT005")}
            assert got == want, (combo, node_id, name)


def wrong(name: str, kind: str) -> AttributeProto:
    """Build an attribute holding a value of the named kind."""
    return AttributeProto(**{"name": name, kind: "x" if kind == "string_val" else 1})


def test_wrong_kind_or_repeat_is_attribute_type_error() -> None:
    kinds = ("int64_val", "uint64_val", "string_val")
    for attr_name, kind, repeats in product(("stream", "comm_size", "op_schema", "is_cpu_op", "other"), kinds, (1, 2)):
        built = node(7)
        built.attr.extend(wrong(attr_name, kind) for _ in range(repeats))
        expected = {"stream": "int64_val", "comm_size": "int64_val", "op_schema": "string_val", "is_cpu_op": "bool_val"}
        # A known attribute must use its declared kind; any name must not repeat
        bad = repeats > 1 or (attr_name in expected and expected[attr_name] != kind)
        got = hits_of([built, node(8, rf_id=1)])
        assert (("ATT002", None) in got) == bad, (attr_name, kind, repeats)
        if bad:
            assert got[("ATT002", None)] == (1, [7])


def test_attribute_helper_builds_each_kind() -> None:
    assert attr("a", True).WhichOneof("value") == "bool_val"
    assert attr("a", "x").WhichOneof("value") == "string_val"


def test_sample_ids_keep_first_two_then_latest() -> None:
    nodes = [node(i, rf_id=0, tid=1) for i in range(1, 7)]
    assert hits_of(nodes)[("ATT003", None)] == (6, [1, 2, 6])


@pytest.mark.parametrize("off", ["ATT001", "ATT002", "ATT003", "ATT004", "ATT005"])
def test_disabled_rule_emits_nothing(off) -> None:
    built = [node(1, rf_id=0, scope=11, fw_tid=1, fw_parent=0, tid=1), node(2)]
    built[1].attr.extend([wrong("stream", "uint64_val")])
    hits, _ = run(AttributeRules({off}), built)
    assert {h.rule for h in hits} == {"ATT001", "ATT002", "ATT003", "ATT004", "ATT005"} - {off}
