"""IntegrityRules reports node types that the installed schema lacks."""

from itertools import product

from chakra.schema.protobuf.et_def_pb2 import NodeType
from families import node, run
from integrity_rules import IntegrityRules

KNOWN = sorted(NodeType.DESCRIPTOR.values_by_number)[:3]
UNKNOWN = (97, 98)


def test_every_mix_of_known_and_unknown_types_matches_the_spec() -> None:
    for types in product((*KNOWN, *UNKNOWN), repeat=3):
        hits, _ = run(IntegrityRules(), [node(i, t) for i, t in enumerate(types, 1)])
        got = {h.values["type"]: (h.values["count"], h.ids) for h in hits if h.rule == "INT003"}
        # INT003: each type the schema does not define, with its node count
        want = {t: (types.count(t), [i for i, x in enumerate(types, 1) if x == t]) for t in set(types) if t in UNKNOWN}
        assert got == want, types


def test_sample_ids_keep_first_two_then_latest() -> None:
    hits, _ = run(IntegrityRules(), [node(i, 97) for i in range(1, 7)])
    assert hits[0].ids == [1, 2, 6]


def test_disabled_rule_emits_nothing() -> None:
    hits, _ = run(IntegrityRules({"INT003"}), [node(1, 97)])
    assert [h.rule for h in hits] == ["INT004"]


def test_empty_trace_reports_int002() -> None:
    hits, _ = run(IntegrityRules(), [])
    assert [(h.rule, h.values) for h in hits] == [("INT002", {"count": 0})]


def test_nonempty_trace_reports_its_count_not_int002() -> None:
    hits, _ = run(IntegrityRules(), [node(1)])
    assert [(h.rule, h.values) for h in hits] == [("INT004", {"count": 1})]


def test_unreadable_file_reports_int001_not_int002(tmp_path) -> None:
    from index_builder import IndexBuilder

    index = IndexBuilder(tmp_path / "missing.et", families=[IntegrityRules()]).build()
    hits = IntegrityRules().finish(index)
    assert [h.rule for h in hits] == ["INT001"]
    assert isinstance(hits[0].values["error"], Exception)
