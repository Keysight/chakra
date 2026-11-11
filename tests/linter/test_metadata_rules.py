"""MetadataRules judges readability, node types, and the header."""

from itertools import product

from chakra.schema.protobuf.et_def_pb2 import NodeType
from families import node, run
from index_builder import IndexBuilder
from metadata_rules import MetadataRules

TIMES = (None, 5, 10, "late")  # start_ts or finish_ts: absent, early, late, text
# The header tests leave out the integrity rules MET009 to MET012
INTEGRITY = frozenset({"MET009", "MET010", "MET011", "MET012"})
# The integrity tests leave out the header rules MET001 to MET008
HEADER = frozenset(f"MET00{n}" for n in range(1, 9))
KNOWN = sorted(NodeType.DESCRIPTOR.values_by_number)[:3]
UNKNOWN = (97, 98)
ATTR_RULES = MetadataRules.METADATA_ATTRS
ALL_RULES = {"MET001", "MET002", "MET003", "MET004", "MET007"}  # inverted header


def header(version: bool, present: tuple[bool, ...], start, finish) -> dict[str, object]:
    """Build a header with the chosen attributes and timestamps."""
    out: dict[str, object] = {n: 1 for n, on in zip(ATTR_RULES.values(), present, strict=True) if on}
    out.pop("start_ts", None)
    out.pop("finish_ts", None)
    if start is not None:
        out["start_ts"] = start
    if finish is not None:
        out["finish_ts"] = finish
    if version:
        out["version"] = "0.0.4"
    return out


def hits_of(head: dict[str, object], pytorch: bool) -> dict[str, dict]:
    """Run the family on a trace with or without PyTorch-only attributes."""
    nodes = [node(1, rf_id=1)] if pytorch else [node(1)]
    hits, _ = run(MetadataRules(INTEGRITY), nodes, head)
    return {h.rule: h.values for h in hits}


def test_every_header_matches_the_spec() -> None:
    for version, present in product((False, True), product((False, True), repeat=len(ATTR_RULES))):
        for start, finish, pytorch in product(TIMES, TIMES, (False, True)):
            head = header(version, present, start, finish)
            want: dict[str, dict] = {}
            # MET001: the version is required on every trace
            if not version:
                want["MET001"] = {}
            # MET002 to MET006: one rule per converter attribute; PyTorch only
            if pytorch:
                want |= {r: {"name": n} for r, n in ATTR_RULES.items() if n not in head}
            # MET007: finish_ts precedes start_ts; both must be numbers
            start_ts, finish_ts = head.get("start_ts"), head.get("finish_ts")
            if pytorch and isinstance(start_ts, int) and isinstance(finish_ts, int) and finish_ts < start_ts:
                want["MET007"] = {"start": start_ts, "finish": finish_ts}
            assert hits_of(head, pytorch) == want, head


def test_schema_list_matches_the_converter() -> None:
    """MET008 accepts exactly the schemas that the converter accepts."""
    from chakra.src.converter.pytorch_node import PyTorchNode

    assert set(MetadataRules.SUPPORTED_SCHEMAS) == set(PyTorchNode.SUPPORTED_VERSIONS)


def test_unsupported_schema_is_reported_on_pytorch_traces_only() -> None:
    bad: dict[str, object] = {"version": "0.0.4", "schema": "9.9.9-chakra.0.0.4"}
    for schema in MetadataRules.SUPPORTED_SCHEMAS:
        assert "MET008" not in hits_of({**bad, "schema": schema}, pytorch=True)
    assert hits_of(bad, pytorch=True)["MET008"] == {"value": "9.9.9-chakra.0.0.4"}
    assert "MET008" not in hits_of(bad, pytorch=False)


# --- Integrity rules MET009 to MET012 ---


def test_every_mix_of_known_and_unknown_types_matches_the_spec() -> None:
    for types in product((*KNOWN, *UNKNOWN), repeat=3):
        hits, _ = run(MetadataRules(HEADER), [node(i, t) for i, t in enumerate(types, 1)])
        got = {h.values["type"]: (h.values["count"], h.ids) for h in hits if h.rule == "MET011"}
        # MET011: each type the schema does not define, with its node count
        want = {t: (types.count(t), [i for i, x in enumerate(types, 1) if x == t]) for t in set(types) if t in UNKNOWN}
        assert got == want, types


def test_unknown_type_sample_ids_keep_first_two_then_latest() -> None:
    hits, _ = run(MetadataRules(HEADER), [node(i, 97) for i in range(1, 7)])
    assert hits[0].ids == [1, 2, 6]


def test_disabled_integrity_rule_emits_nothing() -> None:
    hits, _ = run(MetadataRules(HEADER | {"MET011"}), [node(1, 97)])
    assert [h.rule for h in hits] == ["MET012"]


def test_empty_trace_reports_met010() -> None:
    hits, _ = run(MetadataRules(HEADER), [])
    assert [(h.rule, h.values) for h in hits] == [("MET010", {"count": 0})]


def test_nonempty_trace_reports_its_count_not_met010() -> None:
    hits, _ = run(MetadataRules(HEADER), [node(1)])
    assert [(h.rule, h.values) for h in hits] == [("MET012", {"count": 1})]


def test_unreadable_file_reports_met009_not_met010(tmp_path) -> None:
    index = IndexBuilder(tmp_path / "missing.et", families=[MetadataRules(HEADER)]).build()
    hits = MetadataRules(HEADER).finish(index)
    assert [h.rule for h in hits] == ["MET009"]
    assert isinstance(hits[0].values["error"], Exception)
