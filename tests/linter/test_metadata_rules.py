"""MetadataRules judges the header: version is required, the rest warn."""

from itertools import product

from families import node, run
from metadata_rules import MetadataRules

TIMES = (None, 5, 10, "late")  # start_ts or finish_ts: absent, early, late, text
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
    hits, _ = run(MetadataRules(), nodes, head)
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
