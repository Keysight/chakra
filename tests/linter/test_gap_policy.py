"""Hits become gaps with the consumer levels that the rule implies."""

import consumer
import linter
import messages
import pytest
import rule_config
from rule_family import Hit


def gap(rule: str) -> consumer.Gap:
    """Build the gap of a bare hit."""
    hit = Hit(rule, [1], {"count": 1, "total": 1, "family": "f"})
    return consumer.Gap.from_hit(hit, messages.render(messages.default_messages(), rule, **hit.values))


def test_every_family_gap_rule_is_a_gap_in_the_toml() -> None:
    import rule_family

    notes = {"OPS002", "MET012"}  # notes, not gaps
    needed = {rule for family in rule_family.FAMILIES for rule in family.checks} - notes
    # Fatal findings stop the scan before grading
    needed -= {"MET009", "MET010"}
    rules = rule_config.shipped_rules()
    assert {r for r in needed if rules[r].is_gap()} == needed


def test_each_case_is_its_own_rule_with_a_flat_consumer_impact() -> None:
    assert gap("OPS001").consumer_impact == {"replay": "REVIEW"}
    assert gap("OPS005").consumer_impact == {"replay": "NOT SUITABLE"}
    assert gap("OPS003").consumer_impact == {"replay": "NOT SUITABLE"}
    assert gap("OPS006").consumer_impact == {"replay": "REVIEW"}
    assert gap("KIN003").consumer_impact == {"simulator": "LIMITED", "analysis": "LIMITED"}
    assert gap("KIN005").consumer_impact == {"simulator": "REVIEW", "analysis": "NOT SUITABLE"}


def test_consumer_impact_values_are_levels_never_tables() -> None:
    for rule in rule_config.shipped_rules().values():
        assert all(isinstance(v, str) for v in rule.consumer_impact.values()), rule.id


def test_every_rule_declares_a_consumer_impact_for_all_three_consumers() -> None:
    for rule in rule_config.shipped_rules().values():
        assert list(rule.consumer_impact) == ["replay", "simulator", "analysis"], rule.id


def test_consumer_impact_is_ready_exactly_when_the_rule_cannot_lower_a_consumer() -> None:
    for rule in rule_config.shipped_rules().values():
        ready = set(rule.consumer_impact.values()) == {"READY"}
        assert ready == (rule.severity in ("info", "pass")), rule.id


def test_aggregates_cover_the_three_consumers_in_order() -> None:
    shipped = consumer.TraceResult.aggregates()
    assert list(shipped) == ["replay", "simulator", "analysis"]
    assert [a.id for a in shipped.values()] == ["SUI001", "SUI002", "SUI003"]


def test_consumer_impact_naming_an_unknown_consumer_is_rejected(tmp_path) -> None:
    text = rule_config.DEFAULT_RULES.read_text(encoding="utf-8")
    text = text.replace("consumer_impact = { replay", "consumer_impact = { toaster", 1)
    path = tmp_path / "rules.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(rule_config.RuleConfigError, match="toaster"):
        rule_config.load_rules(path)


@pytest.mark.parametrize("severity", ["info", "pass"])
def test_info_and_pass_hits_lower_no_consumer_level(tmp_path, monkeypatch, severity) -> None:
    """Grading ignores info and pass hits, as it ignores a rule with no hit."""
    from dataclasses import replace

    import rule_family
    from families import node, write_trace

    path = write_trace(tmp_path / "t.et", [node(i) for i in (1, 2, 3)])
    assert linter.lint_trace(path).gaps  # the bare trace has gaps to ignore
    real = rule_family.RuleFamily.finish
    monkeypatch.setattr(
        rule_family.RuleFamily,
        "finish",
        lambda self, index: [replace(h, severity=severity) for h in real(self, index)],
    )
    result = linter.lint_trace(path)
    assert not result.gaps
    assert all(result.status(c)[0] == consumer.READY for c in consumer.CONSUMERS)
    assert bool(result.findings) == (severity == "info")
