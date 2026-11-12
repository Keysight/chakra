"""`--set` and `--set-file` change rule fields for one run."""

import pytest
from chakra.src.linter import consumer, linter
from chakra.src.linter.catalog import shipped_rules
from chakra.src.linter.rule_config import RuleConfigError, apply_overrides, read_settings
from families import node, write_trace


def test_each_field_can_be_set() -> None:
    rules = apply_overrides(
        shipped_rules(),
        [
            "STO007.severity=info",
            "STO007.enabled=false",
            "STO007.message=zero bytes",
            "STO007.consumer_impact.replay=REVIEW",
            "OPS001.exempt=a*, b*",
        ],
    )
    rule = rules["STO007"]
    assert (rule.severity, rule.enabled, rule.message) == ("info", False, "zero bytes")
    assert rule.consumer_impact["replay"] == "REVIEW"
    assert rules["OPS001"].exempt == ["a*", "b*"]


def test_shipped_rules_stay_unchanged() -> None:
    apply_overrides(shipped_rules(), ["STO007.severity=info"])
    assert shipped_rules()["STO007"].severity != "info"


def test_selector_accepts_id_name_and_prefix() -> None:
    by_name = apply_overrides(shipped_rules(), ["dag-cycle.severity=info"])
    assert by_name["DAG005"].severity == "info" and by_name["DAG001"].severity != "info"
    by_prefix = apply_overrides(shipped_rules(), ["DAG.severity=info"])
    assert {r.severity for r in by_prefix.values() if r.id.startswith("DAG")} == {"info"}


@pytest.mark.parametrize(
    ("setting", "text"),
    [
        ("STO007", "expected SELECTOR.field=value"),
        ("STO007.severity", "expected SELECTOR.field=value"),
        ("STO999.severity=info", "unknown rule ID"),
        ("STO007.color=red", "unknown field"),
        ("STO007.severity=loud", "not in"),
        ("STO007.enabled=maybe", "true or false"),
        ("STO007.message=bad {bogus}", "bogus"),
        ("STO007.consumer_impact.replay=GREAT", "not in"),
        ("STO007.exempt=a", "no exempt list"),
        ("MET009.enabled=false", "required"),
        ("MET010.severity=info", "required"),
    ],
)
def test_bad_settings_are_rejected(setting, text) -> None:
    with pytest.raises(RuleConfigError, match=text):
        apply_overrides(shipped_rules(), [setting])


def test_settings_file_skips_comments_and_blank_lines(tmp_path) -> None:
    path = tmp_path / "rules.txt"
    path.write_text("# lint policy\n\nSTO007.severity=info\n  DAG005.enabled=false  \n")
    assert read_settings(path) == ["STO007.severity=info", "DAG005.enabled=false"]


def test_missing_settings_file_is_a_config_error(tmp_path) -> None:
    with pytest.raises(RuleConfigError, match="cannot read settings file"):
        read_settings(tmp_path / "none.txt")


def test_command_line_set_wins_over_the_file(tmp_path, capsys) -> None:
    path = tmp_path / "rules.txt"
    path.write_text("STO007.severity=info\n")
    argv = ["--list-rules", "--set-file", str(path), "--set", "STO007.severity=error"]
    assert linter.main(argv) == 0
    line = next(ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("STO007"))
    assert line.split()[2] == "error"


def test_bad_setting_exits_with_usage_error(capsys) -> None:
    assert linter.main(["--list-rules", "--set", "STO007.severity=loud"]) == 2
    assert "error:" in capsys.readouterr().err


def test_severity_and_impact_overrides_reach_the_grade(tmp_path) -> None:
    """A scan grades with the effective rules, not the shipped ones."""
    path = write_trace(tmp_path / "t.et", [node(i) for i in (1, 2, 3)])
    shipped = linter.lint_trace(path)
    rule = next(g.rule for g in shipped.gaps if g.consumer_impact.get("replay") == "NOT SUITABLE")
    rules = apply_overrides(shipped_rules(), [f"{rule}.consumer_impact.replay=LIMITED"])
    softened = linter.lint_trace(path, rules=rules)
    assert next(g for g in softened.gaps if g.rule == rule).consumer_impact["replay"] == "LIMITED"
    muted = linter.lint_trace(path, rules=apply_overrides(shipped_rules(), [f"{rule}.severity=info"]))
    assert rule not in {g.rule for g in muted.gaps}
    assert rule in {n.rule for n in muted.notes}
    assert shipped.status("replay")[0] != consumer.READY
