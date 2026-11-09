"""BL-15: the shipped rule file matches the code and the CLI."""

import ast
from pathlib import Path

import linter
import messages
import pytest
import reports
import rule_config

ROOT = Path(__file__).resolve().parents[2] / "src" / "linter"


@pytest.fixture(scope="module")
def shipped_rules() -> dict[str, linter.Rule]:
    return linter.load_rules(linter.DEFAULT_RULES)


def test_rule_file_matches_code(shipped_rules) -> None:
    """Every rule ID that code names literally has a rule entry."""
    tree = ast.parse(Path(linter.__file__).read_text())
    named = {
        arg.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "render"
        for arg in node.args[1:2]
        if isinstance(arg, ast.Constant)
    }
    assert named <= set(shipped_rules)


def test_every_rule_has_a_check(shipped_rules) -> None:
    """Every rule ID in the file appears as a string constant in the code."""
    literals = {
        n.value
        for source in [Path(linter.__file__), *ROOT.glob("*_rules.py")]
        for n in ast.walk(ast.parse(source.read_text()))
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    }
    missing = sorted(set(shipped_rules) - literals)
    assert not missing, f"rules without a check: {missing}"


def test_list_rules_shows_state(shipped_rules, capsys) -> None:
    argv = ["--list-rules", "--disable-rule", "DAG005"]
    assert linter.main(argv) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == len(shipped_rules) + 1
    states = {ln.split()[0]: ln.split()[-1] for ln in lines[:-1]}
    assert states["DAG005"] == "disabled"
    assert states["INT001"] == "enabled"
    assert lines[-1] == f"{len(shipped_rules)} rules, 1 disabled"


def test_paths_required_without_list_rules() -> None:
    with pytest.raises(SystemExit) as exc:
        linter.main([])
    assert exc.value.code == 2


def test_report_links_every_rule_to_a_description(shipped_rules) -> None:
    """Rule IDs in both report formats link to a heading in the Rules list."""
    trace = ROOT / "missing.et"
    result = linter.TraceResult()
    result.readable = False
    result.problems = ["cannot decode"]
    result.fatal_rule = "INT001"
    for as_html in (False, True):
        text = reports.render_report([(trace, result)], shipped_rules, as_html=as_html)
        assert "#### INT001" in text
        assert "#### SUI001" in text
        assert "(#INT001)" in text or 'href="#INT001"' in text


def test_selectors_accept_name_and_prefix(shipped_rules) -> None:
    by_name = linter.disabled_rules(shipped_rules, disable=["dag-cycle"])
    assert by_name == {"DAG005"}
    by_prefix = linter.disabled_rules(shipped_rules, disable=["DAG"])
    assert by_prefix == {f"DAG00{i}" for i in range(1, 6)}


def test_rule_ids_and_names_are_unique(shipped_rules) -> None:
    names = [rule.name for rule in shipped_rules.values()]
    assert len(names) == len(set(names))


def test_any_schema_placeholder_renders_in_any_message() -> None:
    """Placeholders a check omits take trace-wide values, else `n/a`."""
    template = " ".join(f"{{{name}}}" for name in sorted(rule_config.master_placeholders()))
    text = messages.render({"DAG001": template}, "DAG001", count=2)
    assert "n/a" in text and "{" not in text


def test_unknown_placeholder_is_a_config_error() -> None:
    with pytest.raises(linter.RuleConfigError, match=r"rule DAG001.*\{bogus\}"):
        messages.render({"DAG001": "bad {bogus}"}, "DAG001", count=2)


def test_every_rule_has_an_owner(shipped_rules) -> None:
    """Each rule of the file belongs to one family."""
    import rule_family

    owned = {rule for family in rule_family.FAMILIES for rule in family.checks}
    assert owned == set(shipped_rules)
