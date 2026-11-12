"""The shipped rule catalog matches the code and the CLI."""

import ast
from pathlib import Path

import pytest
from chakra.src.linter import catalog, linter, messages, reports, rule_config

ROOT = Path(__file__).resolve().parents[2] / "src" / "linter"


@pytest.fixture(scope="module")
def shipped_rules() -> dict[str, linter.Rule]:
    return catalog.shipped_rules()


def test_rule_catalog_matches_code(shipped_rules) -> None:
    """Every rule ID that code names literally is in the catalog."""
    tree = ast.parse(Path(linter.__file__).read_text())
    named = {
        arg.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "render"
        for arg in node.args[1:2]
        if isinstance(arg, ast.Constant)
    }
    assert named <= set(shipped_rules)


def test_list_rules_shows_state(shipped_rules, capsys) -> None:
    argv = ["--list-rules", "--disable-rule", "DAG005"]
    assert linter.main(argv) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == len(shipped_rules) + 1
    states = {ln.split()[0]: ln.split()[3] for ln in lines[:-1]}
    assert states["DAG005"] == "disabled"
    assert states["MET009"] == "enabled"
    assert lines[-1] == f"{len(shipped_rules)} rules, 1 disabled"


def test_list_rules_shows_effective_settings_and_marks_overrides(capsys) -> None:
    argv = ["--list-rules", "--set", "STO007.severity=info", "--set", "DAG005.enabled=false"]
    assert linter.main(argv) == 0
    lines = {ln.split()[0]: ln for ln in capsys.readouterr().out.splitlines()}
    assert lines["STO007"].split()[2] == "info" and lines["STO007"].endswith("(set: severity)")
    assert lines["DAG005"].split()[3] == "disabled" and lines["DAG005"].endswith("(set: enabled)")
    assert "(set:" not in lines["STO006"]


def test_paths_required_without_list_rules() -> None:
    with pytest.raises(SystemExit) as exc:
        linter.main([])
    assert exc.value.code == 2


def test_report_links_every_rule_to_a_description(shipped_rules) -> None:
    """Rule IDs in both report formats link to a heading in the Rules list."""
    trace = ROOT / "missing.et"
    result = linter.TraceResult()
    result.problems = ["cannot decode"]
    result.fatal_rule = "MET009"
    for as_html in (False, True):
        text = reports.render_report([(trace, result)], shipped_rules, as_html=as_html)
        assert "#### MET009" in text
        assert "#### SUI001" in text
        assert "(#MET009)" in text or 'href="#MET009"' in text


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
    """Each rule of the catalog belongs to one family."""
    from chakra.src.linter import rule_family

    owned = {rule for family in rule_family.FAMILIES for rule in family.checks}
    assert owned == set(shipped_rules)


def test_every_rules_module_registers_a_family() -> None:
    """A *_rules.py module that registers nothing never runs in a scan."""
    from chakra.src.linter import rule_family

    modules = {f.__module__.rpartition(".")[2] for f in rule_family.FAMILIES}
    files = {p.stem for p in Path(linter.__file__).parent.glob("*_rules.py")}
    assert files == modules


def test_family_orders_are_unique_and_integrity_leads() -> None:
    """Report order is explicit: no ties, metadata and integrity first."""
    from chakra.src.linter import rule_family

    orders = [f.order for f in rule_family.FAMILIES]
    assert len(orders) == len(set(orders))
    assert min(rule_family.FAMILIES, key=lambda f: f.order).__name__ == "MetadataRules"
