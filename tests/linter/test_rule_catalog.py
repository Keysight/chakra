"""The shipped rule catalog meets the conventions the decorators cannot express."""

import ast
import string
from pathlib import Path

import pytest
from chakra.src.linter import consumer, linter
from chakra.src.linter.catalog import shipped_rules
from chakra.src.linter.rule_config import PLACEHOLDERS, Rule

EXEMPT_OWNER = "OPS001"


@pytest.fixture(scope="module")
def rules() -> dict[str, Rule]:
    """Return the shipped catalog."""
    return shipped_rules()


def test_name_and_consumer_entries_are_unique(rules) -> None:
    for values in (
        [r.name for r in rules.values()] + [c.name for c in consumer.CONSUMER_INFO.values()],
        [r.id for r in rules.values()] + [c.id for c in consumer.CONSUMER_INFO.values()],
    ):
        assert len(values) == len(set(values)), "duplicate id or name"


def test_prefix_groups_are_contiguous_and_sequential(rules) -> None:
    """Rules sharing an ID prefix stay adjacent and numbered from 001."""
    seen: dict[str, int] = {}
    previous = None
    for rule_id in rules:
        prefix, number = rule_id[:-3], int(rule_id[-3:])
        if prefix != previous:
            assert prefix not in seen, f"{prefix} group is split"
        assert number == seen.get(prefix, 0) + 1, f"{rule_id} breaks sequence"
        seen[prefix], previous = number, prefix


def test_exempt_belongs_to_one_rule_only(rules) -> None:
    assert {r.id for r in rules.values() if r.exempt} == {EXEMPT_OWNER}


def test_required_rules_are_the_fatal_ones(rules) -> None:
    """A fatal rule stops the scan, so it cannot be turned off or re-graded."""
    assert {r.id for r in rules.values() if r.required} == {r.id for r in rules.values() if r.severity == "fatal"}


def _master() -> set[str]:
    """Return the placeholder names that messages may use."""
    return set(PLACEHOLDERS)


def _dict_keys(tree: ast.AST, node: ast.AST) -> set[str]:
    """Return the string keys of a dict literal, or of the dict a name holds."""
    if isinstance(node, ast.Name):
        node = next(
            (
                a.value
                for a in ast.walk(tree)
                if isinstance(a, ast.Assign) and getattr(a.targets[0], "id", None) == node.id
            ),
            ast.Constant(None),
        )
    return {k.value for k in getattr(node, "keys", []) if isinstance(k, ast.Constant)}


def _used_in_code() -> set[str]:
    """Return placeholder names that the linter and its families supply."""
    used: set[str] = set()
    for family in Path(linter.__file__).parent.glob("*_rules.py"):
        tree = ast.parse(family.read_text())
        for node in ast.walk(tree):
            # A family hands its placeholder values to Hit as a dict
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Hit":
                for arg in node.args[2:3]:
                    used |= _dict_keys(tree, arg)
    folder = Path(linter.__file__).parent
    for name in ("linter.py", "reports.py", "messages.py"):
        for node in ast.walk(ast.parse((folder / name).read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) in {"render", "issue"}:
                used |= {kw.arg for kw in node.keywords if kw.arg}
    tree = ast.parse((folder / "messages.py").read_text())
    # `render` fills the version and stream when no finding supplies them
    render = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "render")
    for node in ast.walk(render):
        if isinstance(node, ast.AugAssign) and isinstance(node.value, ast.Dict):
            used |= _dict_keys(tree, node.value)
    return used


def test_every_placeholder_has_a_description() -> None:
    for name, text in PLACEHOLDERS.items():
        assert text.endswith("."), f"{name}: no description"


def test_placeholders_are_the_source_of_truth(rules) -> None:
    """Code and messages use only listed names; every name is in use."""
    master = _master()
    in_messages = {
        name for rule in rules.values() for _, name, _, _ in string.Formatter().parse(rule.message) if name is not None
    }
    used = _used_in_code()
    assert used <= master, "code supplies a placeholder missing from PLACEHOLDERS"
    assert in_messages <= master, "a rule message uses a placeholder missing from PLACEHOLDERS"
    assert master <= used, "PLACEHOLDERS lists a name that no check supplies"


def test_messages_render_with_their_checks_values(rules) -> None:
    """Every shipped message renders once given values for each name."""
    for rule in rules.values():
        rule.message.format(**dict.fromkeys(_master(), "0"))
