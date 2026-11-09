"""The shipped rules.toml meets the criteria stated in its header comments."""

import ast
import json
import string
import tomllib
from pathlib import Path

import jsonschema
import linter
import pytest

RULES_FILE = linter.DEFAULT_RULES
SCHEMA_FILE = RULES_FILE.with_name("rules.schema.json")
EXEMPT_OWNER = "OPS001"


@pytest.fixture(scope="module")
def entries() -> list[dict]:
    """Return the raw [[rule]] tables, bypassing the loader's validation."""
    with RULES_FILE.open("rb") as handle:
        return tomllib.load(handle)["rule"]


def test_file_conforms_to_schema() -> None:
    schema = json.loads(SCHEMA_FILE.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    with RULES_FILE.open("rb") as handle:
        jsonschema.validate(tomllib.load(handle), schema)


def test_id_and_name_are_unique(entries) -> None:
    with RULES_FILE.open("rb") as handle:
        aggregates = tomllib.load(handle)["consumer"]
    for key in ("id", "name"):
        values = [entry[key] for entry in (*entries, *aggregates)]
        assert len(values) == len(set(values)), f"duplicate {key}"


def test_prefix_groups_are_contiguous_and_sequential(entries) -> None:
    """Rules sharing an ID prefix stay adjacent and numbered from 001."""
    seen: dict[str, int] = {}
    previous = None
    for entry in entries:
        prefix, number = entry["id"][:-3], int(entry["id"][-3:])
        if prefix != previous:
            assert prefix not in seen, f"{prefix} group is split"
        assert number == seen.get(prefix, 0) + 1, f"{entry['id']} breaks sequence"
        seen[prefix], previous = number, prefix


def test_exempt_belongs_to_one_rule_only(entries) -> None:
    for entry in entries:
        if "exempt" not in entry:
            continue
        assert entry["id"] == EXEMPT_OWNER


def _master() -> set[str]:
    """Return the placeholder names that the schema declares."""
    schema = json.loads(SCHEMA_FILE.read_text())
    return set(schema["x-placeholders"]) - {"$comment"}


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


def test_schema_describes_every_placeholder() -> None:
    schema = json.loads(SCHEMA_FILE.read_text())
    for name in _master():
        text = schema["x-placeholders"][name]
        assert isinstance(text, str) and text.endswith("."), f"{name}: no description"


def test_schema_placeholders_are_the_source_of_truth(entries) -> None:
    """Code and messages use only schema names; every name is in use."""
    master = _master()
    in_messages = {
        name for entry in entries for _, name, _, _ in string.Formatter().parse(entry["message"]) if name is not None
    }
    used = _used_in_code()
    assert used <= master, "code supplies a placeholder missing from the schema"
    assert in_messages <= master, "rules.toml uses a placeholder missing from the schema"
    assert master <= used, "schema lists a placeholder that no check supplies"


def test_messages_render_with_their_checks_values(entries) -> None:
    """Every shipped message renders once given values for each name."""
    for entry in entries:
        entry["message"].format(**dict.fromkeys(_master(), "0"))
