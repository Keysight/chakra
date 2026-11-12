"""
Shipped rule catalog: every family's rules, in report order.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from functools import cache

from . import (
    attribute_rules,  # noqa: F401  (registers its family)
    comm_rules,  # noqa: F401  (registers its family)
    dag_rules,  # noqa: F401  (registers its family)
    kineto_rules,  # noqa: F401  (registers its family)
    metadata_rules,  # noqa: F401  (registers its family)
    replay_rules,  # noqa: F401  (registers its family)
    storage_rules,  # noqa: F401  (registers its family)
)
from .rule_config import Rule, RuleConfigError
from .rule_family import FAMILIES

# Rule ID prefixes in report order; integrity leads
GROUP_ORDER = ("MET", "DAG", "KIN", "COM", "STO", "OPS", "ATT")


@cache
def shipped_rules() -> dict[str, Rule]:
    """Return the rules declared by the families, in report order."""
    rules: dict[str, Rule] = {}
    for family in FAMILIES:
        rules.update(family.rules)
    unlisted = sorted({r[:-3] for r in rules} - set(GROUP_ORDER))
    if unlisted:
        raise RuleConfigError(f"rule prefix missing from GROUP_ORDER: {', '.join(unlisted)}")
    return dict(sorted(rules.items(), key=lambda item: (GROUP_ORDER.index(item[0][:-3]), item[0])))
