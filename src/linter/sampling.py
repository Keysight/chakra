"""
Sample-ID helpers shared by the linter and its rule families.

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.
"""

from collections.abc import Iterable

# Node IDs kept per defect so engineers can inspect the trace
SAMPLE_LIMIT = 3


def keep_sample(ids: list[int], node_id: int) -> None:
    """Keep the first two node IDs, then the latest as the last."""
    if len(ids) < SAMPLE_LIMIT:
        ids.append(node_id)
    else:
        ids[-1] = node_id


def add_sample(samples: dict[object, list[int]], key: object, node_id: int) -> None:
    """Keep the first few node IDs that show a defect."""
    ids = samples.setdefault(key, [])
    keep_sample(ids, node_id)


def tally(hits: Iterable[tuple[int, int]]) -> tuple[int, list[int]]:
    """Sum per-node hit counts; keep the first few node IDs with a hit."""
    total, ids = 0, []
    for node_id, count in hits:
        total += count
        if count:
            keep_sample(ids, node_id)
    return total, ids
