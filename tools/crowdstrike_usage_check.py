#!/usr/bin/env python3
"""
Check how the CrowdStrike fetchers *use* the fields, not just that they exist.

Why this exists
---------------
`crowdstrike_schema_check.py` answers "is this a real field name?". That caught
several bugs, but it cannot catch the next one along: a field name that is
perfectly real being used as the wrong *kind* of thing.

The case that motivated this. `FwmgrFirewallRuleV1.monitor` is not a boolean —
gofalcon types it as `FwmgrFirewallMonitoring`, an object of `{count,
period_ms}`, and marks it `Required: true`, so it is present on every rule
whether or not match logging is switched on. The fetcher tested it for
truthiness. A non-empty dict is always true, so `monitored_rules` would have
equalled `total_rules` on any real tenant: a logging control reported as fully
in place purely because a mandatory field exists.

Every existing test passed. The mock omitted `monitor` from three of its four
rules, so fixture and fetcher were written from the same assumption, agreed with
each other, and both disagreed with the API. That is the failure this project
keeps re-learning, and the only cure is a source that is independent of both —
which the committed `crowdstrike_models.json` already is.

What it flags
-------------
A `.get("field")` in a boolean context where `field` is declared as a nested
object. Reading a list for emptiness is legitimate (`if group.get("policy_ids")`
means "attached to something"), so lists are not flagged. Nor is the defaulting
idiom `record.get("host") or {}`, which is presence-handling on the way to a
read rather than a truth test.

Usage
-----
    python tools/crowdstrike_usage_check.py     # exits non-zero on a finding
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Dict, Iterator, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO_ROOT / "fetchers" / "crowdstrike"
MODELS_PATH = Path(__file__).resolve().parent / "crowdstrike_models.json"


def nested_object_fields() -> Dict[str, Set[str]]:
    """Field name -> the declarations that make it a nested object."""
    models = json.loads(MODELS_PATH.read_text())["models"]
    nested: Dict[str, Set[str]] = {}
    for model_name, fields in models.items():
        for field_name, meta in fields.items():
            if not isinstance(meta, dict):
                continue
            if meta.get("model") and not meta.get("is_list"):
                nested.setdefault(field_name, set()).add(
                    f"{model_name}.{field_name} is {meta['model']}"
                )
    return nested


def _boolean_contexts(tree: ast.AST) -> Iterator[ast.expr]:
    """Every expression Python will evaluate for its truthiness."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While, ast.IfExp)):
            yield node.test
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            yield node.operand
        elif isinstance(node, ast.BoolOp):
            yield from node.values
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "bool"
        ):
            yield from node.args
        elif isinstance(node, ast.comprehension):
            yield from node.ifs


def _is_defaulting_idiom(node: ast.AST, parent: ast.AST) -> bool:
    """`record.get("host") or {}` — a fallback on the way to a read."""
    if not (isinstance(parent, ast.BoolOp) and isinstance(parent.op, ast.Or)):
        return False
    if parent.values[0] is not node:
        return False
    return all(
        isinstance(v, (ast.Constant, ast.Dict, ast.List)) for v in parent.values[1:]
    )


def scan(path: Path, nested: Dict[str, Set[str]]) -> List[Tuple[int, str, Set[str]]]:
    tree = ast.parse(path.read_text())

    parents: Dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    findings: Dict[Tuple[int, str], Set[str]] = {}
    for context in _boolean_contexts(tree):
        for node in ast.walk(context):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                continue
            field = node.args[0].value
            if field not in nested:
                continue
            parent = parents.get(node)
            if parent is None or _is_defaulting_idiom(node, parent):
                continue
            # `x.get("f").attr` is a read, not a truth test.
            if isinstance(parent, ast.Attribute):
                continue
            findings.setdefault((node.lineno, field), set()).update(nested[field])

    return [(line, field, decls) for (line, field), decls in sorted(findings.items())]


def main() -> int:
    nested = nested_object_fields()
    findings = 0

    for path in sorted(FETCHER_ROOT.glob("*/fetcher.py")):
        for line, field, decls in scan(path, nested):
            findings += 1
            rel = path.relative_to(REPO_ROOT)
            print(f"{rel}:{line}: .get({field!r}) is tested for truth, but it is an object")
            for decl in sorted(decls):
                print(f"    {decl}")
            print(
                "    A nested object is truthy whenever it is present, so this "
                "counts every record that carries the field."
            )

    if findings:
        print(f"\n{findings} finding(s).")
        return 1
    print("No object-as-boolean usage found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
