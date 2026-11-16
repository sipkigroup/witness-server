"""Witness catalog 0.1 (r0313, KONSTITUCIYA-KATALOG-1411 s4 / s6 step 1): the descriptive, machine-readable list of action classes.

Step 1 only: the judge (hookjudge, constitution) does NOT read this file yet; tests check that the catalog and the code agree.
JSON (not YAML): no YAML library is in the deployment requirements and none is added. Schema validation is a small built-in validator
for the keyword subset the schema uses (no new dependency); tests cross-check with `jsonschema` when it is installed."""
from __future__ import annotations

import json
import re
from pathlib import Path

_DIR = Path(__file__).resolve().parent
CATALOG_FILE = _DIR / "witness-catalog-0.1.json"
SCHEMA_FILE = _DIR / "catalog-0.1.schema.json"
_cache: dict = {}


def load_schema() -> dict:
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


def load(path=None) -> dict:
    if path is not None:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    if "c" not in _cache:
        _cache["c"] = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
    return _cache["c"]


def _ty(v, t):
    return {"object": isinstance(v, dict), "array": isinstance(v, list), "string": isinstance(v, str),
            "integer": isinstance(v, int) and not isinstance(v, bool)}.get(t, False)


def _walk(v, s, root, at, errs):
    if "$ref" in s:
        node = root
        for part in s["$ref"].lstrip("#/").split("/"):
            node = node[part]
        return _walk(v, node, root, at, errs)
    if "const" in s and v != s["const"]:
        errs.append("%s: must be %r" % (at, s["const"]))
    if "enum" in s and v not in s["enum"]:
        errs.append("%s: %r not in %s" % (at, v, s["enum"]))
    if "type" in s and not _ty(v, s["type"]):
        errs.append("%s: expected %s" % (at, s["type"]))
        return
    if isinstance(v, str):
        if len(v) < s.get("minLength", 0):
            errs.append("%s: too short" % at)
        if "pattern" in s and not re.search(s["pattern"], v):
            errs.append("%s: %r does not match %s" % (at, v, s["pattern"]))
    if isinstance(v, int) and not isinstance(v, bool) and v < s.get("minimum", v):
        errs.append("%s: below minimum" % at)
    if isinstance(v, list):
        if len(v) < s.get("minItems", 0):
            errs.append("%s: too few items" % at)
        if "items" in s:
            for i, x in enumerate(v):
                _walk(x, s["items"], root, "%s[%d]" % (at, i), errs)
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append("%s: missing %s" % (at, k))
        props = s.get("properties", {})
        if s.get("additionalProperties") is False:
            for k in v:
                if k not in props:
                    errs.append("%s: unknown field %s" % (at, k))
        for k, sub in props.items():
            if k in v:
                _walk(v[k], sub, root, "%s.%s" % (at, k), errs)


def validate(catalog=None, schema=None) -> list:
    """-> list of error strings (empty = valid)."""
    c = load() if catalog is None else catalog
    s = load_schema() if schema is None else schema
    errs: list = []
    _walk(c, s, s, "$", errs)
    return errs


def classes() -> list:
    return load()["classes"]


def by_id(i):
    return next((e for e in classes() if e["id"] == i), None)


def by_mark(mark):
    """The class that owns a classifier mark (bashparse danger category), or None."""
    return next((e for e in classes() if mark in e.get("marks", [])), None)


def by_code(code):
    """The class that owns a constitution code (FORBIDDEN_*), or None."""
    return next((e for e in classes() if code in e.get("codes", [])), None)


def n_articles() -> tuple:
    """Codes of the N-articles built from the catalog (default verdict N, a code, an article number), in article order.
    Step 1: only compared with constitution.CODES; the judge does not use it yet."""
    rows = sorted((e["article"], c) for e in classes() if e["verdict"]["default"] == "N" and e.get("article") for c in e.get("codes", []))
    return tuple(c for _, c in rows)
