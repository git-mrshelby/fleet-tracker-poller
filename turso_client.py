"""
Turso (libSQL) HTTP client — thin wrapper over the /v2/pipeline API.
No native deps: works on GitHub Actions ubuntu-latest with plain requests.
"""

import os
import uuid
import requests

TURSO_DATABASE_URL = (os.environ.get("TURSO_DATABASE_URL") or "").rstrip("/")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN") or ""

_last_replication_index = None


def configured():
    return bool(TURSO_DATABASE_URL and TURSO_AUTH_TOKEN)


def _val(v):
    if v is None:
        return None
    if v.get("type") == "null":
        return None
    return v.get("value")


def _arg(a):
    if a is None:
        return {"type": "null", "value": None}
    if isinstance(a, bool):
        return {"type": "integer", "value": 1 if a else 0}
    if isinstance(a, int):
        return {"type": "integer", "value": a}
    if isinstance(a, float):
        return {"type": "float", "value": a}
    return {"type": "text", "value": str(a)}


def execute(statements):
    """Run a batch of (sql, args) tuples in one HTTP round-trip.

    Returns a list of row-lists, one per statement. Each row is a list of
    plain Python values (text/integer/float mapped; null -> None).
    """
    if not configured():
        raise RuntimeError("TURSO_DATABASE_URL / TURSO_AUTH_TOKEN not set")
    reqs = [
        {"type": "execute", "stmt": {"sql": sql, "args": [_arg(a) for a in args]}}
        for (sql, args) in statements
    ]
    reqs.append({"type": "close"})
    resp = requests.post(
        f"{TURSO_DATABASE_URL}/v2/pipeline",
        json={"requests": reqs},
        headers={"Authorization": f"Bearer {TURSO_AUTH_TOKEN}"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    results = data.get("results", [])
    out = []
    for res in results:
        rtype = res.get("type")
        response = res.get("response", {})
        if rtype == "error" or response.get("type") == "error":
            err = response.get("error", res)
            raise RuntimeError(f"Turso error: {err}")
        if rtype == "ok" and response.get("type") == "close":
            continue
        result = response.get("result", {})
        rows = [[_val(v) for v in row] for row in result.get("rows", [])]
        out.append(rows)
    return out


def query(sql, args=()):
    """Run one SELECT and return rows as lists of values."""
    return execute([(sql, list(args))])[0]


def query_one(sql, args=()):
    rows = query(sql, args)
    return rows[0] if rows else None


def run(sql, args=()):
    """Run one write statement; returns (rows_affected, last_insert_rowid)."""
    if not configured():
        raise RuntimeError("TURSO_DATABASE_URL / TURSO_AUTH_TOKEN not set")
    reqs = [
        {"type": "execute", "stmt": {"sql": sql, "args": [_arg(a) for a in args]}},
        {"type": "close"},
    ]
    resp = requests.post(
        f"{TURSO_DATABASE_URL}/v2/pipeline",
        json={"requests": reqs},
        headers={"Authorization": f"Bearer {TURSO_AUTH_TOKEN}"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    for res in data.get("results", []):
        response = res.get("response", {})
        if res.get("type") == "error" or response.get("type") == "error":
            raise RuntimeError(f"Turso error: {response.get('error', res)}")
        result = response.get("result")
        if result is not None:
            return result.get("affected_row_count", 0)
    return 0


def new_id():
    return str(uuid.uuid4())
