"""Shared helpers for the audit extractors.

Everything written by this toolkit goes through write_json / write_csv so that
each artefact lands in a predictable place and gets hashed by manifest.py.
"""

import csv
import json
import os
import sys
import time
from datetime import datetime, timezone


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    sys.stderr.write("[%s] %s\n" % (utcnow_iso(), msg))
    sys.stderr.flush()


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def write_json(out_dir, name, payload):
    ensure_dir(out_dir)
    path = os.path.join(out_dir, name + ".json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True, ensure_ascii=False)
    log("wrote %s (%d records)" % (path, len(payload) if isinstance(payload, list) else 1))
    return path


def flatten(obj, prefix="", out=None):
    """Flatten nested dicts/lists into a single-level dict for CSV output.

    Lists of scalars are joined with '|'. Lists of dicts get indexed keys.
    """
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, "%s.%s" % (prefix, k) if prefix else str(k), out)
    elif isinstance(obj, list):
        if all(not isinstance(i, (dict, list)) for i in obj):
            out[prefix] = "|".join("" if i is None else str(i) for i in obj)
        else:
            for idx, item in enumerate(obj):
                flatten(item, "%s[%d]" % (prefix, idx), out)
    else:
        out[prefix] = obj
    return out


def write_csv(out_dir, name, rows):
    """Write a flattened CSV alongside the raw JSON.

    The JSON is the authoritative export; the CSV exists so the client can open
    it in Excel without losing the fact that it was derived, not collected.
    """
    ensure_dir(out_dir)
    path = os.path.join(out_dir, name + ".csv")
    flat = [flatten(r) for r in rows]
    headers = []
    seen = set()
    for row in flat:
        for k in row:
            if k not in seen:
                seen.add(k)
                headers.append(k)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in flat:
            writer.writerow(row)
    log("wrote %s (%d rows, %d columns)" % (path, len(flat), len(headers)))
    return path


def emit(out_dir, name, rows):
    """Write both representations of one collection."""
    write_json(out_dir, name, rows)
    if isinstance(rows, list) and rows:
        write_csv(out_dir, name, rows)
    return rows


def retry(fn, attempts=5, base_delay=2.0, on_error=None):
    """Retry with exponential backoff.

    Google's Reports API and Meta's Graph API both rate limit aggressively on
    wide date ranges, and a half-finished export is worse than a slow one.
    """
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - we re-raise below
            last = exc
            if on_error and not on_error(exc):
                raise
            delay = base_delay * (2 ** attempt)
            log("attempt %d/%d failed (%s); retrying in %.0fs" % (attempt + 1, attempts, exc, delay))
            time.sleep(delay)
    raise last
