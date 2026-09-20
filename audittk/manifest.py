"""Hash every exported file so the archive can be proved unaltered later.

This is what makes the export an "immutable history" in any practical sense:
the files themselves can obviously be edited, but a manifest hashed and
timestamped at collection time means any later edit is detectable. Keep a
copy of MANIFEST.sha256 somewhere separate from the archive.

Usage:
    python -m audittk.manifest --dir out                 # write manifest
    python -m audittk.manifest --dir out --verify        # re-check it
"""

import argparse
import hashlib
import json
import os
import sys

from .common import log, utcnow_iso

MANIFEST_NAME = "MANIFEST.sha256"
MANIFEST_JSON = "MANIFEST.json"


def sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def walk(root):
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if fn in (MANIFEST_NAME, MANIFEST_JSON):
                continue
            full = os.path.join(dirpath, fn)
            yield os.path.relpath(full, root).replace(os.sep, "/"), full


def build(root):
    entries = []
    for rel, full in sorted(walk(root)):
        entries.append({
            "path": rel,
            "sha256": sha256_file(full),
            "bytes": os.path.getsize(full),
        })
    return entries


def write_manifest(root):
    entries = build(root)
    text_path = os.path.join(root, MANIFEST_NAME)
    with open(text_path, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write("%s  %s\n" % (e["sha256"], e["path"]))
    # A hash of the manifest itself: one value to write down or email to
    # yourself. If that single value still matches, nothing in the archive
    # has moved.
    root_hash = hashlib.sha256(
        "".join("%s  %s\n" % (e["sha256"], e["path"]) for e in entries).encode("utf-8")
    ).hexdigest()
    with open(os.path.join(root, MANIFEST_JSON), "w", encoding="utf-8") as fh:
        json.dump({
            "generated_at": utcnow_iso(),
            "file_count": len(entries),
            "total_bytes": sum(e["bytes"] for e in entries),
            "manifest_sha256": root_hash,
            "algorithm": "sha256",
            "files": entries,
        }, fh, indent=2)
    log("manifest: %d files, root hash %s" % (len(entries), root_hash))
    print(root_hash)
    return root_hash


def verify(root):
    path = os.path.join(root, MANIFEST_JSON)
    if not os.path.exists(path):
        log("no %s in %s" % (MANIFEST_JSON, root))
        return 2
    with open(path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    recorded = {e["path"]: e["sha256"] for e in manifest["files"]}
    current = {rel: sha256_file(full) for rel, full in walk(root)}

    changed = [p for p in recorded if p in current and recorded[p] != current[p]]
    missing = [p for p in recorded if p not in current]
    added = [p for p in current if p not in recorded]

    for p in changed:
        log("CHANGED  %s" % p)
    for p in missing:
        log("MISSING  %s" % p)
    for p in added:
        log("ADDED    %s" % p)
    if not (changed or missing or added):
        log("OK: %d files match the manifest generated at %s"
            % (len(recorded), manifest["generated_at"]))
        return 0
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="Hash or verify an export archive")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args(argv)
    if args.verify:
        return verify(args.dir)
    write_manifest(args.dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
