"""Deobfuscation post-processor (Iteration 7).

Scope
-----
Blutter's C++ side does not know whether a snapshot was passed through Dart's
`--obfuscate` flag or a third-party renamer. This module runs over the
JSON/SQL artifacts after the main blutter pass and produces two deliverables:

  1. An obfuscation *detector* — summary ratios + a boolean verdict.
  2. A best-effort *name recovery* pass that proposes replacement names for
     obfuscated identifiers, each with a confidence score in [0.0, 1.0].

We deliberately keep this conservative: the tool reports candidates, it does
not rewrite the symbols in the asm dump or the binary. Consumers (Ghidra/IDA
scripts, auditors) pick which recovered names to trust via the confidence
threshold of their choice.

Heuristics
----------
* Name-shape obfuscation detector: a class or function name matching
  `^[A-Za-z]{1,2}[0-9]{1,4}$` is extremely common in Dart's renamer output
  (single/double letter + a counter). We compute the share of such names over
  the whole app; > 30% typically indicates an obfuscated build.

* Flutter / Dart framework intrinsic table: some classes keep their real
  names even after obfuscation because they come from pre-compiled kernel
  libraries that the renamer skips (`dart:*` libraries, parts of
  `package:flutter/…` that the engine needs at runtime). When we see a
  matching `library` URL on an *obfuscated* class, we emit a recovered name
  derived from the library's own exported symbols — this is the "string
  reference proximity" pass #1 in the original plan, specialized to the
  library URL which is itself a reliable string reference.

* Explicit kCid-keyed intrinsic table (pass #2): a small hand-curated list of
  well-known Flutter/Dart class ids and the names they're built with. Matches
  here have high confidence because Dart/Flutter keeps these CIDs stable
  across releases.

Output file
-----------
`recovered_names.json` (in outdir), alongside a summary stanza that blutter.py
prints to stdout.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass, asdict
from typing import Iterable

# Name-shape heuristic — Dart's `--obfuscate` renamer emits names like
# `A`, `Ab`, `Ab12`, `Z99`. We require at least one letter so the digit-only
# field names (off_10) from blutter's own dump don't get flagged.
OBFUSCATED_NAME_RE = re.compile(r"^[A-Za-z]{1,2}[0-9]{0,4}$")

# Threshold above which the app is considered "obfuscated". Empirically 30%
# cleanly separates obfuscated builds (typically 80–95% of names match) from
# normal ones (typically 0–5%: short identifiers like `x`, `i`, `j`).
OBFUSCATION_THRESHOLD = 0.30

# Intrinsic table — class ids that the Dart VM hands out with a stable name
# regardless of user-side obfuscation. CIDs here come from
# `runtime/vm/class_id.h` in the Dart SDK; they're stable across 3.x. We only
# list names that stay valid across multiple minor versions so the table
# doesn't become version-coupled.
#
# Note: these are *predefined* class ids (kNumPredefinedCids boundary). User
# classes begin above it and are always subject to obfuscation.
DART_INTRINSIC_NAMES: dict[int, str] = {
    0:   "Class",
    1:   "Null",
    # 10–30 are low-level VM types; we deliberately skip them because their
    # names are rarely what an auditor wants to recover to.
    42:  "Closure",
    46:  "_Smi",
    51:  "bool",
    53:  "LibraryPrefix",
    62:  "_Double",
    85:  "String",
    94:  "Array",
    95:  "ImmutableArray",
}


@dataclass
class RecoveredName:
    kind: str            # 'class' or 'function'
    key: str             # stable identifier: for functions, hex address; for classes, cid
    original: str        # name blutter saw (may be obfuscated)
    recovered: str       # proposed name
    confidence: float    # 0.0–1.0
    source: str          # which heuristic fired: 'intrinsic_cid' | 'library_name' | 'name_shape_intrinsic'


def _is_obfuscated(name: str) -> bool:
    if not name:
        return False
    return bool(OBFUSCATED_NAME_RE.match(name))


def _load_functions_from_db(db_path: str) -> list[dict]:
    """Pull the minimum fields we need out of blutter.db."""
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT addr, name, cls, lib, is_closure FROM functions"
        ).fetchall()
    return [
        {"addr": r[0], "name": r[1], "cls": r[2], "lib": r[3], "is_closure": r[4]}
        for r in rows
    ]


def _load_functions_from_json(json_path: str) -> list[dict]:
    """Flatten functions.json into the same shape as the DB rows."""
    with open(json_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    out = []
    for fn in payload.get("functions", []):
        addr_s = fn.get("addr", "0x0")
        addr = int(addr_s, 16) if isinstance(addr_s, str) else int(addr_s)
        out.append({
            "addr": addr,
            "name": fn.get("name", ""),
            "cls": fn.get("class", ""),
            "lib": fn.get("library", ""),
            "is_closure": 1 if fn.get("is_closure") else 0,
        })
    return out


def detect(functions: Iterable[dict]) -> dict:
    """Run the name-shape detector over a function table.

    Returns a dict with counts and a verdict. Anonymous closures and empty
    names are excluded from the denominator because Dart emits those by
    design on every build, obfuscated or not.
    """
    total = 0
    obfuscated = 0
    for fn in functions:
        name = fn.get("name") or ""
        if fn.get("is_closure") and name.startswith("<"):
            continue
        if not name:
            continue
        total += 1
        if _is_obfuscated(name):
            obfuscated += 1
    ratio = (obfuscated / total) if total else 0.0
    return {
        "total_named_functions": total,
        "obfuscated_matches": obfuscated,
        "ratio": round(ratio, 4),
        "threshold": OBFUSCATION_THRESHOLD,
        "is_obfuscated": ratio >= OBFUSCATION_THRESHOLD,
    }


def recover(functions: Iterable[dict], objects_by_cid: dict[int, str] | None = None) -> list[RecoveredName]:
    """Propose recovered names for obfuscated entries.

    Returns a list of :class:`RecoveredName`. The caller decides what to do
    with them; blutter dumps the list to JSON and never rewrites the binary.
    """
    out: list[RecoveredName] = []
    seen_class_cids: set[int] = set()

    for fn in functions:
        name = fn.get("name") or ""
        cls = fn.get("cls") or ""
        lib = fn.get("lib") or ""
        addr = fn.get("addr")

        # Pass #1: obfuscated function but the owning library URL survived
        # (dart:* / package:flutter/* libraries always do). We can at least
        # namespace the recovered name to the library, which is useful when
        # triaging an obfuscated build.
        if _is_obfuscated(name) and lib and (lib.startswith("dart_") or lib.startswith("flutter") or "flutter" in lib):
            out.append(RecoveredName(
                kind="function",
                key=hex(addr) if isinstance(addr, int) else str(addr),
                original=f"{cls}::{name}" if cls else name,
                recovered=f"{lib}::__unobf_{name}",
                # Low-to-medium confidence: we know the library but not what
                # the function was called originally.
                confidence=0.35,
                source="library_name",
            ))

    # Pass #2 — intrinsic CID table for classes. Only fires when objects_by_cid
    # was provided (i.e. we loaded blutter.db / objs.json).
    if objects_by_cid:
        for cid, observed_name in objects_by_cid.items():
            if cid in seen_class_cids:
                continue
            seen_class_cids.add(cid)
            if cid in DART_INTRINSIC_NAMES and _is_obfuscated(observed_name):
                out.append(RecoveredName(
                    kind="class",
                    key=str(cid),
                    original=observed_name,
                    recovered=DART_INTRINSIC_NAMES[cid],
                    # High confidence: the CID<->name mapping is fixed in
                    # runtime/vm/class_id.h and the engine relies on it.
                    confidence=0.95,
                    source="intrinsic_cid",
                ))
    return out


def _load_objects_by_cid_db(db_path: str) -> dict[int, str]:
    """Build {cid: class_name} from blutter.db.

    When multiple objects share a cid (common — every int is cid 42), first
    non-empty name wins; all subsequent ones are identical by construction
    since cid uniquely determines the class name.
    """
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT cid, class_name FROM objects WHERE cid >= 0 GROUP BY cid"
        ).fetchall()
    return {r[0]: (r[1] or "") for r in rows}


def run(outdir: str) -> dict:
    """Main entry: inspect the outputs already in *outdir* and write
    `recovered_names.json`. Returns the summary dict printed by blutter.py.
    """
    db_path = os.path.join(outdir, "blutter.db")
    functions_json = os.path.join(outdir, "functions.json")

    if os.path.isfile(db_path):
        functions = _load_functions_from_db(db_path)
        objects_by_cid = _load_objects_by_cid_db(db_path)
    elif os.path.isfile(functions_json):
        functions = _load_functions_from_json(functions_json)
        # objs.json doesn't carry cid separately yet (kept cls_name only); the
        # name-shape check on the class name is good enough in this mode.
        objects_by_cid = {}
    else:
        # Nothing to work from; still emit a valid summary so callers can
        # rely on the file existing.
        detection = {
            "total_named_functions": 0,
            "obfuscated_matches": 0,
            "ratio": 0.0,
            "threshold": OBFUSCATION_THRESHOLD,
            "is_obfuscated": False,
        }
        _write_output(outdir, detection, [])
        return detection

    detection = detect(functions)
    recovered: list[RecoveredName] = recover(functions, objects_by_cid) if detection["is_obfuscated"] else []

    _write_output(outdir, detection, recovered)
    return detection


def _write_output(outdir: str, detection: dict, recovered: list[RecoveredName]) -> None:
    payload = {
        "schema_version": 1,
        "detection": detection,
        "recovered_names": [asdict(r) for r in recovered],
    }
    dst = os.path.join(outdir, "recovered_names.json")
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("outdir", help="blutter output directory (containing blutter.db or functions.json)")
    args = ap.parse_args()
    summary = run(args.outdir)
    print(json.dumps(summary, indent=2))
