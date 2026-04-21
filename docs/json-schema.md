# Blutter JSON export schema

`blutter --json` (or `python3 blutter.py ... --json`) emits two files
alongside the usual `pp.txt` / `objs.txt`:

- `pp.json` — one entry per Dart object-pool slot
- `objs.json` — one entry per Dart object that blutter expanded

Both files carry a top-level `"schema_version"` field so downstream tooling
can refuse mismatched versions without brittle string sniffing.

---

## Current schema

`schema_version: 1`

### pp.json

```jsonc
{
  "schema_version": 1,
  "pool_heap_offset": "0x...",        // pool ObjectPtr relative to heap_base
  "entries": [
    {
      "index": 0,                      // pool index
      "offset": 17,                    // offset in compiled code (OffsetFromIndex(i) + 1)
      "description": "[pp+0x11] Null"  // stable human-readable line, same as pp.txt
    },
    ...
  ]
}
```

Notes:
- `pool_heap_offset` is a hex string so consumers don't have to worry about
  64-bit integer overflow in JSON parsers that top out at 2^53.
- `UnlinkedCall` entries occupy two pool slots; only the first slot is
  emitted (mirrors `pp.txt`).

### objs.json

```jsonc
{
  "schema_version": 1,
  "objects": [
    {
      "ptr": "0x...",          // raw ObjectPtr (tagged) as hex string
      "class": "package:foo/bar.Baz",  // full Dart class name if resolvable, "" otherwise
      "description": "..."     // full dump, same text as objs.txt for this object
    },
    ...
  ]
}
```

---

## Compatibility guarantees

Within a given `schema_version`:
- Existing fields will never be removed or change type.
- New fields may be **added** without bumping the version. Consumers must
  ignore unknown fields.

Breaking changes (removals, semantic shifts) bump `schema_version`.

---

## Future directions (schema v2 candidates)

Not in v1 — tracked for later iterations:

- **Structured object fields**: break `objects[].description` into typed
  field entries (`name`, `cid`, `value`) instead of a pre-formatted string.
- **Type metadata**: once Iteration 6 (type inference) lands, include
  function signatures and resolved return types.
- **Cross-references**: pool index → object ptr, object ptr → asm address.
