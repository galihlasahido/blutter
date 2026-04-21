# Blutter improvement plan

Living document. Legend: `[ ]` not started · `[~]` in progress · `[x]` done.

Scope: harden existing code, then layer in missing platform/analyzer features.
Order reflects the recommendation in the design discussion: sustainability (tests + CI) first, then iOS/Mach-O, then JSON export, then heavier C++ work.

---

## Iteration 1 — Test & CI scaffolding

**Goal:** every bug fixed so far is regression-protected, and future Dart releases that break `find_compat_macro` or friends fail CI instead of silently producing wrong output.

### 1.1 Test infrastructure
- [x] Decide config format (`pyproject.toml` with `[tool.pytest.ini_options]`)
- [x] Add `pytest.ini`/`pyproject.toml`
- [x] Create `tests/` package (`__init__.py`, `conftest.py`)
- [x] Ensure tests importable without installing the repo (path manipulation in `conftest.py`)
- [x] Update `.gitignore` to cover `.pytest_cache`, `__pycache__`, `*.egg-info`

### 1.2 Refactor for testability
- [x] Extract `version_tuple()` helper into `dartvm_fetch_build.py`
- [x] Replace inline version parsing in `blutter.py` with the helper (Dart < 2.15 check)
- [x] Replace inline version parsing in `dartvm_fetch_build.py` with the helper (Dart ≥ 3.8 check)

### 1.3 Unit tests — `version_tuple`
- [x] Parses simple `major.minor.patch`
- [x] Parses `major.minor` (2 components)
- [x] Parses pre-release tags (`3.8.0-226.0.dev`)
- [x] Ordering: `3.11 > 3.8 > 3.7.9`
- [x] Regression: `4.0.0 >= (3, 8)` returns True (was a real bug)
- [x] Regression: `2.14.0 < (2, 15)` and `2.15.0 >= (2, 15)`

### 1.4 Unit tests — `DartLibInfo`
- [x] Android default → `has_compressed_ptrs=True`
- [x] iOS default → `has_compressed_ptrs=False`
- [x] Explicit override respected
- [x] `lib_name` format `dartvm{ver}_{os}_{arch}`
- [x] Snapshot hash optional, defaults to None

### 1.5 Unit tests — `BlutterInput`
- [x] Default `name_suffix` empty for android/arm64 + analysis
- [x] `_no-compressed-ptrs` suffix added when flag false
- [x] `_no-analysis` suffix added when requested
- [x] Both suffixes stacked in correct order
- [x] Dart < 2.15 forces no-analysis
- [x] Dart 2.15 does not force no-analysis
- [x] Dart 3.x does not force no-analysis
- [x] `blutter_file` path ends with `.exe` on Windows (`os.name == 'nt'`)
- [x] `blutter_file` path has no extension on POSIX

### 1.6 Unit tests — `find_compat_macro`
Each test sets up a `tmp_path/dartvm{ver}/vm/` with crafted headers and monkey-patches `PKG_INC_DIR`.
- [x] Fixture helper that writes all 5 required headers with defaults (post-commit state)
- [x] `OLD_MAP_SET_NAME` detected when `V(LinkedHashMap)` present
- [x] `OLD_MAP_NO_IMMUTABLE` stacked when ImmutableLinkedHashMap absent
- [x] `NO_LAST_INTERNAL_ONLY_CID` when marker missing
- [x] `HAS_TYPE_REF` when `V(TypeRef)` present
- [x] `HAS_RECORD_TYPE` only on Dart 3.x with `V(RecordType)`
- [x] `HAS_RECORD_TYPE` NOT emitted on Dart 2.x even when marker present
- [x] `HAS_SHARED_CLASS_TABLE` detected
- [x] `NO_INIT_LATE_STATIC_FIELD` when stub missing
- [x] `NO_METHOD_EXTRACTOR_STUB` when store entry missing
- [x] `UNIFORM_INTEGER_ACCESS` when old accessor missing
- [x] `NO_CODE_ANALYSIS` when `no_analysis=True`
- [x] All absent → empty macro list

### 1.7 Unit tests — `extract_dart_info`
- [x] Fixture builder for minimal valid ELF with one symbol + rodata payload
- [x] `extract_snapshot_hash_flags` returns hash + flags from crafted ELF
- [x] **Regression**: snapshot hash read works even when `st_value ≠ file_offset` (section translation)
- [x] `extract_libflutter_info` returns `arch='arm64'` for `EM_AARCH64`
- [x] `extract_libflutter_info` returns `arch='x64'` for `EM_X86_64` (regression for IA_64 bug)
- [x] Unsupported architecture raises `AssertionError`

### 1.8 CI pipeline
- [x] `.github/workflows/ci.yml`
- [x] Matrix: Ubuntu, Python 3.10/3.11/3.12
- [x] Install minimal deps (`pyelftools`, `requests`, `pytest`)
- [x] Run `pytest -v`
- [x] Fail fast configuration (via `fail-fast: false` + `concurrency` cancel)
- [x] Cache pip to keep runs quick

### 1.9 Verification
- [x] `pytest` runs green locally (58/58 passed)
- [x] No import errors, no warnings other than deprecation whitelist
- [x] `python3 -m compileall -q` all modified sources

---

## Iteration 2 — iOS / Mach-O detection (Python side)

**Goal:** user can point `blutter.py` at an `.ipa` or an iOS `Payload/*.app/` and get a correct `Dart version / flags / target` readout. C++ analyzer still refuses iOS snapshot in this iteration; that is iteration 4.

### 2.1 Input handling
- [x] `blutter.py` accepts `*.ipa` with same code path as `.apk`
- [x] Inside `.ipa`, locate `Payload/*.app/Frameworks/App.framework/App` and `Frameworks/Flutter.framework/Flutter`
- [x] `find_lib_files` handles Mach-O naming when directory passed (already supported `App`/`Flutter` names)
- [x] iOS target short-circuits `main2()` with a clear message (C++ loader not ready)

### 2.2 Mach-O parser (`macho_info.py` + `extract_dart_info.py`)
- [x] Detect file type by magic (`CF FA ED FE` thin, `CA FE BA BE` fat)
- [x] For fat binaries, walk FAT arches and pick arm64 slice (fall back to first slice)
- [x] Parse `LC_SEGMENT_64`, build section/offset map
- [x] Parse `LC_SYMTAB` to find `__kDartVmSnapshotData` (Mach-O adds leading `_`)
- [x] Translate symbol VM address → container-absolute file offset (fat-safe)
- [x] Mach-O snapshot-hash + flags extraction reuses ELF layout logic
- [x] `extract_libflutter_info` Mach-O variant: scan `__TEXT,__const` and `__TEXT,__cstring`
- [x] Top-level `extract_snapshot_hash_flags` / `extract_libflutter_info` dispatch on magic

### 2.3 Unit tests
- [x] Fixture builder for minimal Mach-O binary (`tests/macho_fixture.py`)
- [x] Thin Mach-O symbol extraction (`tests/test_macho_info.py`)
- [x] Fat Mach-O arch selection + container-absolute vm translation
- [x] Mach-O snapshot hash + flags integration (`tests/test_extract_dart_info_macho.py`)
- [x] Mach-O libflutter scan (both `__const` and `__cstring`, thin + fat)
- [x] `.ipa` extraction smoke test against fake zip (`tests/test_ipa_extraction.py`)

### 2.4 User docs
- [x] README section for iOS detection (explicitly note C++ loader not ready)

---

## Iteration 3 — JSON export of object pool / objects

**Goal:** downstream tooling (Ghidra scripts, custom analyzers) can consume Blutter output without parsing `pp.txt`.

### 3.1 C++ implementation
- [x] `DartDumper::DumpObjectPoolJson(const char* path)`
- [x] `DartDumper::DumpObjectsJson(const char* path)`
- [x] Hand-rolled JSON writer (no new dep); escapes all control chars + quotes
- [x] `--json` CLI flag in `main.cpp` (`args.hxx`)
- [x] `blutter.py --json` forwards the flag to the C++ binary
- [x] When `--json` set, emit `pp.json` and `objs.json` alongside text versions

### 3.2 Schema doc
- [x] `docs/json-schema.md` describing object, field, type layout
- [x] Version the schema (`"schema_version": 1`)
- [x] Document forward-compat guarantees within a schema version

### 3.3 Tests / smoke
- [ ] Golden-file snapshot test against a committed tiny libapp fixture
  > Requires building the blutter C++ binary against a specific Dart version
  > and running it against a committed tiny snapshot. Deferred — needs a
  > build/CI environment with the Dart VM toolchain. The JSON code is covered
  > by compile-time checks + manual testing until then.

---

## Iteration 4 — C++ Mach-O loader (real iOS support)

**Goal:** `blutter` binary loads an iOS `App` Mach-O snapshot end-to-end.

### 4.1 Parser skeleton (landed)
- [x] `MachOHelper.{h,cpp}` mirroring `ElfHelper` shape
- [x] Parses thin Mach-O 64-bit + FAT containers, picks arm64 slice
- [x] Walks `LC_SEGMENT_64` + `LC_SYMTAB` and resolves the four Dart symbols
- [x] Memory-maps the file on POSIX + Windows
- [x] Added to `sourcelist.cmake` so CI catches compile breakage

### 4.1.1 Bugs caught during real-binary validation (fixed)
- [x] Missing `<vector>` / `<iterator>` explicit includes — the source was
      silently relying on `pch.h` to pull them in. Now included directly so
      the file compiles outside the project PCH context too.
- [x] Symbol-name mangling: the original skeleton only searched for the
      double-underscore form (`__kDartVmSnapshotData`). Real Mach-O binaries
      (Flutter 3.41.6 / Dart 3.11.4 iOS AOT) store these symbols with a
      single leading underscore. Now tries both forms, matching the Python
      `macho_info.find_symbol` fallback.

### 4.2 Wiring (landed — end-to-end on real iOS binary)
- [x] `DartApp` constructor sniffs magic bytes and routes to `MachOHelper`
      or `ElfHelper`. Ripped out the never-implemented Mach-O fallback
      inside `ElfHelper.cpp` (was returning `size >= sizeof(...)` from a
      function returning `LibAppInfo`).
- [x] `DartApp::base()` / `heap_base()` unchanged — the existing semantics
      (`lib_base = libInfo.lib`, `heap_base_` from the Dart VM isolate)
      are correct for Mach-O. For a FAT container we set `lib` to the
      picked thin-slice base, which matches how IDA/Ghidra display offsets.
- [x] `os_name='ios'` plumbed through CMake. Fixed the Dart SDK template
      which only defined `DART_TARGET_OS_MACOS_IOS` — the SDK requires
      both `DART_TARGET_OS_MACOS` and `DART_TARGET_OS_MACOS_IOS` so the
      nested `#if defined(DART_TARGET_OS_MACOS) / MACOS_IOS` checks in
      `runtime/vm/dart.cc` etc. match.
- [x] Uncompressed-pointer build now compiles. `CSREG_DART_HEAP` was
      guarded behind `#ifdef DART_COMPRESSED_POINTERS` even though
      `HEAP_BITS` (R28) is always a valid register (used for the write
      barrier mask in both modes). Removed the guard and turned
      `handleDecompressPointer` / `handleExtraDecompressPointer` into
      no-ops under uncompressed pointers (the Dart compiler doesn't emit
      the `ADD ..., Xreg, HEAP_BITS, LSR #32` pattern in that mode).
- [x] Removed iOS short-circuit in `main2()` — it now flows straight into
      `build_and_run()`.
- [ ] arm64e pointer-authentication: still not wired. The test binary is
      plain arm64 (`cputype=ARM64 subtype=ALL`), so PAC stripping isn't on
      the critical path. Deferred to a future iteration when we hit an
      arm64e target that actually exercises it.

### 4.2.1 Uncompressed-pointer code-pattern fixes (landed)
End-to-end run on the iOS test binary surfaced 143 `Analysis error`
messages in `CodeAnalyzer_arm64.cpp`. Each had the shape of a pattern that
had only been written against compressed-pointer code. Fixed:
- [x] Smi-to-stack-slot scale: compressed emits `add Xd, Xfp, Wn, sxtw #2`
      because the Smi lives in a W-register; uncompressed emits
      `add Xd, Xfp, Xn, lsl #2`. Introduced `INSN_SMI_STACK_SCALE` /
      `INSN_SMI_PAIR_SCALE` helper macros so the assertions accept both
      forms. Callers at lines 898, 970, 1315, 1559 (parameter stack loads)
      and 1112 (ArgsDesc named-entry indexing) now match both modes.
- [x] ArgsDesc named-entry LDUR displacement: the disp is
      `sizeof(void*)*2 - kHeapObjectTag` in compressed mode but
      `sizeof(void*)*3 - kHeapObjectTag` in uncompressed mode (the `lsl #2`
      scaling already absorbs the slot-size doubling, but the uncompressed
      ArgsDesc layout shifts the field one extra 8-byte unit forward).
      Made the constant conditional.
- [x] Smi→int untagging: compressed uses `sbfx Xd, Xn, #1, #0x1f` (32-bit
      Smi → sign-extended 64-bit), uncompressed uses `asr Xd, Xn, #1`
      (64-bit Smi → 64-bit int). Added parallel ASR branches alongside the
      existing SBFX branches in `handleOptionalNamedParameters`.

- [x] OneByteString/TwoByteString char access: the `processLoadStore`
      assertion at line 3352 only accepted TypedData payload offset or
      Array data offset. Extended it to also accept
      `OneByteString::data_offset - kHeapObjectTag` and
      `TwoByteString::data_offset - kHeapObjectTag`. Surfaced on
      uncompressed mode because `OneByteString::data_offset` is 0x10
      there (vs 0xc compressed), but the assertion was narrow in both
      modes — fix applies to both.

Result: 143 → 0 `Analysis error` on the same binary. `pp.txt` (14973 lines),
`objs.txt` (19572 lines), `asm/`, `ida_script/`, and `blutter_frida.js` all
regenerate cleanly.

### 4.3 Validation
- [x] **Python path end-to-end validated on a real Flutter iOS Release build**
      (Flutter 3.41.6, Dart 3.11.4, arm64, `flutter build ios --release
      --no-codesign`). `extract_dart_info.py` correctly recovers Dart
      version, snapshot hash, flags, arch, and os_name from
      `App.framework/App` + `Flutter.framework/Flutter`. `blutter.py`'s
      iOS short-circuit prints the expected message instead of crashing.
- [x] **C++ `MachOHelper` parser validated on the same binary** via a
      standalone harness (`clang++ -std=c++20`). All four snapshot symbols
      resolved, snapshot-hash byte window cross-checks with the Python
      extractor.
- [x] **Full C++ analyzer end-to-end on a real Flutter iOS Release build**
      (same `/tmp/blutter_ios_test/libs` fixture as above, now with 4.2 +
      4.2.1 landed). `python3 blutter.py` produces zero `Analysis error`
      messages and emits the full output set:
      - `pp.txt` (14973 lines): object-pool entries with decoded Stubs,
        Strings, Closures, TypeParameters, Fields.
      - `objs.txt` (19572 lines): live object dump with typed children
        (e.g. `WidgetStatePropertyAll<double>`, `EdgeInsets` nested values).
      - `asm/` (302 files across `collection/`, `flutter/`,
        `ios_validation/`, `material_color_utilities/`, `vector_math/`) —
        user Dart code (`ios_validation/main.dart`) is disassembled
        alongside Flutter framework code.
      - `ida_script/` with `addNames.py` + `ida_dart_struct.h`.
      - `blutter_frida.js` with the class-id table populated (Class,
        Function, Field, ... through to the full runtime cid set).
      Cross-architecture diff against a matching Android build of the
      same app is deferred until such a build exists in-tree.
- [x] **C++ unit test harness added in-tree** at `tests/cpp/` using Catch2
      v3.5.3 via CMake FetchContent. Ports `tests/macho_fixture.py` to a
      header-only C++ fixture (`tests/cpp/macho_fixture.h`) and drives
      `MachOHelper::findSnapshots` / `MachOHelper::IsMachO` with 8 test
      cases covering: thin arm64 with single- and double-underscore
      symbol variants, missing required symbol, truncated/bogus magic,
      FAT container with arm64 preferred over x86_64, FAT fallback to
      first slice, and `IsMachO` magic recognition. Build with
      `cmake -G Ninja tests/cpp && ninja -C build/cpp_tests test_macho_parser`.
      Runtime: `build/cpp_tests/test_macho_parser` — 23 assertions across
      8 cases, all passing.

---

## Iteration 5 — x64 analyzer (deferred, low priority)

**Status:** deferred indefinitely. Revisit only if a real-world x64 target
lands on the roadmap — until then this iteration sits behind Iterations 6–8.

**Why deferred:** shipped Dart AOT targets are overwhelmingly arm64.
Google Play has required 64-bit since 2019 and the long tail of arm32
Android has collapsed; iOS has been arm64-only since 2017. The niches that
would need x64 are:
  * Android x86_64 splits for Chromebook / emulator — rarely used in the wild.
  * Flutter desktop (Windows, Intel macOS, Linux) — most desktop Flutter builds
    ship JIT snapshots, not AOT, so blutter's pipeline wouldn't apply anyway.
  * x86_64 simulator builds on Intel Macs — Apple Silicon is now the default.

The cost is high (~4000 lines of Capstone-driven pattern matching mirroring
`CodeAnalyzer_arm64.cpp` and `Disassembler_arm64.h`, ~147 KB total) and the
payoff narrow. Leaving the sub-task list intact below in case the priority
flips later, but intentionally not scheduling it.

**Goal (if resumed):** x64 libapp.so (Android emulator builds, AOT desktop
Flutter) produces usable asm dump.

### 5.1 Dart x64 ABI mapping (prereq)
- [ ] Read `runtime/vm/constants_x64.h` in the target Dart SDK and record
      the register conventions: `THR`, `PP`, `NULL_REG`, `CODE_REG`,
      `DISPATCH_TABLE_REG`, `HEAP_BASE`, argument registers, return reg.
- [ ] Document the mapping in `docs/x64-abi.md` so it can be reviewed
      before any code lands.

### 5.2 Disassembler
- [ ] `Disassembler_x64.{h,cpp}` wrapping Capstone `CS_ARCH_X86` /
      `CS_MODE_64`; mirror `Disassembler_arm64`'s public API (Insn struct,
      operand classification, branch target extraction).
- [ ] Arch dispatch at `Disassembler.cpp` via compile-time `#ifdef` on
      Dart's target arch (same pattern as arm64 gets selected today).

### 5.3 Code analyzer backend
- [ ] `CodeAnalyzer_x64.cpp` — port each pass from the arm64 file: prologue
      detection, stack-frame size, parameter location map, pool offset
      resolution, call target resolution.
- [ ] `CodeAnalyzer.cpp` dispatches to arm64 vs x64 backend.
- [ ] IL generation: reuse `il.h` nodes but emit x64-specific lowering.

### 5.4 Python/build integration
- [ ] `blutter.py` builds `dartvm<ver>_android_x64` + `blutter_dartvm<ver>_android_x64`.
- [ ] Smoke run against an x64 emulator APK.
- [ ] CI job (if environment supports cross-compile).

---

## Iteration 6 — Type inference — landed (surface layer)

**Scope:** surface the signature metadata that `DartApp::finalizeFunctionsInfo`
already walks out of `dart::FunctionType` into every user-facing output. Deeper
inference work (flow-sensitive param-use analysis, generic type-argument
resolution across call sites) remains future work and is tracked separately
under "stretch goals" below.

### 6.1 Research — done (inline)
- [x] Layout source of truth: `DartApp::finalizeFunctionsInfo` in
      `blutter/src/DartApp.cpp` walks `dart::FunctionType` →
      `result_type()`, `NumParameters()`, `num_fixed_parameters()`,
      `NumOptionalPositionalParameters()`, `NumOptionalNamedParameters()`,
      `IsRequiredAt()`, `ParameterTypeAt()`, `ParameterNameAt()`. Types are
      canonicalized through `DartTypeDb::FindOrAdd` to dedupe across
      functions.
- [x] Compat-macro interaction: `HAS_RECORD_TYPE` extends `DartAbstractType`
      with the `RecordType` kind so `ToString()` round-trips tuple types on
      Dart 3.0+; `UNIFORM_INTEGER_ACCESS` only affects integer reading inside
      the analyzer IR, not the signature path. No special-casing needed in
      the surface layer.

### 6.2 Implementation — landed
- [x] Function signature recovery (argc, argc_opt, has_named, is_static,
      is_closure, is_required-per-named-param, param names, param types,
      return type) is populated on every `DartFunction` whose signature
      survived snapshotting. Verified on the iOS 3.11.4 fixture: 6747
      functions total, 1369 with non-empty `params[]`, 1576 with a recovered
      return type, 29 named params, 5 required named params.
- [x] Return type surfaced on `DartFunction::Signature().ReturnType()`; used
      by the existing asm header emitter (`PrintHead`), the Frida table, the
      SQLite `functions.ret` column, and the new `functions.json`.
- [x] `functions.json` (schema_version=1). One record per unique function
      address with `addr`, `name`, `class`, `library`, flag triad,
      `return_type`, and a `params[]` array of `{name, type, required}`
      entries. Emitted from `DartDumper::DumpFunctionsJson`, triggered by
      `--json`.
- [x] SQLite `params` table — `(fn_addr, idx, name, type, is_required)` with
      composite primary key, indexed on `fn_addr`. Join back to `functions`
      for a full signature view.
- [x] `scripts/frida.template.js` table extended: function entries now carry
      a `params` array when the signature was recovered
      (`{name?, type, req?}`), via `FridaWriter.cpp`.

### 6.3 Stretch goals (not required to close Iter 6)
- [ ] Generic type-argument resolution at call sites (walks the object-pool
      `TypeArguments` slots touched by each caller to refine an otherwise
      erased `T` return).
- [ ] Nullability tightening for param types inferred from null-check
      patterns at function entry.
- [ ] Schema bump to `schema_version: 2` if a future consumer requires the
      richer envelope above.

---

## Iteration 7 — Deobfuscation — landed (first pass)

**Scope:** heuristic, Python-side. Implemented as a post-processor that reads
the artifacts blutter already produces (`functions.json` or `blutter.db`).
Lives in `scripts/deobfuscate.py`; blutter.py invokes it automatically at the
end of a run so no flag is needed to get the report.

- [x] Detect obfuscated snapshots — name-shape regex
      `^[A-Za-z]{1,2}[0-9]{0,4}$` on function names, with anonymous closures
      and empty names excluded from the denominator. Verdict threshold:
      ratio ≥ 0.30 of remaining names. Verified non-obfuscated on the iOS
      3.11.4 fixture (0.6% ratio, 36/6312); verified obfuscated on a
      synthetic input (75% ratio → is_obfuscated=true).
- [x] Heuristic name recovery pass #1: library-namespace fallback. When a
      function's name looks obfuscated but its owning library URL survived
      (always true for `dart:*` and `package:flutter/*` because those come
      from pre-compiled kernel the renamer skips), emit
      `<lib>::__unobf_<orig>` with confidence 0.35. Not a *correct* name —
      useful as a triage prefix to surface which library the obfuscator
      renamed into.
- [x] Heuristic name recovery pass #2: intrinsic CID table
      (`DART_INTRINSIC_NAMES`). Covers the stable predefined class ids
      (`_Double`=62, `String`=85, `Array`=94, `ImmutableArray`=95, `_Smi`=46,
      `Closure`=42, `bool`=51, `Null`=1, `Class`=0, `LibraryPrefix`=53).
      When one of these CIDs appears in the snapshot with a name that looks
      obfuscated, emit the canonical name with confidence 0.95.
- [x] Confidence score attached to each recovered name (`RecoveredName`
      dataclass, field `confidence`).
- [x] Surface via `recovered_names.json` (schema_version=1) in the blutter
      output directory, plus a one-line banner on stdout. No rewrite into
      asm dump or binary — consumers (scripts, auditors) pick which
      candidates to trust.

### 7.1 Stretch goals (not required to close Iter 7)
- [ ] Full "string-reference proximity" pass — walk each function's pool
      references and, when ≥ 2 distinct literal strings share a domain
      (e.g. SQL keywords), propose a name like `query_users`. Depends on
      CodeAnalyzer attaching per-instruction pool-index metadata, which is
      partially implemented today.
- [ ] Cross-build symbol stability — once we run blutter on two versions of
      the same app, confirm that intrinsic-CID recoveries agree between
      them, giving users a basis for *observational* confidence on top of
      the static confidence score.
- [ ] Apply recovered-name overlay to the Ghidra / IDA scripts so the
      rename propagates to disassembly views (currently we only emit the
      JSON).

---

## Iteration 8 — Additional output formats

Each output is independent; can land in any order.

### 8.1 Ghidra script (landed, minus per-insn struct refs)
- [x] New `ghidra_script/` directory parallel to `ida_script/`; emits a
      single self-contained `blutter_ghidra.py` (no external dependencies —
      the Dart struct C source is embedded inline as a raw Python string).
- [x] Translate IDA symbol output to Ghidra Jython bindings: `FUNCS`,
      `EXTRA_LABELS` (morphic miss/check), `STUBS`, `POOL_COMMENTS` data
      tables + `apply_all()` which calls `createFunction`/`createLabel` +
      `CParser.parse()` on the struct source, then walks
      `DTM.getAllStructures()` to resolve the `DartThread` / `DartObjectPool`
      types around possible typedef wrapping, and finally applies
      `POOL_COMMENTS` via `Structure.getComponentAt(off).setComment`.
- [x] Wired into `main.cpp` right after `Dump4Ida`. Verified against the
      iOS gallery fixture: 6811 functions, 144 extra labels, 1523 stubs,
      8070 pool comments, ~1.5 MB script, parses under Python's `ast`.
- [x] README "Output files" section updated.
- [ ] Deferred: per-instruction EOL comments for DART_THR (x28) / DART_PP
      (x27) operand refs — IDA's equivalent is the `op_stroff` pass. Ghidra
      has no direct analogue; needs a pre-computed `(insn_addr, reg, imm)`
      table. Straightforward follow-up; skipped for this first cut to keep
      the script a manageable size.

### 8.2 DWARF export (landed)
- [x] Hand-rolled DWARF-5 emitter in `blutter/src/DwarfWriter.{h,cpp}` —
      no libdwarf / dwarfgen dependency. Writes a single ELF64/aarch64
      relocatable `blutter.dwarf` with `.shstrtab`, `.strtab`, `.symtab`,
      `.debug_str`, `.debug_abbrev`, `.debug_info`. ELF header + section
      headers packed by hand (no `<elf.h>` dependency, so the writer
      compiles cleanly on macOS hosts).
- [x] One compile unit per output; each function + non-empty stub becomes
      a `DW_TAG_subprogram` DIE with `DW_AT_name` / `DW_AT_low_pc` /
      `DW_AT_high_pc` (high_pc as data8 = size, per DWARF-4+ convention).
      `.symtab` carries the same set as `STT_FUNC` symbols anchored at
      `SHN_ABS` so `nm` / `objdump -t` also work.
- [x] Wired into `main.cpp` right after `FridaWriter`. Verified on the iOS
      gallery fixture: 8333 subprograms, ~1.2 MB file.
- [x] Verification: `dwarfdump` parses it cleanly as DWARF-5; `lldb
      target create` loads it and `image lookup -n <sym>` resolves names
      to addresses; `objdump -h` shows all six sections; `nm` enumerates
      all symbols. `dwarfdump --verify` reports one "overlapping address
      ranges" error which is expected on Dart AOT due to
      `dedup_instructions` (multiple function names share the same code
      range); the file is otherwise structurally sound.
- [x] README "Output files" section updated with load instructions for
      gdb and lldb.

### 8.3 Function-aware Frida script (landed)
- [x] Extract `DartFunction` metadata into `blutter_frida.js`: `FridaWriter::Create`
      emits a `Functions` array alongside `Classes`, one entry per analyzed
      function keyed by entry-point offset, with short keys
      (`addr`, `name`, `cls`, `lib`, `argc`, `argcOpt?`, `named?`, `stat?`,
      `clos?`, `ret?`). 6747 entries on the iOS gallery fixture.
- [x] Add lookup helpers in `scripts/frida.template.js`:
      `getFunctionByAddr(offset)`, `getFunctionByName(name)` (indexed by bare
      name, `Cls.name`, and `[lib] Cls::name`), and a `hookFunction` wrapper
      around `Interceptor.attach` that resolves by name or offset and logs
      the resolved signature.
- [x] Bug fix uncovered during verification: `DartFunctionSignature` fields
      (`returnType`, `numOptionalParam`, `hasNamedParam`) were uninitialized
      and `numOptionalParam`/`hasNamedParam` were never assigned. Fixed by
      adding default member initializers in `DartFunction.h` and populating
      both fields from `num_opt_params` / `num_opt_named_params` in
      `DartApp.cpp`. Verified post-fix: 31 funcs with `argcOpt`, 17 with
      `named`, 1576 with `ret`, 1369 static, 757 closures.

### 8.4 SQLite export — landed
- [x] Schema:
      `objects(ptr PK, cid, class_name, description)`,
      `pool(idx PK, offset, description)`,
      `functions(addr PK, name, cls, lib, argc, argc_opt, has_named,
                 is_static, is_closure, ret)`,
      plus a `meta(key, value)` table with `schema_version=1`.
      ('idx' is used in place of SQL's reserved 'index'; 'cls' exposes the
      owning class name in addition to its library.)
- [x] `--sqlite` flag on both the C++ binary and `blutter.py`. The C++ side
      emits `blutter.db.sql` (CREATE TABLE + INSERTs wrapped in a single
      transaction, with `PRAGMA journal_mode=OFF` / `synchronous=OFF` for
      fast bulk load). `blutter.py` materializes `blutter.db` from that SQL
      via stdlib `sqlite3.executescript()`, so the C++ binary doesn't need
      to link libsqlite3.
- [x] `functions` is populated from the address-keyed `DartApp::functions`
      map (rather than walking libs→classes→Functions()) so that
      dedup_instructions collisions don't violate the PRIMARY KEY.
- [x] Verified end-to-end on the iOS arm64 fixture
      (`/tmp/blutter_ios_test/libs`, Dart 3.11.4): 1820 objects, 8441 pool
      entries, 6747 functions across 293 libraries; sample queries via
      `sqlite3` return expected rows. Full pipeline
      (`python3 blutter.py … --sqlite`) produces both `blutter.db.sql`
      (~2.3 MB) and `blutter.db` (~2.2 MB).

---

## Cross-cutting hygiene (ongoing)

- [x] Bug: `EM_IA_64` vs `EM_X86_64` — fixed & regression-tested in 1.7
- [x] Bug: `st_value` as file offset — fixed & regression-tested in 1.7
- [x] Bug: version compare `>= 3.8` for Dart 4.x — fixed & regression-tested in 1.3
- [x] Bug: mnemonic memcpy bound — fixed
- [x] Bug: HTTP status check `// 10 == 20` — fixed
- [x] Bug: `shutil.rmtree` `onerror` deprecation — fixed
- [x] Bug: mmap patch without flush — fixed
- [x] Typo: `gerVersion_*` — fixed
- [x] ICU inner-zip lookup by name — fixed
- [x] `extract_libflutter_info` hardening: tolerate ≠ 2 SHA hashes (dedupes + keeps all valid hashes)
- [x] `extract_libflutter_functions.py` pattern-match instead of positional (ADRP+ADD scan, first BL, first tail B)
- [ ] Compat macros detected via version+commit metadata, not string-search of headers
  > Would remove the fragile `mmap.find(b'V(TypeRef)')` style checks. Requires
  > maintaining a version→commit→macro mapping table. Punting until a Dart
  > release breaks the current detection — at that point the payoff justifies
  > the bookkeeping overhead.
- [ ] Compat macros detected via version+commit metadata, not string-search of headers
