# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Blutter reverse-engineers Flutter Android apps (arm64 `libapp.so`). It does this by compiling the Dart AOT runtime as a static library for the exact Dart version the target app was built with, then linking a C++ tool against it that loads the snapshot and dumps objects, assembly, an IDA script, and a Frida hook template.

Currently only Android arm64 is fully supported; iOS/x64 paths exist but are incomplete.

## Common commands

All workflows go through `blutter.py` (Python 3). The script auto-detects the Dart version, fetches matching Dart SDK source, builds a per-version `dartvm<ver>_<os>_<arch>` static lib into `packages/`, builds the blutter C++ executable into `bin/`, then runs it.

```
# Standard: directory containing libapp.so + libflutter.so
python3 blutter.py path/to/app/lib/arm64-v8a out_dir

# APK input (arm64-v8a libs are extracted to a temp dir)
python3 blutter.py path/to/app.apk out_dir

# Force rebuild the blutter binary (after git pull, or when editing blutter/src/*)
python3 blutter.py path/to/lib/arm64-v8a out_dir --rebuild

# Skip code analysis pass (produces asm dump only; forced on automatically for Dart <2.15)
python3 blutter.py path/to/lib/arm64-v8a out_dir --no-analysis

# Windows: emit a Visual Studio solution instead of building (run from x64 Native Tools prompt)
python blutter.py path\to\lib\arm64-v8a build\vs --vs-sln

# Run without libflutter (indir becomes the libapp.so path); specify the Dart target triple
python3 blutter.py libapp.so out_dir --dart-version 3.4.2_android_arm64
```

Fetch + build a Dart VM static lib by itself (rarely needed, but useful when iterating on the Dart compat layer):

```
python3 dartvm_fetch_build.py <dart_version> [android|ios] [arm64|x64] [snapshot_hash]
```

Inspect a target without building anything:

```
python3 extract_dart_info.py path/to/lib/arm64-v8a
```

### Platform notes

- Requires a C++20-capable compiler (`<format>`): g++ >= 13, Clang >= 16. On macOS Ventura/Sonoma, `blutter.py` expects `brew --prefix llvm@16` and overrides `CC`/`CXX` automatically; on Sequoia (macOS 15+) the system toolchain is used.
- Dart 3.11.0+ requires C++20; earlier versions are built with C++17. The actual standard is parsed from `runtime/tools/run_clang_tidy.dart` in each Dart checkout — do not hardcode this.
- There are no automated tests in this repo. "Is it working?" means: build succeeds and `python3 blutter.py <lib> <out>` produces a non-empty `out/asm/`, `pp.txt`, `objs.txt`, and `blutter_frida.js`.

## Architecture

### Two-stage build pipeline

1. **Dart VM static lib** (`dartvm_fetch_build.py` → `scripts/CMakeLists.txt` template)
   - Sparse-clones `dart-lang/sdk` at the exact version tag into `dartsdk/v<ver>/`, keeping only `runtime/`, `tools/`, `third_party/double-conversion/`.
   - Generates `runtime/vm/version.cc` (either via the upstream `tools/make_version.py`, or via `scripts/dartvm_make_version.py` when a snapshot hash was extracted from `libapp.so`).
   - Generates a source list via `scripts/dartvm_create_srclist.py`, instantiates `scripts/CMakeLists.txt` with the Dart version + C++ std into `dartsdk/v<ver>/CMakeLists.txt`, then CMake+Ninja builds a static lib and installs it to `packages/lib/libdartvm<ver>_<os>_<arch>.a` with headers at `packages/include/dartvm<ver>/`.
   - Key defines baked in: `DART_PRECOMPILED_RUNTIME`, `PRODUCT`, `EXCLUDE_CFE_AND_KERNEL_PLATFORM`, `TARGET_ARCH_*`, `DART_TARGET_OS_*`, and conditionally `DART_COMPRESSED_POINTERS`.
   - Python 3.12 compatibility: `dart-lang/sdk`'s older `tools/utils.py` imports the removed `imp` module. `checkout_dart` patches it in place using `importlib.machinery`. Keep this patch if you touch that function.
   - Windows + Dart >= 3.8 + arm64: `runtime/platform/unwinding_records.h` is patched to work around a `RUNTIME_FUNCTION` redeclaration.

2. **blutter executable** (`blutter/CMakeLists.txt`)
   - Links against one specific `dartvm<ver>_<os>_<arch>` package (`find_package(${DARTLIB})`) plus system `capstone` (or the vendored `external/capstone/` on Windows) and ICU.
   - Output: `bin/blutter_dartvm<ver>_<os>_<arch>[_suffix]`. Suffix is `_no-compressed-ptrs` (iOS default) and/or `_no-analysis`.
   - A separate binary is produced per Dart version — do not assume one binary handles multiple versions.

### Dart version compatibility macros

`find_compat_macro` in `blutter.py` greps specific commit-fingerprint strings out of the checked-out Dart headers (`class_id.h`, `class_table.h`, `stub_code_list.h`, `object_store.h`, `object.h`) and translates them into `-D` flags passed to the blutter build. Each flag corresponds to a specific upstream Dart commit (commit links are in the Python source). When a new Dart release changes VM internals, the fix is almost always:

1. Find the commit that changed the relevant struct/enum.
2. Add a detection line in `find_compat_macro` that checks for a pre/post-commit marker string.
3. Add matching `#ifdef` branches in the C++ sources and a mirrored entry in `blutter/CMakeLists.txt`.

Current macros: `OLD_MAP_SET_NAME`, `OLD_MAP_NO_IMMUTABLE`, `NO_LAST_INTERNAL_ONLY_CID`, `HAS_SHARED_CLASS_TABLE`, `HAS_TYPE_REF`, `HAS_RECORD_TYPE`, `NO_INIT_LATE_STATIC_FIELD`, `NO_METHOD_EXTRACTOR_STUB`, `UNIFORM_INTEGER_ACCESS`, `NO_CODE_ANALYSIS`.

### Runtime target detection

`extract_dart_info.py` reads `libapp.so` and `libflutter.so` with `pyelftools`:
- The Dart VM snapshot hash + feature flags (including `compressed-pointers`) come from the bytes at `_kDartVmSnapshotData`.
- The Dart version string comes from `libflutter.so`'s `.rodata`. If missing (beta/dev channel), two candidate engine SHA hashes are extracted and resolved against `storage.googleapis.com/flutter_infra_release` to download just the first 4 KiB of `dart-sdk-windows-x64.zip` to read `dart-sdk/revision` and `dart-sdk/version`.

This is why the tool needs network access the first time it sees an unfamiliar app.

### C++ tool layout (`blutter/src/`)

Pipeline inside `main.cpp`:

1. `DartApp` loads the ELF, relocates segments, and exposes `base()` / `heap_base()`. `LoadInfo()` walks the snapshot to build `DartLoader`/`DartClass`/`DartLibrary`/`DartFunction`/`DartField`/`DartStub`/`DartTypes`.
2. `CodeAnalyzer` (+ `CodeAnalyzer_arm64.cpp` for the arm64 backend, using Capstone via `Disassembler_arm64`) runs unless `NO_CODE_ANALYSIS` is defined. `il.{h,cpp}` defines the intermediate representation it produces.
3. `DartDumper` emits `pp.txt`, `objs.txt`, `asm/`, and `ida_script/`.
4. `FridaWriter` renders `scripts/frida.template.js` (path baked in at build time via `FRIDA_TEMPLATE_DIR`) into `blutter_frida.js`.

`pch.h` is the precompiled header and pulls in the Dart VM internals; anything added there recompiles the world.

### Directory conventions

- `bin/` — compiled blutter executables, one per (Dart version × os × arch × suffix).
- `packages/` — installed Dart VM static libs and headers (one subtree per version).
- `dartsdk/` — transient Dart source checkouts; safe to delete after a successful build.
- `build/` — transient CMake+Ninja build trees for both the Dart VM and blutter; safe to delete.
- `external/` — vendored libraries (Capstone, ICU) for Windows only.
- `scripts/` — Python helpers invoked during the Dart VM build, plus `frida.template.js`.
