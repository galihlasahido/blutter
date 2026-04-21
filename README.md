# B(l)utter
Flutter Mobile Application Reverse Engineering Tool by Compiling Dart AOT Runtime

Currently the application supports only Android libapp.so (arm64 only).
Also the application is currently work only against recent Dart versions.

For high priority missing features, see [TODO](#todo)


## Environment Setup
This application uses C++20 Formatting library. It requires very recent C++ compiler such as g++>=13, Clang>=16.

I recommend using Linux OS (only tested on Deiban sid/trixie) because it is easy to setup.

### Debian Unstable (gcc 13)
**_NOTE:_**
Use ONLY Debian/Ubuntu version that provides gcc>=13 from its own main repository.
Using ported gcc to old Debian/Ubuntu version does not work.

- Install build tools and depenencies
```
apt install python3-pyelftools python3-requests git cmake ninja-build \
    build-essential pkg-config libicu-dev libcapstone-dev
```

### Windows
- Install git and python 3
- Install latest Visual Studio with "Desktop development with C++" and "C++ CMake tools"
- Install required libraries (libcapstone and libicu4c)
```
python scripts\init_env_win.py
```
- Start "x64 Native Tools Command Prompt"

### macOS Sequoia
- Install XCode
- Install required tools
```
brew install cmake ninja pkg-config icu4c capstone
pip3 install pyelftools requests
```

### macOS Ventura and Sonoma (clang 16)
- Install XCode
- Install clang 16 and required tools
```
brew install llvm@16 cmake ninja pkg-config icu4c capstone
pip3 install pyelftools requests
```

## Usage
Extract "lib" directory from apk file
```
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```
The blutter.py will automatically detect the Dart version from the flutter engine and call executable of blutter to get the information from libapp.so.

If the blutter executable for required Dart version does not exists, the script will automatically checkout Dart source code and compiling it.

`blutter.py` can also take an `.apk` or an `.ipa` directly and will extract the
required binaries into a temporary directory:
```
python3 blutter.py path/to/app.apk out_dir
python3 blutter.py path/to/app.ipa out_dir
```

### iOS / Mach-O (detection only)
Blutter detects iOS targets end-to-end: pointing the script at an `.ipa` or a
`Payload/<Name>.app/` directory reports the Dart version, snapshot hash, flags,
and target (`ios arm64`). The analyzer build is then skipped because the C++
binary loader is ELF-only today — Mach-O loader support is tracked in
`plan.md` (Iteration 4).

## Update
You can use ```git pull``` to update and run blutter.py with ```--rebuild``` option to force rebuild the executable
```
python3 blutter.py path/to/app/lib/arm64-v8a out_dir --rebuild
```

## Output files
- **asm/\*** libapp assemblies with symbols
- **blutter_frida.js** the frida script template for the target application
- **blutter.dwarf** minimal DWARF-5 debug file (ELF64/aarch64 container) with
  function names + addresses as `DW_TAG_subprogram` DIEs and an ELF `.symtab`.
  Load into gdb/lldb as a separate debug file (e.g. `add-symbol-file
  blutter.dwarf -o 0` in gdb, or `target symbols add blutter.dwarf` in lldb)
- **ghidra_script/blutter_ghidra.py** Ghidra Jython script that applies function
  names + stubs + Dart struct types (`DartThread`, `DartObjectPool`). Run it
  from Ghidra's Script Manager after initial auto-analysis
- **ida_script/** IDAPython helpers (addNames.py + ida_dart_struct.h)
- **objs.txt** complete (nested) dump of Object from Object Pool
- **pp.txt** all Dart objects in Object Pool
- **blutter.db** / **blutter.db.sql** (only with `--sqlite`) SQLite database
  with these tables: `objects(ptr, cid, class_name, description)`,
  `pool(idx, offset, description)`,
  `functions(addr, name, cls, lib, argc, argc_opt, has_named, is_static,
  is_closure, ret)`, and
  `params(fn_addr, idx, name, type, is_required)` (join to `functions` on
  `fn_addr`). blutter emits the `.sql` form; blutter.py materializes the
  binary `.db` via Python's stdlib sqlite3. Query with
  `sqlite3 out/blutter.db 'SELECT lib, COUNT(*) FROM functions GROUP BY lib'`
- **functions.json** (only with `--json`) structured signatures for every
  recovered function: `addr`, `name`, `class`, `library`, flag triad,
  `return_type`, and a `params[]` array of `{name, type, required}`.
- **recovered_names.json** post-processor output from
  `scripts/deobfuscate.py`. Always emitted when `--json` or `--sqlite` is
  set. Contains an obfuscation-detection summary (ratio of names matching
  the Dart `--obfuscate` rename shape) plus a list of recovered-name
  candidates with a confidence score in [0.0, 1.0]. On a non-obfuscated
  build the candidate list is empty.


## Directories
- **bin** contains blutter executables for each Dart version in "blutter_dartvm\<ver\>\_\<os\>\_\<arch\>" format
- **blutter** contains source code. need building against Dart VM library
- **build** contains building projects which can be deleted after finishing the build process
- **dartsdk** contains checkout of Dart Runtime which can be deleted after finishing the build process
- **external** contains 3rd party libraries for Windows only
- **packages** contains the static libraries of Dart Runtime
- **scripts** contains python scripts for getting/building Dart


## Generating Visual Studio Solution for Development
I use Visual Studio to delevlop Blutter on Windows. ```--vs-sln``` options can be used to generate a Visual Studio solution.
```
python blutter.py path\to\lib\arm64-v8a build\vs --vs-sln
```

## TODO
- More code analysis
  - Function arguments and return type
  - Some psuedo code for code pattern
- Generate better Frida script
  - More internal classes
  - Object modification
- Obfuscated app (still missing many functions)
- Reading iOS binary
- Input as apk or ipa
