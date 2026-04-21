import io
import os
import re
import requests
import sys
import zipfile
import zlib
from struct import unpack

from elftools.elf.elffile import ELFFile

import macho_info


def _sniff_format(path: str) -> str:
    """Return 'elf', 'macho', or 'unknown' based on the file magic."""
    with open(path, 'rb') as f:
        head = f.read(4)
    if len(head) < 4:
        return 'unknown'
    if head[:4] == b'\x7fELF':
        return 'elf'
    fmt = macho_info.sniff_format(head)
    if fmt in ('macho', 'fat-macho'):
        return 'macho'
    return 'unknown'


def _extract_snapshot_hash_flags_elf(libapp_file):
    with open(libapp_file, 'rb') as f:
        elf = ELFFile(f)
        # find "_kDartVmSnapshotData" symbol
        dynsym = elf.get_section_by_name('.dynsym')
        sym = dynsym.get_symbol_by_name('_kDartVmSnapshotData')[0]
        assert sym['st_size'] > 128
        # st_value is a virtual address; for ET_DYN it is not necessarily equal to the
        # file offset. Translate via the section that contains the symbol.
        section = elf.get_section(sym['st_shndx'])
        file_offset = section['sh_offset'] + (sym['st_value'] - section['sh_addr'])
        f.seek(file_offset + 20)
        snapshot_hash = f.read(32).decode()
        data = f.read(256) # should be enough
        flags = data[:data.index(b'\0')].decode().strip().split(' ')

    return snapshot_hash, flags


def _extract_snapshot_hash_flags_macho(libapp_file):
    sl = macho_info.parse(libapp_file, prefer_arch='arm64')
    # Mach-O C symbols are exported with a leading underscore, so the Dart symbol
    # `_kDartVmSnapshotData` appears in the symbol table as `__kDartVmSnapshotData`.
    sym = sl.find_symbol('__kDartVmSnapshotData', '_kDartVmSnapshotData')
    if sym is None:
        raise RuntimeError('kDartVmSnapshotData symbol not found in Mach-O binary')

    file_offset = sl.vm_to_file_offset(sym.n_value)
    if file_offset is None:
        raise RuntimeError(
            f'Could not map kDartVmSnapshotData vm address {sym.n_value:#x} to file offset'
        )

    buf = sl.container_bytes[file_offset + 20:file_offset + 20 + 32 + 256]
    snapshot_hash = buf[:32].decode()
    tail = buf[32:]
    flags = tail[:tail.index(b'\0')].decode().strip().split(' ')
    return snapshot_hash, flags


def extract_snapshot_hash_flags(libapp_file):
    fmt = _sniff_format(libapp_file)
    if fmt == 'elf':
        return _extract_snapshot_hash_flags_elf(libapp_file)
    if fmt == 'macho':
        return _extract_snapshot_hash_flags_macho(libapp_file)
    raise ValueError(f'Unsupported binary format for {libapp_file}')


def _extract_libflutter_info_elf(libflutter_file):
    with open(libflutter_file, 'rb') as f:
        elf = ELFFile(f)
        if elf.header.e_machine == 'EM_AARCH64': # 183
            arch = 'arm64'
        elif elf.header.e_machine == 'EM_X86_64': # 62
            arch = 'x64'
        else:
            assert False, f"Unsupport architecture: {elf.header.e_machine}"

        section = elf.get_section_by_name('.rodata')
        data = section.data()

    return _parse_flutter_strings(data, arch, 'android')


def _extract_libflutter_info_macho(libflutter_file):
    sl = macho_info.parse(libflutter_file, prefer_arch='arm64')
    if sl.arch not in ('arm64', 'x64'):
        assert False, f"Unsupport architecture: {sl.arch}"

    # Collect bytes from every __TEXT section that can contain string literals.
    # __TEXT,__const holds C-string constants in newer toolchains;
    # __TEXT,__cstring is the classic location. We scan both.
    chunks = []
    for section in sl.sections:
        if section.segname != '__TEXT':
            continue
        if section.sectname not in ('__const', '__cstring'):
            continue
        chunks.append(sl.section_bytes(section))
    data = b'\x00'.join(chunks)

    return _parse_flutter_strings(data, sl.arch, 'ios')


def _parse_flutter_strings(data: bytes, arch: str, os_name: str):
    # Historically libflutter embedded exactly two null-terminated SHA-1 hashes
    # (engine commit + skia/dart commit, ordering varies by release). Newer
    # builds have been observed with 1 or 3. Return all of them deduped so
    # get_dart_sdk_url_size can try each.
    sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', data)
    seen = set()
    engine_ids = []
    for h in sha_hashes:
        sid = h.decode()
        if sid not in seen:
            seen.add(sid)
            engine_ids.append(sid)

    m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', data)
    dart_version = m.group(1).decode() if m else None

    # iOS Flutter often has the stamped version string but no embedded SHA-1
    # engine hashes; Android Flutter typically has hashes and no version string.
    # We only fail if both channels are empty.
    assert dart_version or engine_ids, (
        'Could not find Dart version string or engine SHA hashes in libflutter'
    )

    return engine_ids, dart_version, arch, os_name


def extract_libflutter_info(libflutter_file):
    fmt = _sniff_format(libflutter_file)
    if fmt == 'elf':
        return _extract_libflutter_info_elf(libflutter_file)
    if fmt == 'macho':
        return _extract_libflutter_info_macho(libflutter_file)
    raise ValueError(f'Unsupported binary format for {libflutter_file}')


def get_dart_sdk_url_size(engine_ids):
    #url = f'https://storage.googleapis.com/dart-archive/channels/stable/release/3.0.3/sdk/dartsdk-windows-x64-release.zip'
    for engine_id in engine_ids:
        url = f'https://storage.googleapis.com/flutter_infra_release/flutter/{engine_id}/dart-sdk-windows-x64.zip'
        resp = requests.head(url, timeout=30)
        if resp.status_code == 200:
           sdk_size = int(resp.headers['Content-Length'])
           return engine_id, url, sdk_size

    return None, None, None

def get_dart_commit(url):
    # in downloaded zip
    # * dart-sdk/revision - the dart commit id of https://github.com/dart-lang/sdk/
    # * dart-sdk/version  - the dart version
    # revision and version zip file records should be in first 4096 bytes
    # using stream in case a server does not support range
    commit_id = None
    dart_version = None
    fp = None
    with requests.get(url, headers={"Range": "bytes=0-4096"}, stream=True, timeout=30) as r:
        if r.status_code // 100 == 2:
            x = next(r.iter_content(chunk_size=4096))
            fp = io.BytesIO(x)

    if fp is not None:
        while fp.tell() < 4096-30 and (commit_id is None or dart_version is None):
            #sig, ver, flags, compression, filetime, filedate, crc, compressSize, uncompressSize, filenameLen, extraLen = unpack(fp, '<IHHHHHIIIHH')
            _, _, _, compMethod, _, _, _, compressSize, _, filenameLen, extraLen = unpack('<IHHHHHIIIHH', fp.read(30))
            filename = fp.read(filenameLen)
            #print(filename)
            if extraLen > 0:
                fp.seek(extraLen, io.SEEK_CUR)
            data = fp.read(compressSize)

            # expect compression method to be zipfile.ZIP_DEFLATED
            assert compMethod == zipfile.ZIP_DEFLATED, 'Unexpected compression method'
            if filename == b'dart-sdk/revision':
                commit_id = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()
            elif filename == b'dart-sdk/version':
                dart_version = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()

    # TODO: if no revision and version in first 4096 bytes, get the file location from the first zip dir entries at the end of file (less than 256KB)
    return commit_id, dart_version

def extract_dart_info(libapp_file: str, libflutter_file: str):
    snapshot_hash, flags = extract_snapshot_hash_flags(libapp_file)

    engine_ids, dart_version, arch, os_name = extract_libflutter_info(libflutter_file)

    if dart_version is None:
        engine_id, sdk_url, sdk_size = get_dart_sdk_url_size(engine_ids)
        commit_id, dart_version = get_dart_commit(sdk_url)

    return dart_version, snapshot_hash, flags, arch, os_name


def _resolve_lib_pair(path: str):
    """Resolve a directory to (libapp, libflutter) paths.

    Accepts three layouts:
      1. Android: <dir>/libapp.so + <dir>/libflutter.so
      2. iOS frameworks: <dir>/App.framework/App + <dir>/Flutter.framework/Flutter
      3. iOS flat: <dir>/App + <dir>/Flutter (e.g. copied out of an .ipa)
    """
    candidates = [
        (os.path.join(path, 'libapp.so'), os.path.join(path, 'libflutter.so')),
        (os.path.join(path, 'App.framework', 'App'),
         os.path.join(path, 'Flutter.framework', 'Flutter')),
        (os.path.join(path, 'App'), os.path.join(path, 'Flutter')),
    ]
    for app, flutter in candidates:
        if os.path.isfile(app) and os.path.isfile(flutter):
            return app, flutter
    raise FileNotFoundError(
        f'Could not find a libapp/libflutter pair under {path!r}. '
        'Expected libapp.so+libflutter.so (Android) or App.framework/App+Flutter.framework/Flutter (iOS).'
    )


if __name__ == "__main__":
    arg = sys.argv[1]
    if os.path.isdir(arg):
        libapp_file, libflutter_file = _resolve_lib_pair(arg)
    elif len(sys.argv) >= 3:
        libapp_file, libflutter_file = sys.argv[1], sys.argv[2]
    else:
        raise SystemExit(
            'Usage: extract_dart_info.py <dir> | <libapp> <libflutter>'
        )

    print(extract_dart_info(libapp_file, libflutter_file))
