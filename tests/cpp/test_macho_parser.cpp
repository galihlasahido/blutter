// Catch2 regression tests for blutter/src/MachOHelper.cpp.
//
// The tests drive the parser with synthetic Mach-O 64 thin and FAT byte
// buffers built by macho_fixture.h (the C++ mirror of tests/macho_fixture.py).
// This is the parser-side counterpart to the Python tests in
// tests/test_macho_info.py, so breakage in either language surfaces the
// same kind of regression.

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "MachOHelper.h"
#include "macho_fixture.h"

using namespace macho_fixture;

namespace {

// Puts the four Dart snapshot symbols into two separate sections so the
// parser's vmaddr → file-offset mapping gets exercised on both.
BuiltMachO make_four_sym_arm64(const std::string& prefix) {
    std::vector<uint8_t> a(4096, 0);
    std::vector<uint8_t> b(4096, 0);
    for (size_t i = 0; i < a.size(); ++i) a[i] = static_cast<uint8_t>(i & 0xff);
    for (size_t i = 0; i < b.size(); ++i) b[i] = static_cast<uint8_t>((i + 0x80) & 0xff);

    std::vector<Section> sections = {
        Section{ "__TEXT",       "__const", std::move(a) },
        Section{ "__DATA_CONST", "__const", std::move(b) },
    };
    std::vector<Symbol> symbols = {
        Symbol{ prefix + "kDartVmSnapshotData",              1, 0x100 },
        Symbol{ prefix + "kDartVmSnapshotInstructions",      0, 0x200 },
        Symbol{ prefix + "kDartIsolateSnapshotData",         1, 0x300 },
        Symbol{ prefix + "kDartIsolateSnapshotInstructions", 0, 0x400 },
    };
    return build_thin(sections, symbols);
}

} // namespace

TEST_CASE("thin arm64 mach-o: all four Dart snapshot symbols resolve", "[macho][thin]") {
    auto built = make_four_sym_arm64("_");

    LibAppInfo info = MachOHelper::findSnapshots(built.bytes.data(), built.bytes.size());
    REQUIRE(info.lib == built.bytes.data());

    auto expected = [&](size_t sect_idx, uint64_t off) {
        return built.bytes.data() + built.section_file_offsets[sect_idx] + off;
    };
    REQUIRE(info.vm_snapshot_data              == expected(1, 0x100));
    REQUIRE(info.vm_snapshot_instructions      == expected(0, 0x200));
    REQUIRE(info.isolate_snapshot_data         == expected(1, 0x300));
    REQUIRE(info.isolate_snapshot_instructions == expected(0, 0x400));
}

TEST_CASE("thin arm64 mach-o: double-underscore symbol variant is accepted", "[macho][thin]") {
    auto built = make_four_sym_arm64("__");
    REQUIRE_NOTHROW(MachOHelper::findSnapshots(built.bytes.data(), built.bytes.size()));
}

TEST_CASE("thin mach-o: missing _kDartVmSnapshotData is a parse error", "[macho][error]") {
    std::vector<uint8_t> payload(256, 0);
    std::vector<Section> sections = {
        Section{ "__DATA_CONST", "__const", std::move(payload) },
    };
    std::vector<Symbol> symbols = {
        Symbol{ "_kDartVmSnapshotInstructions",      0, 0 },
        Symbol{ "_kDartIsolateSnapshotData",         0, 0x40 },
        Symbol{ "_kDartIsolateSnapshotInstructions", 0, 0x80 },
    };
    auto built = build_thin(sections, symbols);
    REQUIRE_THROWS_AS(
        MachOHelper::findSnapshots(built.bytes.data(), built.bytes.size()),
        std::invalid_argument);
}

TEST_CASE("thin mach-o: truncated header is a parse error", "[macho][error]") {
    uint8_t stub[4] = { 0xcf, 0xfa, 0xed, 0xfe };  // MH_MAGIC_64 LE, nothing else
    REQUIRE_THROWS_AS(
        MachOHelper::findSnapshots(stub, sizeof(stub)),
        std::invalid_argument);
}

TEST_CASE("mach-o: bogus magic is a parse error", "[macho][error]") {
    uint8_t junk[32] = {};
    junk[0] = 0x7f; junk[1] = 'E'; junk[2] = 'L'; junk[3] = 'F';
    REQUIRE_THROWS_AS(
        MachOHelper::findSnapshots(junk, sizeof(junk)),
        std::invalid_argument);
}

TEST_CASE("fat container: arm64 slice is preferred over x86_64", "[macho][fat]") {
    // Build an x86_64 slice where the symbols live at distinctive offsets so
    // we can distinguish it from the arm64 slice's pointers.
    std::vector<Section> x64_sections = {
        Section{ "__DATA_CONST", "__const", std::vector<uint8_t>(1024, 0x11) },
    };
    std::vector<Symbol> x64_symbols = {
        Symbol{ "_kDartVmSnapshotData",              0, 0x000 },
        Symbol{ "_kDartVmSnapshotInstructions",      0, 0x020 },
        Symbol{ "_kDartIsolateSnapshotData",         0, 0x040 },
        Symbol{ "_kDartIsolateSnapshotInstructions", 0, 0x060 },
    };
    ThinOpts x64_opts;
    x64_opts.cputype = CPU_TYPE_X86_64;
    auto x64 = build_thin(x64_sections, x64_symbols, x64_opts);

    auto arm = make_four_sym_arm64("_");

    auto fat = build_fat({
        { CPU_TYPE_X86_64, x64.bytes },
        { CPU_TYPE_ARM64,  arm.bytes },
    });

    LibAppInfo info = MachOHelper::findSnapshots(fat.data(), fat.size());
    const uint8_t* picked_base = static_cast<const uint8_t*>(info.lib);

    // The arm64 slice is laid out after the x86_64 slice in the FAT (align 4096);
    // picked_base should therefore land strictly past the x86_64 payload.
    REQUIRE(picked_base >  fat.data() + 4096);
    REQUIRE(picked_base <  fat.data() + fat.size());

    // And the symbol pointers should match the offsets we put in the arm64
    // slice, not the x86_64 one.
    REQUIRE(info.vm_snapshot_data              == picked_base + arm.section_file_offsets[1] + 0x100);
    REQUIRE(info.vm_snapshot_instructions      == picked_base + arm.section_file_offsets[0] + 0x200);
    REQUIRE(info.isolate_snapshot_data         == picked_base + arm.section_file_offsets[1] + 0x300);
    REQUIRE(info.isolate_snapshot_instructions == picked_base + arm.section_file_offsets[0] + 0x400);
}

TEST_CASE("fat container: falls back to first slice when no arm64", "[macho][fat]") {
    std::vector<Section> sections = {
        Section{ "__DATA_CONST", "__const", std::vector<uint8_t>(512, 0x77) },
    };
    std::vector<Symbol> symbols = {
        Symbol{ "_kDartVmSnapshotData",              0, 0x10 },
        Symbol{ "_kDartVmSnapshotInstructions",      0, 0x30 },
        Symbol{ "_kDartIsolateSnapshotData",         0, 0x50 },
        Symbol{ "_kDartIsolateSnapshotInstructions", 0, 0x70 },
    };
    ThinOpts x64_opts;
    x64_opts.cputype = CPU_TYPE_X86_64;
    auto thin = build_thin(sections, symbols, x64_opts);
    auto fat = build_fat({ { CPU_TYPE_X86_64, thin.bytes } });

    LibAppInfo info = MachOHelper::findSnapshots(fat.data(), fat.size());
    REQUIRE(info.vm_snapshot_data != nullptr);
    REQUIRE(info.vm_snapshot_instructions != nullptr);
    REQUIRE(info.isolate_snapshot_data != nullptr);
    REQUIRE(info.isolate_snapshot_instructions != nullptr);
}

TEST_CASE("IsMachO: thin and fat are both recognised, ELF is not", "[macho][magic]") {
    auto built = make_four_sym_arm64("_");
    REQUIRE(MachOHelper::IsMachO(built.bytes.data(), built.bytes.size()));

    auto fat = build_fat({ { CPU_TYPE_ARM64, built.bytes } });
    REQUIRE(MachOHelper::IsMachO(fat.data(), fat.size()));

    uint8_t elf[8] = { 0x7f, 'E', 'L', 'F', 0, 0, 0, 0 };
    REQUIRE_FALSE(MachOHelper::IsMachO(elf, sizeof(elf)));

    uint8_t short_buf[2] = { 0xcf, 0xfa };
    REQUIRE_FALSE(MachOHelper::IsMachO(short_buf, sizeof(short_buf)));
}
