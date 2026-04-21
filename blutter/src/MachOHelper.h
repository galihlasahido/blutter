#pragma once
// --- Iteration 4 WIP ---------------------------------------------------------
// Mach-O counterpart to ElfHelper. Parses a mapped iOS Flutter App binary and
// locates the four Dart snapshot symbols. Currently NOT wired into DartApp /
// DartLoader — only the metadata-extraction path (Python) consumes iOS today.
//
// Remaining work before hookup (tracked in plan.md Iteration 4):
//   * arm64e pointer-authentication bit stripping on ObjectPtr values
//   * DartApp base()/heap_base() derivation for Mach-O
//   * Dispatch in DartLoader on magic so ELF and Mach-O share the same
//     DartApp entry point
// -----------------------------------------------------------------------------
#include <stddef.h>
#include <stdint.h>
#include "ElfHelper.h"  // for LibAppInfo

class MachOHelper final
{
public:
	// Detect whether `data` starts with a supported Mach-O magic (thin 64-bit
	// little-endian or FAT container). Returns true if MapLibApp() can handle it.
	static bool IsMachO(const uint8_t* data, size_t size);

	// Parse a mapped Mach-O binary and return the four Dart snapshot pointers.
	// Throws std::invalid_argument on any structural error.
	// For FAT containers, the arm64 slice is preferred; falls back to the first
	// slice if arm64 is not present.
	static LibAppInfo findSnapshots(const uint8_t* data, size_t size);

	// Memory-map `path` and delegate to findSnapshots.
	static LibAppInfo MapLibApp(const char* path);

private:
	MachOHelper() = delete;
};
