#pragma once
#include "DartApp.h"

// Writes a minimal DWARF-5 debug file (ELF64/aarch64 container) containing
// function names + addresses as DW_TAG_subprogram DIEs plus an ELF .symtab
// of STT_FUNC symbols. Intended to be loaded by gdb/lldb as a "separate
// debug file" alongside libapp.so. Addresses are emitted as entry-point
// offsets within libapp (i.e. relative to the image base), matching how
// the symbols in the main ELF would appear.
class DwarfWriter
{
public:
	DwarfWriter(DartApp& app) : app(app) {}
	void Create(const char* filename);

private:
	DartApp& app;
};
