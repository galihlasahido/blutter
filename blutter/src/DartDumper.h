#pragma once
#include "DartApp.h"
#include <filesystem>

class DartDumper
{
public:
	DartDumper(DartApp& app) : app(app) {};

	void Dump4Ida(std::filesystem::path outDir);
	// Emits a Ghidra Jython script (`blutter_ghidra.py`) that applies the
	// same symbol set + Dart struct definitions as the IDA output. The Dart
	// struct source is embedded directly in the script so it can be run
	// standalone in Ghidra.
	void Dump4Ghidra(std::filesystem::path outDir);

	std::vector<std::pair<intptr_t, std::string>> DumpStructHeaderFile(std::string outFile);

	void DumpCode(const char* out_dir);

	void DumpObjectPool(const char* filename);
	void DumpObjects(const char* filename);

	// JSON export — schema_version 1.
	// Emits a structured equivalent of pp.txt / objs.txt so downstream tools
	// (Ghidra scripts, custom analyzers) can iterate entries without parsing
	// the free-form text output.
	void DumpObjectPoolJson(const char* filename);
	void DumpObjectsJson(const char* filename);

	// Structured function signatures (Iter 6 — Type inference surface).
	// Emits functions.json: one record per unique function with addr, name,
	// class, library, flags, return_type, and a params[] array
	// ({name, type, required}). Provides a machine-readable view of the
	// signature data already walked in DartApp::finalizeFunctionsInfo.
	void DumpFunctionsJson(const char* filename);

	// SQLite export (text SQL form). Emits blutter.db.sql: CREATE TABLE
	// statements for `objects`, `pool`, and `functions`, plus INSERTs wrapped
	// in a single transaction. blutter.py converts this into blutter.db via
	// stdlib sqlite3 so we don't need to link the sqlite3 C library here.
	void DumpSqlite(const char* filename);

	std::string ObjectToString(dart::Object& obj, bool simpleForm = false, bool nestedObj = false, int depth = 0);

private:
	std::string getPoolObjectDescription(intptr_t offset, bool simpleForm = true);

	std::string dumpInstance(dart::Object& obj, bool simpleForm = false, bool nestedObj = false, int depth = 0);
	std::string dumpInstanceFields(dart::Object& obj, DartClass& dartCls, intptr_t ptr, intptr_t offset, bool simpleForm = false, bool nestedObj = false, int depth = 0);

	void applyStruct4Ida(std::ostream& of);
	std::vector<std::pair<intptr_t, std::string>> buildStructHeader(std::ostream& of);

	const std::string& getQuoteString(dart::Object& obj);

	DartApp& app;
	// map for object ptr to unescape string with quote
	std::unordered_map<intptr_t, std::string> quoteStringCache;
};
