#include "pch.h"
#include "DartDumper.h"
#include <fstream>
#include <format>
#include <set>
#include <ranges>
#include <iostream>
#include <sstream>
#include <numeric>
#include "Disassembler.h"
#include "DartThreadInfo.h"
#include "CodeAnalyzer.h"

// TODO: move arm64 specific code to *_arm64 file

static std::unordered_map<std::string, std::string> OP_MAP {
	{ "==", "eq" },
	{ "<", "lt" }, { ">", "gt" },
	{ "<=", "lte" }, { ">=", "gte" },
	{ "=", "assign" },
	{ "[]", "at" }, { "[]=", "at_assign" },
	{ "++", "increment" }, { "--", "decrement" },
	{ "+", "add" }, { "-", "sub" }, { "*", "mul" }, { "~/", "div" }, { "/", "divf" },
	{ "%", "mod" },
	{ "&", "LAnd" }, { "|", "LOr" }, { "^", "xor" }, { "~", "not" }, {">>", "shar"}, {"<<", "shal"}, {">>", "shr"}
};

static std::string getFunctionName4Ida(const DartFunction& dartFn, const std::string& cls_prefix)
{
	auto fnName = dartFn.Name();
	if (dartFn.IsClosure() && fnName == "<anonymous closure>") {
		return "_anon_closure";
	}

	auto periodPos = fnName.find('.');
	std::string prefix;
	if (dartFn.IsStatic() && dartFn.Kind() == DartFunction::NORMAL && periodPos != std::string::npos) {
		// this one is extension
		prefix = fnName.substr(0, periodPos + 1);
		if (prefix.starts_with("_extension#")) {
			// anonymous extension. '#' is invalid name in IDA.
			std::replace(prefix.begin(), prefix.end(), '#', '@');
		}
		fnName = fnName.substr(periodPos + 1);
	}

	if (OP_MAP.contains(fnName)) {
		return prefix + "op_" + OP_MAP[fnName];
	}
	const auto last = fnName.back();
	if (last == '=') {
		fnName.pop_back();
		return prefix + fnName + "_assign";
	}
	else if (last == '-') {
		fnName.pop_back();
		return prefix + fnName + "_neg";
	}
	else if (last == '!') {
		fnName.pop_back();
		return prefix + fnName + "_not";
	}

	switch (dartFn.Kind()) {
	case DartFunction::CONSTRUCTOR: {
		std::string name = dartFn.IsStatic() ? "factory_ctor" : "ctor";
		ASSERT(fnName.starts_with(cls_prefix));
		if (fnName[cls_prefix.length()] == '.') {
			name += '_';
			name += &fnName[cls_prefix.length() + 1];
		}
		return name;
	}
	case DartFunction::SETTER:
		return "set_" + fnName;
	case DartFunction::GETTER:
		return "get_" + fnName;
	default:
		break;
	}

	return prefix + fnName;
}

void DartDumper::Dump4Ida(std::filesystem::path outDir)
{
	std::filesystem::create_directory(outDir);
	std::ofstream of((outDir / "addNames.py").string());
	of << "import ida_funcs\n";
	of << "import idaapi\n\n";

	for (auto lib : app.libs) {
		std::string lib_prefix = lib->GetName();
		for (auto cls : lib->classes) {
			std::string cls_prefix = cls->Name();
			for (auto dartFn : cls->Functions()) {
				const auto ep = dartFn->Address();
				auto name = getFunctionName4Ida(*dartFn, cls_prefix);
				of << std::format("ida_funcs.add_func({:#x}, {:#x})\n", ep, ep + dartFn->Size());
				of << std::format("idaapi.set_name({:#x}, \"{}_{}::{}_{:x}\")\n", ep, lib_prefix, cls_prefix, name.c_str(), ep);
				if (dartFn->HasMorphicCode()) {
					of << std::format("idaapi.set_name({:#x}, \"{}_{}::{}_{:x}_miss\")\n", dartFn->PayloadAddress(), lib_prefix, cls_prefix, name.c_str(), ep);
					of << std::format("idaapi.set_name({:#x}, \"{}_{}::{}_{:x}_check\")\n", dartFn->MonomorphicAddress(), lib_prefix, cls_prefix, name.c_str(), ep);
				}
			}
		}
	}

	for (auto& item : app.stubs) {
		auto stub = item.second;
		const auto ep = stub->Address();
		auto name = stub->FullName();
		std::replace(name.begin(), name.end(), '<', '@');
		std::replace(name.begin(), name.end(), '>', '@');
		std::replace(name.begin(), name.end(), ',', '&');
		std::replace(name.begin(), name.end(), ' ', '_');
		of << std::format("idaapi.set_name({:#x}, \"{}_{:x}\")\n", ep, name.c_str(), ep);
		if (stub->Size() == 0)
			continue;
		of << std::format("ida_funcs.add_func({:#x}, {:#x})\n", ep, ep + stub->Size());
	}


	// Note: create struct with a lot of member by ida script is very slow
	//   use header file then adding comment is much faster
	auto comments = DumpStructHeaderFile((outDir / "ida_dart_struct.h").string());
	of << R"CBLOCK(
import ida_struct
import os
def create_Dart_structs():
	sid1 = idc.get_struc_id("DartThread")
	if sid1 != idc.BADADDR:
		return sid1, idc.get_struc_id("DartObjectPool")
	hdr_file = os.path.join(os.path.dirname(__file__), 'ida_dart_struct.h')
	idaapi.idc_parse_types(hdr_file, idc.PT_FILE)
	sid1 = idc.import_type(-1, "DartThread")
	sid2 = idc.import_type(-1, "DartObjectPool")
	struc = ida_struct.get_struc(sid2)
)CBLOCK";
	for (const auto& [offset, comment] : comments) {
		of << "\tida_struct.set_member_cmt(ida_struct.get_member(struc, " << offset << "), '''" << comment << "''', True)\n";
	}
	of << "\treturn sid1, sid2\n";
	of << "thrs, pps = create_Dart_structs()\n";

	of << "print('Applying Thread and Object Pool struct')\n";
	applyStruct4Ida(of);

	of << "print('Script finished!')\n";
}

// Ghidra Jython script. Mirrors Dump4Ida's symbol output for Ghidra users:
// creates functions + labels, imports the DartThread / DartObjectPool struct
// types into the program's DataTypeManager, and attaches object-pool entry
// descriptions as struct-member comments.
//
// The Dart struct C source is embedded inline (as a Python triple-quoted
// string) so the script is self-contained; it does not depend on the
// ida_script directory.
//
// Per-instruction THR/PP operand-to-struct-member rewrites (the equivalent
// of IDA's `idc.op_stroff` pass) are deliberately skipped in this first cut
// to keep the generated script a manageable size. The struct types are
// imported into the DTM so users can apply them manually, or a follow-up
// pass can emit EOL comments from a precomputed (insn_addr, field_off) list.
void DartDumper::Dump4Ghidra(std::filesystem::path outDir)
{
	std::filesystem::create_directory(outDir);
	std::ofstream of((outDir / "blutter_ghidra.py").string());

	of << "# blutter_ghidra.py --- generated by Blutter\n";
	of << "# Applies Dart function names, stubs, and struct types to libapp.\n";
	of << "# Run inside Ghidra (Script Manager) after initial auto-analysis.\n";
	of << "# @category Blutter\n";
	of << "# @runtime Jython\n\n";

	of << "from ghidra.program.model.symbol import SourceType\n";
	of << "from ghidra.program.model.listing import CodeUnit\n";
	of << "from ghidra.app.util.cparser.C import CParser\n\n";

	of << "BASE = currentProgram.getImageBase()\n";
	of << "LISTING = currentProgram.getListing()\n";
	of << "DTM = currentProgram.getDataTypeManager()\n\n";

	of << "def _addr(off):\n";
	of << "    return BASE.add(off)\n\n";

	of << "def _apply_function(off, size, name):\n";
	of << "    addr = _addr(off)\n";
	of << "    try:\n";
	of << "        fn = getFunctionAt(addr)\n";
	of << "        if fn is None:\n";
	of << "            disassemble(addr)\n";
	of << "            fn = createFunction(addr, name)\n";
	of << "        if fn is not None:\n";
	of << "            fn.setName(name, SourceType.USER_DEFINED)\n";
	of << "    except Exception as e:\n";
	of << "        print('  fn %s @ %s: %s' % (name, addr, e))\n\n";

	of << "def _apply_label(off, name):\n";
	of << "    try:\n";
	of << "        createLabel(_addr(off), name, True, SourceType.USER_DEFINED)\n";
	of << "    except Exception as e:\n";
	of << "        print('  label %s @ %s: %s' % (name, hex(off), e))\n\n";

	// Functions: (offset, size, fq_name). Entries from classes, stubs later.
	// For functions with a monomorphic entry point, emit the main label at
	// the canonical entry and two extra labels for the _miss / _check
	// addresses, matching what Dump4Ida produces.
	of << "FUNCS = [\n";
	for (auto lib : app.libs) {
		std::string lib_prefix = lib->GetName();
		for (auto cls : lib->classes) {
			std::string cls_prefix = cls->Name();
			for (auto dartFn : cls->Functions()) {
				const auto ep = dartFn->Address();
				auto name = getFunctionName4Ida(*dartFn, cls_prefix);
				of << std::format("    ({:#x}, {:#x}, \"{}_{}::{}_{:x}\"),\n",
					ep, dartFn->Size(), lib_prefix, cls_prefix, name.c_str(), ep);
			}
		}
	}
	of << "]\n\n";

	of << "EXTRA_LABELS = [\n";
	for (auto lib : app.libs) {
		std::string lib_prefix = lib->GetName();
		for (auto cls : lib->classes) {
			std::string cls_prefix = cls->Name();
			for (auto dartFn : cls->Functions()) {
				if (!dartFn->HasMorphicCode())
					continue;
				const auto ep = dartFn->Address();
				auto name = getFunctionName4Ida(*dartFn, cls_prefix);
				of << std::format("    ({:#x}, \"{}_{}::{}_{:x}_miss\"),\n",
					dartFn->PayloadAddress(), lib_prefix, cls_prefix, name.c_str(), ep);
				of << std::format("    ({:#x}, \"{}_{}::{}_{:x}_check\"),\n",
					dartFn->MonomorphicAddress(), lib_prefix, cls_prefix, name.c_str(), ep);
			}
		}
	}
	of << "]\n\n";

	// Stubs: size==0 means label only (no function body / unknown size).
	of << "STUBS = [\n";
	for (auto& item : app.stubs) {
		auto stub = item.second;
		const auto ep = stub->Address();
		auto name = stub->FullName();
		std::replace(name.begin(), name.end(), '<', '@');
		std::replace(name.begin(), name.end(), '>', '@');
		std::replace(name.begin(), name.end(), ',', '&');
		std::replace(name.begin(), name.end(), ' ', '_');
		of << std::format("    ({:#x}, {:#x}, \"{}_{:x}\"),\n",
			ep, stub->Size(), name.c_str(), ep);
	}
	of << "]\n\n";

	// Embedded Dart struct source. We stringify via a triple-quoted raw
	// Python literal. The contents are identical to ida_dart_struct.h so
	// this script can be run standalone without the IDA output sitting
	// alongside it.
	std::stringstream structSrc;
	auto comments = buildStructHeader(structSrc);
	of << "DART_STRUCT_SRC = r\"\"\"\n";
	of << structSrc.str();
	of << "\"\"\"\n\n";

	// Member comments: one triple-single-quoted entry per pool field with a
	// human-readable object description. Keyed by byte offset into the
	// DartObjectPool struct.
	of << "POOL_COMMENTS = {\n";
	for (const auto& [offset, comment] : comments) {
		// Escape triple quotes by inserting a zero-width separator; in
		// practice Dart ObjectPool descriptions don't contain them, but
		// this keeps the script robust against unusual payloads.
		std::string safe = comment;
		size_t pos = 0;
		while ((pos = safe.find("'''", pos)) != std::string::npos) {
			safe.replace(pos, 3, "''\\'");
			pos += 4;
		}
		of << "    " << offset << ": '''" << safe << "''',\n";
	}
	of << "}\n\n";

	of << "def _find_struct(name):\n";
	of << "    # CParser may register both a Structure and a TypeDef for\n";
	of << "    # `typedef struct X { ... } X;`. Prefer the Structure so we can\n";
	of << "    # set member comments directly.\n";
	of << "    from ghidra.program.model.data import Structure\n";
	of << "    it = DTM.getAllStructures()\n";
	of << "    while it.hasNext():\n";
	of << "        dt = it.next()\n";
	of << "        if dt.getName() == name:\n";
	of << "            return dt\n";
	of << "    return None\n\n";

	of << "def _import_structs():\n";
	of << "    try:\n";
	of << "        parser = CParser(DTM)\n";
	of << "        parser.parse(DART_STRUCT_SRC)\n";
	of << "    except Exception as e:\n";
	of << "        print('  CParser failed:', e)\n";
	of << "        return None, None\n";
	of << "    thr = _find_struct('DartThread')\n";
	of << "    pp  = _find_struct('DartObjectPool')\n";
	of << "    if pp is not None:\n";
	of << "        applied = 0\n";
	of << "        for off, cmt in POOL_COMMENTS.items():\n";
	of << "            member = pp.getComponentAt(off)\n";
	of << "            if member is not None:\n";
	of << "                member.setComment(cmt)\n";
	of << "                applied += 1\n";
	of << "        print('  applied %d pool comments.' % applied)\n";
	of << "    return thr, pp\n\n";

	of << "def apply_all():\n";
	of << "    print('Blutter: applying %d functions...' % len(FUNCS))\n";
	of << "    for off, size, name in FUNCS:\n";
	of << "        _apply_function(off, size, name)\n";
	of << "    print('Blutter: applying %d extra labels (miss/check)...' % len(EXTRA_LABELS))\n";
	of << "    for off, name in EXTRA_LABELS:\n";
	of << "        _apply_label(off, name)\n";
	of << "    print('Blutter: applying %d stubs...' % len(STUBS))\n";
	of << "    for off, size, name in STUBS:\n";
	of << "        if size > 0:\n";
	of << "            _apply_function(off, size, name)\n";
	of << "        else:\n";
	of << "            _apply_label(off, name)\n";
	of << "    print('Blutter: importing Dart struct types...')\n";
	of << "    thr, pp = _import_structs()\n";
	of << "    if thr is not None: print('  DartThread ready.')\n";
	of << "    if pp  is not None: print('  DartObjectPool ready (%d pool comments).' % len(POOL_COMMENTS))\n\n";

	of << "apply_all()\n";
	of << "print('Blutter: done.')\n";
}

std::vector<std::pair<intptr_t, std::string>> DartDumper::DumpStructHeaderFile(std::string outFile)
{
	std::ofstream of(outFile);
	return buildStructHeader(of);
}

std::vector<std::pair<intptr_t, std::string>> DartDumper::buildStructHeader(std::ostream& of)
{
	const auto max_offset = GetThreadMaxOffset();
	auto padNo = 0;
	of << "typedef struct DartThread {\n";
	for (intptr_t i = 0; i <= max_offset; i += 8) {
		auto& name = GetThreadOffsetName((int)i);
		if (name.empty()) {
			of << "\t__int64 pad" << std::hex << padNo << ";\n";
			padNo++;
		}
		else {
			of << "\t__int64 " << name << ";\n";
		}
	}
	of << "} DartThread;\n";

	of << "typedef struct DartObjectPool {\n";
	of << "\t__int64 pad0;\n";
	of << "\t__int64 pad1;\n";

	std::vector<std::pair<intptr_t, std::string>> comments;
	const auto& pool = app.GetObjectPool();
	intptr_t num = pool.Length();

	auto& obj = dart::Object::Handle();
	for (intptr_t i = num - 1; i >= 0; i--) {
		// the Dart Code access ObjectPool with offset that is not subtract by kHeapObjectTag (1)
		//   so we have to add 1 to make the offset same as offset in the code
		intptr_t offset = dart::ObjectPool::OffsetFromIndex(i) + 1;
		std::string name;

		auto objType = pool.TypeAt(i);
		if (objType == dart::ObjectPool::EntryType::kTaggedObject) {
			obj = pool.ObjectAt(i);
			if (obj.IsUnlinkedCall()) {
				// since Dart 3.10, target type might be kTaggedObject
				auto unlinkTargetType = pool.TypeAt(i + 1);
				if (unlinkTargetType == dart::ObjectPool::EntryType::kImmediate) {
					const auto imm = pool.RawValueAt(i + 1);
					auto dartFn = app.GetFunction(imm - app.base());
					if (dartFn == nullptr) {
						name = std::format("UnlinkedCall_{:#x}_unresolved_{:#x}", offset, imm - app.base());
					} else {
						name = std::format("UnlinkedCall_{:#x}_{:#x}", offset, dartFn->Address());
					}
				}
				else {
					ASSERT(unlinkTargetType == dart::ObjectPool::EntryType::kTaggedObject);
					const auto imm = pool.RawValueAt(i + 1);
					name = std::format("UnlinkedCall_{:#x}_tagged_{:#x}", offset, imm - app.base());
				}
			}
			else {
				// TODO: more meaningful variable name
				name = std::format("Obj_{:#x}", offset);
				auto comment = ObjectToString(obj);
				comments.push_back(std::make_pair(offset, comment));
			}
		}
		else if (objType == dart::ObjectPool::EntryType::kImmediate) {
			name = std::format("IMM_{:#x}_{:#x}", pool.RawValueAt(i), offset);
		}
		else if (objType == dart::ObjectPool::EntryType::kNativeFunction) {
			// the name of NativeFunction can be retrieved from dart::NativeSymbolResolver::LookupSymbolName
			//   but normally flutter code never access it
			// if we use the name, we should cache it because many Pool Objects reference same NativeFunction
			name = std::format("NativeFn_{:#x}_{:#x}", pool.RawValueAt(i), offset);
		}
		else {
			name = std::format("RAW_{:#x}_{:#x}", pool.RawValueAt(i), offset);
		}

		of << "\t__int64 " << name << ";\n";
	}

	of << "} DartObjectPool;\n";

	return comments;
}

void DartDumper::applyStruct4Ida(std::ostream& of)
{
	Disassembler disasmer;

	of << "import ida_ua\n";
	of << "insn = ida_ua.insn_t()\n";

	for (auto lib : app.libs) {
		if (lib->isInternal)
			continue;

		for (auto dartCls : lib->classes) {
			for (auto dartFn : dartCls->Functions()) {
				if (dartFn->PayloadSize() == 0)
					continue;

				auto insns = disasmer.Disasm((uint8_t*)dartFn->PayloadAddress() + app.base(), dartFn->PayloadSize(), dartFn->Address());

				for (uint32_t i = 0; i < insns.Count(); i++) {
					auto insn = insns.At(i);
					const auto op_count = insn.op_count();

					for (uint8_t j = 0; j < op_count; j++) {
						auto reg = ARM64_REG_INVALID;
						if (insn.ops[j].type == ARM64_OP_REG)
							reg = insn.ops[j].reg;
						else if (insn.ops[j].type == ARM64_OP_MEM)
							reg = insn.ops[j].mem.base;
						if (reg == CSREG_DART_THR) {
							of << "ida_ua.decode_insn(insn, " << insn.address() << ")\n";
							of << "idc.op_stroff(insn, " << (int)j << ", thrs, 0)\n";
							break;
						}
						else if (reg == CSREG_DART_PP) {
							// TODO: if it is not MEM operand, reg cannot be struct offset
							of << "ida_ua.decode_insn(insn, " << insn.address() << ")\n";
							of << "idc.op_stroff(insn, " << (int)j << ", pps, 0)\n";
							break;
						}
					}
				}
			}
		}
	}
}

const std::string& DartDumper::getQuoteString(dart::Object& obj)
{
	const auto ptr = (intptr_t)obj.ptr();
	auto& txt = quoteStringCache[ptr];
	// because string is always quotes, empty string means inserting a new one
	if (txt.empty()) {
		txt = Util::UnescapeWithQuote(obj.ToCString());
	}
	return txt;
}

void DartDumper::DumpCode(const char* out_dir)
{
	std::filesystem::create_directory(out_dir);

	Disassembler disasmer;

	for (auto dartLib : app.libs) {
		if (dartLib->isInternal)
			continue;

		auto out_file = dartLib->CreatePath(out_dir);
		std::ofstream of(out_file);
		dartLib->PrintCommentInfo(of);

		for (auto dartCls : dartLib->classes) {
			dartCls->PrintHead(of);

			if (!dartCls->Fields().empty())
				of << "\n";
			for (auto dartField : dartCls->Fields()) {
				dartField->Print(of);
			}

			if (!dartCls->Functions().empty())
				of << "\n";
			for (auto dartFn : dartCls->Functions()) {
				dartFn->PrintHead(of);

#ifndef NO_CODE_ANALYSIS
				// use as app is loaded at zero
				if (dartFn->Size() > 0) {
					auto& asmTexts = dartFn->GetAnalyzedData()->asmTexts.Data();
					auto& il_insns = dartFn->GetAnalyzedData()->il_insns;
					auto il_itr = il_insns.begin();
					AddrRange range;
					ASSERT(!asmTexts.empty());
					for (auto& asmText : asmTexts) {
						std::string extra;
						switch (asmText.dataType) {
						case AsmText::ThreadOffset:
							extra = "THR::" + GetThreadOffsetName(asmText.threadOffset);
							break;
						case AsmText::PoolOffset:
							extra = getPoolObjectDescription(asmText.poolOffset);
							break;
						case AsmText::Boolean:
							extra = asmText.boolVal ? "true" : "false";
							break;
						case AsmText::Call: {
							auto* fn = app.GetFunction(asmText.callAddress);
							if (fn) {
								extra = fn->FullName();
								auto retCid = fn->ReturnType();
								if (retCid != dart::kIllegalCid) {
									auto retCls = app.classes.at(retCid);
									extra += std::format(" -> {} (size={:#x})", retCls->FullName(), retCls->Size());
								}
							}
							break;
						}
						}

						of << "    // ";

						if (range.Has(asmText.addr)) {
							of << "    ";
						}
						else {
							while ((*il_itr)->Start() < asmText.addr) {
								if ((*il_itr)->Kind() != ILInstr::Unknown) {
									of << std::format("{:#x}: {}\n", (*il_itr)->Start(), (*il_itr)->ToString());
									of << "    // ";
								}
								++il_itr;
							}
							if ((*il_itr)->Start() == asmText.addr) {
								if ((*il_itr)->Kind() != ILInstr::Unknown) {
									of << std::format("{:#x}: {}\n", asmText.addr, (*il_itr)->ToString());
									of << "    //     ";
									range = (*il_itr)->Range();
								}
								++il_itr;
							}
						}

						if (extra.empty())
							of << std::format("{:#x}: {}\n", asmText.addr, &asmText.text[0]);
						else
							of << std::format("{:#x}: {}  ; {}\n", asmText.addr, &asmText.text[0], extra);
					}
				}
#endif // NO_CODE_ANALYSIS

				dartFn->PrintFoot(of);
			}

			dartCls->PrintFoot(of);
		}
	}
}

// collect instance ptr to dump the full contents in DumpObjects()
static std::set<intptr_t> knownObjectPtrs;

std::string DartDumper::ObjectToString(dart::Object& obj, bool simpleForm, bool nestedObj, int depth)
{
	const auto cid = obj.GetClassId();
	//auto dartCls = app_.classes[obj.GetClassId()];

	if (obj.IsString()) {
		auto& val = getQuoteString(obj);
		if (simpleForm || depth > 0)
			return val;
		return "String: " + val;
	}

	// use TypedData or TypedDataBase ?
	if (obj.IsTypedData()) {
		//dart::kTypedDataInt32ArrayCid;
		auto& arr = dart::TypedData::Cast(obj);
		const auto arr_len = arr.Length();
		auto ptr = arr.DataAddr(0);
		std::string txt;
		if (arr_len > 0) {
			switch (arr.ElementType()) {
#define ACCUMLATE(type) { \
	auto data = (type*)ptr; \
	txt = std::accumulate(data + 1, data + arr_len, std::format("[{:#x}", data[0]), [](std::string x, type y) { return x + ", " + std::format("{:#x}", y); } ); \
}
			case dart::kInt8ArrayElement:
				ACCUMLATE(int8_t);
				break;
			case dart::kUint8ArrayElement:
			case dart::kUint8ClampedArrayElement:
				ACCUMLATE(uint8_t);
				break;
			case dart::kInt16ArrayElement:
				ACCUMLATE(int16_t);
				break;
			case dart::kUint16ArrayElement:
				ACCUMLATE(uint16_t);
				break;
			case dart::kInt32ArrayElement:
				ACCUMLATE(int32_t);
				break;
			case dart::kUint32ArrayElement:
				ACCUMLATE(uint32_t);
				break;
			case dart::kInt64ArrayElement:
				ACCUMLATE(int64_t);
				break;
			case dart::kUint64ArrayElement:
				ACCUMLATE(uint64_t);
				break;
#undef ACCUMLATE
#define ACCUMLATE(type) { \
	auto data = (type*)ptr; \
	txt = std::accumulate(data + 1, data + arr_len, std::format("[{}", data[0]), [](std::string x, type y) { return x + ", " + std::format("{}", y); } ); \
}
			case dart::kFloat32ArrayElement:
				ACCUMLATE(float);
				break;
			case dart::kFloat64ArrayElement:
				ACCUMLATE(double);
				break;
#undef ACCUMLATE
			case dart::kFloat32x4ArrayElement:
			case dart::kInt32x4ArrayElement:
			case dart::kFloat64x2ArrayElement:
				FATAL("TODO: simd array");
			}

			txt += ']';
		}
		//arr.ElementSizeInBytes();
		return std::format("{}({}) {}", app.GetClass(cid)->Name(), arr_len, txt);
	}

	switch (cid) {
	case dart::kSmiCid:
		if (simpleForm || depth > 0)
			return std::format("{:#x}", dart::Smi::Cast(obj).Value());
		return std::format("Smi: {:#x}", dart::Smi::Cast(obj).Value());
	case dart::kMintCid:
		if (simpleForm || depth > 0)
			return std::format("{:#x}", MintValue(dart::Mint::Cast(obj)));
		return std::format("Mint: {:#x}", MintValue(dart::Mint::Cast(obj)));
	case dart::kDoubleCid:
		if (simpleForm || depth > 0)
			return std::format("{}", dart::Double::Cast(obj).value());
		return std::format("Double: {}", dart::Double::Cast(obj).value());
	case dart::kBoolCid:
		return dart::Bool::Cast(obj).value() ? "true" : "false";
	case dart::kNullCid:
		return "Null";
	case dart::kSentinelCid:
		return "Sentinel";
	case dart::kSubtypeTestCacheCid:
		return "SubtypeTestCache";
	case dart::kFunctionCid: {
		// stub never be in Object Pool
		auto fnBase = app.GetFunction(dart::Function::Cast(obj).entry_point() - app.base());
		if (fnBase == nullptr) {
			// Same dedup_instructions edge case as the UnlinkedCall path: the
			// entry point points into a code blob that isn't registered.
			return std::format("Function: [unresolved] ({:#x})",
				dart::Function::Cast(obj).entry_point() - app.base());
		}
		auto dartFn = fnBase->AsFunction();
		if (dartFn->IsClosure()) {
			auto parentFn = dartFn->GetOutermostFunction();
			if (parentFn) {
				// AOT anonymous closure contains only static information
				return std::format("AnonymousClosure: {}({:#x}), in {} ({:#x})",
					dartFn->IsStatic() ? "static " : "", dartFn->Address(),
					parentFn->FullName(), parentFn->Address());
			}
			else {
				return std::format("AnonymousClosure: {}({:#x}), of {}",
					dartFn->IsStatic() ? "static " : "", dartFn->Address(),
					dartFn->Class().FullNameWithPackage());
			}
		}
		return std::format("Function: {} ({:#x})", dartFn->FullName(), dartFn->Address());
	}
	case dart::kClosureCid: {
		// TODO: show owner
		const auto& closure = dart::Closure::Cast(obj);
		if (!app.functions.contains(closure.entry_point() - app.base())) {
			std::cout << std::format("[!] missing closure at {:#x}\n", closure.entry_point() - app.base());
		}
		//RELEASE_ASSERT(app.functions.contains(closure.entry_point() - app.base()));
		return std::format("{} ({:#x})", closure.ToCString(), closure.entry_point());
	}
	case dart::kCodeCid: {
		const auto& code = dart::Code::Cast(obj);
		const auto ep = code.EntryPoint() - app.base();
		if (app.stubs.contains(ep)) {
			const auto stub = app.stubs[ep];
			return std::format("Stub: {} ({:#x})", stub->Name().c_str(), ep);
		}
		return std::format("Code: {} ({:#x})", code.ToCString(), ep);
	}
	case dart::kArrayCid:
	case dart::kImmutableArrayCid: {
		// Note: since Dart 3.7, Ojbect Pool is mutable. so, Array is used too
		// Objects in Object Pool immutable, so only immutable array is used for array
		// Most of no type arguments in Object Pool are Argument Descriptor
		const auto& arr = dart::Array::Cast(obj);
		const auto arr_len = arr.Length();
		const auto typeArg = app.typeDb->FindOrAdd(arr.GetTypeArguments());
		// without type arguments, assume it is argument descriptor. show it even simple form is true.
		if (simpleForm && typeArg->Length() > 0)
			return std::format("List{}({})", typeArg->ToString(), arr_len);

		std::ostringstream ss;
		if (arr_len > 0) {
			// in ImmutableList here, only Dart type (native type is not used)
			auto arrPtr = dart::Array::DataOf(arr.ptr());
			for (intptr_t i = 0; i < arr_len; i++) {
				if (i != 0)
					ss << ", ";

				if (arrPtr->IsHeapObject()) {
					obj = arrPtr->Decompress(app.heap_base());
					ss << ObjectToString(obj, simpleForm, nestedObj, depth + 1);
				}
				else {
					obj = arrPtr->DecompressSmi();
					ss << std::hex << std::showbase << dart::Smi::Cast(obj).Value();
				}
				arrPtr++;
			}
		}
		return std::format("List{}({}) [{}]", typeArg->ToString(), arr_len, ss.str());
	}
#ifdef HAS_RECORD_TYPE
	case dart::kRecordCid: {
		const auto& record = dart::Record::Cast(obj);
		std::ostringstream ss;
		const auto type = app.typeDb->FindOrAdd(DartGetRecordType(record));
		ss << "Record" << type->ToString() << " = (";
		auto& field = dart::Object::Handle();
		const auto num_fields = record.num_fields();
		for (intptr_t i = 0; i < num_fields; i++) {
			if (i != 0) ss << ", ";
			field = record.FieldAt(i);
			ss << ObjectToString(field, simpleForm, nestedObj, depth + 1);
		}
		ss << ")";
		return ss.str();
	}
#endif
	case dart::kTypeArgumentsCid:
		return "TypeArguments: " + app.typeDb->FindOrAdd(dart::TypeArguments::RawCast(obj.ptr()))->ToString();
	case dart::kTypeCid:
		return "Type: " + app.typeDb->FindOrAdd(dart::Type::RawCast(obj.ptr()))->ToString();
#ifdef HAS_RECORD_TYPE
	case dart::kRecordTypeCid:
		return "RecordType: " + app.typeDb->FindOrAdd(dart::RecordType::RawCast(obj.ptr()))->ToString();
#endif
	case dart::kTypeParameterCid:
		return "TypeParameter: " + app.typeDb->FindOrAdd(dart::TypeParameter::RawCast(obj.ptr()))->ToString();
	case dart::kFunctionTypeCid:
		return "FunctionType: " + app.typeDb->FindOrAdd(dart::FunctionType::RawCast(obj.ptr()))->ToString();
#ifdef HAS_TYPE_REF
	case dart::kTypeRefCid:
#endif
	case dart::kTypeParametersCid:
		// might be in a Type but not in Object Pool directly
		return std::format("{} (ptr: {:#x})", obj.ToCString(), (uint64_t)obj.ptr());
	case dart::kFieldCid: {
		const auto& field = dart::Field::Cast(obj);
		return std::format("{} (offset: {:#x})", field.ToCString(), field.TargetOffset());
	}
	case dart::kConstMapCid: {
		auto& map = dart::Map::Cast(obj);
		const auto typeArg = app.typeDb->FindOrAdd(map.GetTypeArguments());
		if (simpleForm)
			return std::format("Map{}({})", typeArg->ToString(), map.Length());

		std::ostringstream ss;
		std::string indent(depth * 2 + 2, ' ');
		ss << std::format("Map{}({}) {{\n", typeArg->ToString(), map.Length());
		dart::Map::Iterator iter(map);
		auto& key = dart::Object::Handle();
		auto& val = dart::Object::Handle();
		int cnt = 0;
		while (iter.MoveNext()) {
			if (cnt++) ss << ",\n";
			key = iter.CurrentKey();
			val = iter.CurrentValue();
			// key always be simple form
			ss << indent << ObjectToString(key, true, false, depth + 1) << ": " << ObjectToString(val, simpleForm, nestedObj, depth + 1);
		}
		if (cnt) ss << "\n";
		ss << std::string(depth * 2, ' ') << "}";
		return ss.str();
	}
	case dart::kConstSetCid: {
		auto& set = dart::Set::Cast(obj);
		const auto typeArg = app.typeDb->FindOrAdd(set.GetTypeArguments());
		if (simpleForm)
			return std::format("Set{}({})", typeArg->ToString(), set.Length());

		std::ostringstream ss;
		ss << std::format("Set{}({}) {{ ", typeArg->ToString(), set.Length());
		dart::Set::Iterator iter(set);
		auto& key = dart::Object::Handle();
		int cnt = 0;
		while (iter.MoveNext()) {
			if (cnt++)
				ss << ", ";
			key = iter.CurrentKey();
			ss << ObjectToString(key, simpleForm, nestedObj, depth + 1);
		}
		ss << " }";
		return ss.str();
	}
	case dart::kLibraryPrefixCid: {
		const auto& libPrefix = dart::LibraryPrefix::Cast(obj);
		const auto& name = dart::String::Handle(libPrefix.name());
		RELEASE_ASSERT(libPrefix.num_imports() == 1);
		// don't know what importer is
		//const auto& importer = dart::Library::Handle(libPrefix.importer());
		const auto& imports = dart::Array::Handle(libPrefix.imports());
		const auto& importObj = dart::Object::Handle(imports.At(0));
		RELEASE_ASSERT(importObj.GetClassId() == dart::kNamespaceCid);
		const auto& ns = dart::Namespace::Cast(importObj);
		const auto& lib = dart::Library::Handle(ns.target());
		const auto& libName = dart::String::Handle(lib.url());
		return std::format("LibraryPrefix: {}, target lib: {} ({})", name.ToCString(), libName.ToCString(), lib.toplevel_class().untag()->id());
	}
	case dart::kInt32x4Cid: {
		const auto& simd = dart::Int32x4::Cast(obj);
		return std::format("Int32x4: ({}, {}, {}, {})", simd.x(), simd.y(), simd.z(), simd.w());
	}
	case dart::kFloat32x4Cid: {
		const auto& simd = dart::Float32x4::Cast(obj);
		return std::format("Float32x4: ({}, {}, {}, {})", simd.x(), simd.y(), simd.z(), simd.w());
	}
	case dart::kFloat64x2Cid: {
		const auto& simd = dart::Float64x2::Cast(obj);
		return std::format("Float64x2: ({}, {})", simd.x(), simd.y());
	}
	case dart::kInstanceCid:
		return std::format("Obj!Object@{:x}", (uint32_t)(intptr_t)obj.ptr());
	// TODO: enum subclass
	}

	// many cids are instance. handling them after special classes.
	ASSERT(obj.IsInstance());

	if (cid < dart::kNumPredefinedCids) {
		FATAL("Unhandle internal class %s (%ld)", app.GetClass(cid)->Name().c_str(), cid);
	}

	// TODO: print library and package prefix
	knownObjectPtrs.insert((intptr_t)obj.ptr());
	return dumpInstance(obj, simpleForm, nestedObj, depth);
}

std::string DartDumper::dumpInstance(dart::Object& obj, bool simpleForm, bool nestedObj, int depth)
{
	auto dartCls = app.classes[obj.GetClassId()];
	ASSERT(dartCls->Id() >= dart::kNumPredefinedCids);

	std::string closeIndent(depth * 2, ' ');
	std::string indent(closeIndent.length() + 2, ' ');

	const auto ptr = dart::UntaggedObject::ToAddr(obj.ptr());
	DartType* dtype = app.typeDb->FindOrAdd(*dartCls, dart::Instance::Cast(obj));
	if (simpleForm || (!nestedObj && depth > 0)) {
		return std::format("Obj!{}@{:x}", dtype->ToString(), (uint32_t)(intptr_t)obj.ptr());
	}

	std::vector<DartClass*> parents;
	auto superCls = dartCls->Parent();
	while (superCls->Id() != dart::kInstanceCid) {
		parents.push_back(superCls);
		superCls = superCls->Parent();
	}

	std::ostringstream ss;
	int fieldCnt = 0;
	ss << std::format("Obj!{}@{:x} : {{\n", dtype->ToString(), (uint32_t)(intptr_t)obj.ptr());
	auto offset = dart::Instance::NextFieldOffset();
	for (auto parent : parents | std::views::reverse) {
		if (offset < parent->Size()) {
			// parent fields depth MUST increment by 2 because 1 is for "Super!..."
			auto txt = dumpInstanceFields(obj, *parent, ptr, offset, simpleForm, nestedObj, depth + 2);
			offset = parent->Size();
			if (!txt.empty()) {
				if (fieldCnt++)
					ss << ",\n";
				ss << indent << "Super!" << parent->FullName() << " : {\n";
				ss << txt << "\n";
				ss << indent << "}";
			}
		}
	}

	auto fieldTxt = dumpInstanceFields(obj, *dartCls, ptr, offset, simpleForm, nestedObj, depth + 1);
	if (!fieldTxt.empty()) {
		if (fieldCnt++)
			ss << ",\n";
		ss << fieldTxt;
	}
	if (fieldCnt)
		ss << "\n";
	ss << closeIndent << "}";

	return ss.str();
}

std::string DartDumper::dumpInstanceFields(dart::Object& obj, DartClass& dartCls, intptr_t ptr, intptr_t offset, bool simpleForm, bool nestedObj, int depth)
{
	std::stringstream ss;
	std::string indent(depth * 2, ' ');

	const auto bitmap = dartCls.UnboxedFieldsBitmap();
	while (offset < dartCls.Size()) {
		std::string txtField;
		// TODO: match the offset to field name if possible
		if (bitmap.Get(offset / dart::kCompressedWordSize)) {
			// AOT uses native integer if it is less than 31 bits (compressed pointer)
			// integer (4/8 bytes) or double (8 bytes)
			if (dart::kCompressedWordSize == 4)
				RELEASE_ASSERT(bitmap.Get((offset + dart::kCompressedWordSize) / dart::kCompressedWordSize));
			auto p = reinterpret_cast<uint64_t*>(ptr + offset);
			// it is rare to find integer that larger than 0x1000_0000_0000_0000
			if (*p <= 0x1000000000000000 || *p >= 0xffffffffffff0000) {
				txtField = std::format("off_{:x}: int({:#x})", offset, *p);
			}
			else {
				txtField = std::format("off_{:x}: double({})", offset, *((double*)p));
			}
			offset += dart::kCompressedWordSize;
		}
		else if (offset != dartCls.TypeArgumentsOffset()) {
			// compressed object ptr
			auto p = reinterpret_cast<dart::CompressedObjectPtr*>(ptr + offset);
			if (*p != dart::CompressedObjectPtr(nullptr)) {
				if (p->IsHeapObject()) {
					auto objPtr2 = p->Decompress(app.heap_base());
					if (objPtr2 != nullptr && objPtr2.GetClassId() != dart::kNullCid) {
						obj = objPtr2;
						if (simpleForm || objPtr2.GetClassId() < dart::kNumPredefinedCids)
							txtField = std::format("off_{:x}: {}", offset, ObjectToString(obj, simpleForm, nestedObj, depth));
						else
							txtField = std::format("off_{:x}_{}", offset, ObjectToString(obj, simpleForm, nestedObj, depth));
					}
				}
				else {
					obj = p->DecompressSmi();
					txtField = std::format("off_{:x}_Smi: {:#x}", offset, dart::Smi::Cast(obj).Value());
				}
			}
		}
		offset += dart::kCompressedWordSize;

		if (!txtField.empty()) {
			if (ss.tellp() != 0)
				ss << ",\n";
			ss << indent << txtField;
		}
	}

	return ss.str();
}

std::string DartDumper::getPoolObjectDescription(intptr_t offset, bool simpleForm)
{
	const auto& pool = app.GetObjectPool();
	intptr_t idx = dart::ObjectPool::IndexFromOffset(offset);
	auto objType = pool.TypeAt(idx);
	// see how the EntryType is handled from vm/object_service.cc - ObjectPool::PrintJSONImpl()
	if (objType == dart::ObjectPool::EntryType::kTaggedObject) {
		auto& obj = dart::Object::Handle(pool.ObjectAt(idx));
		if (obj.IsUnlinkedCall()) {
			// since Dart 3.10, target type might be kTaggedObject
			auto unlinkTargetType = pool.TypeAt(idx + 1);
			if (unlinkTargetType == dart::ObjectPool::EntryType::kImmediate) {
				const auto imm = pool.RawValueAt(idx + 1);
				auto dartFn = app.GetFunction(imm - app.base());
				// On AOT builds that fold duplicate instructions (`dedup_instructions`),
				// an UnlinkedCall can point at a code blob that isn't registered as a
				// function *or* a stub — we've seen this on obfuscated release APKs.
				// Fall back to the raw target so the pool dump stays intact.
				if (dartFn == nullptr) {
					return std::format("[pp+{:#x}] UnlinkedCall: {:#x} - [unresolved]", offset, imm - app.base());
				}
				return std::format("[pp+{:#x}] UnlinkedCall: {:#x} - {}", offset, dartFn->Address(), dartFn->FullName().c_str());
			}
			else {
				ASSERT(unlinkTargetType == dart::ObjectPool::EntryType::kTaggedObject);
				auto& obj2 = dart::Object::Handle(pool.ObjectAt(idx + 1));
				return std::format("[pp+{:#x}] UnlinkedCall: {}", offset, ObjectToString(obj2, simpleForm));
			}
		}
		return std::format("[pp+{:#x}] {}", offset, ObjectToString(obj, simpleForm));
	}
	else if (objType == dart::ObjectPool::EntryType::kImmediate) {
		dart::uword imm = pool.RawValueAt(idx);
		if (imm <= 0x1000000000000000 || imm >= 0xffffffffffff0000) {
			return std::format("[pp+{:#x}] IMM: {:#x}", offset, imm);
		}
		else {
			return std::format("[pp+{:#x}] IMM: double({}) from {:#x}", offset, *((double*)&imm), imm);
		}
	}
	else if (objType == dart::ObjectPool::EntryType::kNativeFunction) {
		auto pc = pool.RawValueAt(idx);
		uintptr_t start = 0;
		auto name = dart::NativeSymbolResolver::LookupSymbolName(pc, &start);
		if (name != NULL) {
			auto txt = std::format("[pp+{:#x}] NativeFn: {} at {:#x}", offset, name, pc);
			dart::NativeSymbolResolver::FreeSymbolName(name);
			return txt;
		}
		else {
			return std::format("[pp+{:#x}] NativeFn: [no name] at {:#x}", offset, pc);
		}
	}
	else {
		throw std::runtime_error(std::format("unknown pool object type: {}", (int)objType).c_str());
	}
}

void DartDumper::DumpObjectPool(const char* filename)
{
	std::ofstream of(filename);
	const auto& pool = app.GetObjectPool();
	intptr_t num = pool.Length();

	const auto& rawObj = pool.ptr()->untag();
	const auto raw_addr = dart::UntaggedObject::ToAddr(rawObj);
	of << std::format("pool heap offset: {:#x}\n", raw_addr - app.heap_base());

	for (intptr_t i = 0; i < num; i++) {
		// offset here is from ObjectPool pointer subtracted by kHeapObjectTag
		// add 1 to make the offset value same as offset in compiled code
		intptr_t offset = dart::ObjectPool::OffsetFromIndex(i);
		auto txt = getPoolObjectDescription(offset + 1, false);
		of << txt << "\n";
		if (txt.compare(txt.find(']'), 15, "] UnlinkedCall:") == 0)
			i++;
	}
}

void DartDumper::DumpObjects(const char* filename)
{
	std::ofstream of(filename);

	auto& obj = dart::Object::Handle();
	for (auto objPtr : knownObjectPtrs) {
		obj = dart::ObjectPtr(objPtr);
		const bool simpleForm = false;
		const bool nestedObj = true;
		of << dumpInstance(obj, simpleForm, nestedObj, 0);
		of << "\n\n";
	}
}

// ---------------------------------------------------------------------------
// JSON export (schema_version 1)
//
// Minimal, hand-rolled JSON writer — enough for well-formed output of the
// fields we emit today. Avoids pulling in a new third-party dependency just
// for an export path. If the schema grows beyond strings and integers,
// prefer upgrading to nlohmann::json rather than extending this in place.
// ---------------------------------------------------------------------------
namespace {

void appendJsonEscaped(std::string& out, std::string_view s)
{
	out.push_back('"');
	for (unsigned char c : s) {
		switch (c) {
		case '"':  out.append("\\\""); break;
		case '\\': out.append("\\\\"); break;
		case '\b': out.append("\\b"); break;
		case '\f': out.append("\\f"); break;
		case '\n': out.append("\\n"); break;
		case '\r': out.append("\\r"); break;
		case '\t': out.append("\\t"); break;
		default:
			if (c < 0x20) {
				out.append(std::format("\\u{:04x}", static_cast<unsigned>(c)));
			} else {
				out.push_back(static_cast<char>(c));
			}
		}
	}
	out.push_back('"');
}

} // namespace

void DartDumper::DumpObjectPoolJson(const char* filename)
{
	std::ofstream of(filename);
	const auto& pool = app.GetObjectPool();
	intptr_t num = pool.Length();

	const auto& rawObj = pool.ptr()->untag();
	const auto raw_addr = dart::UntaggedObject::ToAddr(rawObj);
	const intptr_t pool_heap_offset = raw_addr - app.heap_base();

	of << "{\n";
	of << "  \"schema_version\": 1,\n";
	of << std::format("  \"pool_heap_offset\": \"{:#x}\",\n", pool_heap_offset);
	of << "  \"entries\": [\n";

	bool first = true;
	for (intptr_t i = 0; i < num; i++) {
		intptr_t offset = dart::ObjectPool::OffsetFromIndex(i);
		auto txt = getPoolObjectDescription(offset + 1, false);

		std::string entry;
		entry.append("    {\"index\": ");
		entry.append(std::to_string(i));
		entry.append(", \"offset\": ");
		entry.append(std::to_string(offset + 1));
		entry.append(", \"description\": ");
		appendJsonEscaped(entry, txt);
		entry.append("}");

		if (!first) of << ",\n";
		of << entry;
		first = false;

		// UnlinkedCall occupies two pool slots; skip the second entry so it
		// isn't emitted as a bare immediate (mirrors the text dump's skip).
		if (txt.compare(txt.find(']'), 15, "] UnlinkedCall:") == 0)
			i++;
	}

	of << "\n  ]\n}\n";
}

void DartDumper::DumpObjectsJson(const char* filename)
{
	std::ofstream of(filename);
	of << "{\n";
	of << "  \"schema_version\": 1,\n";
	of << "  \"objects\": [\n";

	auto& obj = dart::Object::Handle();
	bool first = true;
	for (auto objPtr : knownObjectPtrs) {
		obj = dart::ObjectPtr(objPtr);
		const bool simpleForm = false;
		const bool nestedObj = true;
		auto description = dumpInstance(obj, simpleForm, nestedObj, 0);

		std::string cls_name;
		if (!obj.IsNull()) {
			auto clsId = obj.GetClassId();
			if (clsId >= 0 && static_cast<size_t>(clsId) < app.classes.size() && app.classes[clsId] != nullptr)
				cls_name = app.classes[clsId]->FullName();
		}

		std::string entry;
		entry.append("    {\"ptr\": ");
		entry.append(std::format("\"{:#x}\"", static_cast<intptr_t>(objPtr)));
		entry.append(", \"class\": ");
		appendJsonEscaped(entry, cls_name);
		entry.append(", \"description\": ");
		appendJsonEscaped(entry, description);
		entry.append("}");

		if (!first) of << ",\n";
		of << entry;
		first = false;
	}

	of << "\n  ]\n}\n";
}

// ---------------------------------------------------------------------------
// functions.json (schema_version 1) — Iter 6 type-inference surface.
//
// Emits one object per unique function:
//   { "addr": "0x...", "name": "foo", "class": "Bar", "library": "package:x",
//     "argc": N, "argc_opt": M, "has_named": bool, "is_static": bool,
//     "is_closure": bool, "return_type": "String", "params":
//       [ { "name": "x", "type": "int", "required": bool }, ... ] }
// ---------------------------------------------------------------------------
void DartDumper::DumpFunctionsJson(const char* filename)
{
	std::ofstream of(filename);
	of << "{\n";
	of << "  \"schema_version\": 1,\n";
	of << "  \"functions\": [\n";

	bool first = true;
	for (const auto& [addr, dartFn] : app.functions) {
		if (!dartFn) continue;

		if (!first) of << ",\n";
		first = false;

		const auto& cls = dartFn->Class();
		const auto& lib = cls.Library();
		std::string libName = const_cast<DartLibrary&>(lib).GetName();

		std::string entry;
		entry.append("    {\"addr\": ");
		entry.append(std::format("\"{:#x}\"", static_cast<intptr_t>(addr)));
		entry.append(", \"name\": ");
		appendJsonEscaped(entry, dartFn->Name());
		entry.append(", \"class\": ");
		appendJsonEscaped(entry, cls.Name());
		entry.append(", \"library\": ");
		appendJsonEscaped(entry, libName);
		entry.append(", \"argc\": ");
		entry.append(std::to_string(dartFn->NumParam()));
		entry.append(", \"argc_opt\": ");
		entry.append(std::to_string(dartFn->NumOptionalParam()));
		entry.append(", \"has_named\": ");
		entry.append(dartFn->HasNamedParam() ? "true" : "false");
		entry.append(", \"is_static\": ");
		entry.append(dartFn->IsStatic() ? "true" : "false");
		entry.append(", \"is_closure\": ");
		entry.append(dartFn->IsClosure() ? "true" : "false");

		auto* rt = dartFn->Signature().ReturnType();
		entry.append(", \"return_type\": ");
		appendJsonEscaped(entry, rt ? rt->ToString() : std::string());

		entry.append(", \"params\": [");
		auto& params = dartFn->Signature().params;
		bool firstP = true;
		for (auto& p : params) {
			if (!firstP) entry.append(", ");
			firstP = false;
			entry.append("{\"name\": ");
			appendJsonEscaped(entry, p.name);
			entry.append(", \"type\": ");
			appendJsonEscaped(entry, p.type ? p.type->ToString() : std::string());
			entry.append(", \"required\": ");
			entry.append(p.isRequired ? "true" : "false");
			entry.append("}");
		}
		entry.append("]}");

		of << entry;
	}

	of << "\n  ]\n}\n";
}

// ---------------------------------------------------------------------------
// SQLite export (text SQL form, schema_version 1)
//
// Emits CREATE TABLE + INSERT statements wrapped in a transaction. blutter.py
// feeds this to stdlib sqlite3 (executescript) to materialize blutter.db.
// Keeping this as text avoids linking libsqlite3 into the C++ binary.
//
// Schema:
//   objects(ptr PK, cid, class_name, description)
//   pool(idx PK, offset, description)    -- 'idx' avoids the SQL 'index' keyword
//   functions(addr PK, name, cls, lib, argc, argc_opt, has_named,
//             is_static, is_closure, ret)
// ---------------------------------------------------------------------------
namespace {

// SQL single-quoted string escape: double any embedded single quote. Newlines
// and other characters are valid inside SQLite string literals, so no other
// escaping is needed.
void appendSqlQuoted(std::string& out, std::string_view s)
{
	out.push_back('\'');
	for (char c : s) {
		if (c == '\'')
			out.append("''");
		else
			out.push_back(c);
	}
	out.push_back('\'');
}

} // namespace

void DartDumper::DumpSqlite(const char* filename)
{
	std::ofstream of(filename);

	// Speed up bulk load; blutter.db is a build artifact so durability is not
	// a concern.
	of << "PRAGMA journal_mode = OFF;\n";
	of << "PRAGMA synchronous = OFF;\n";
	of << "PRAGMA foreign_keys = OFF;\n\n";

	of << "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);\n";
	of << "INSERT OR REPLACE INTO meta VALUES ('schema_version', '1');\n\n";

	of << "DROP TABLE IF EXISTS objects;\n";
	of << "CREATE TABLE objects (\n";
	of << "    ptr INTEGER PRIMARY KEY,\n";
	of << "    cid INTEGER,\n";
	of << "    class_name TEXT,\n";
	of << "    description TEXT\n";
	of << ");\n\n";

	of << "DROP TABLE IF EXISTS pool;\n";
	of << "CREATE TABLE pool (\n";
	of << "    idx INTEGER PRIMARY KEY,\n";
	of << "    offset INTEGER,\n";
	of << "    description TEXT\n";
	of << ");\n\n";

	of << "DROP TABLE IF EXISTS functions;\n";
	of << "CREATE TABLE functions (\n";
	of << "    addr INTEGER PRIMARY KEY,\n";
	of << "    name TEXT,\n";
	of << "    cls TEXT,\n";
	of << "    lib TEXT,\n";
	of << "    argc INTEGER,\n";
	of << "    argc_opt INTEGER,\n";
	of << "    has_named INTEGER,\n";
	of << "    is_static INTEGER,\n";
	of << "    is_closure INTEGER,\n";
	of << "    ret TEXT\n";
	of << ");\n\n";

	// Iter 6: per-function parameter vector. Each row is one parameter slot;
	// join back to functions via fn_addr. is_required only meaningful for
	// named parameters (functions with has_named=1).
	of << "DROP TABLE IF EXISTS params;\n";
	of << "CREATE TABLE params (\n";
	of << "    fn_addr INTEGER,\n";
	of << "    idx INTEGER,\n";
	of << "    name TEXT,\n";
	of << "    type TEXT,\n";
	of << "    is_required INTEGER,\n";
	of << "    PRIMARY KEY (fn_addr, idx)\n";
	of << ");\n\n";

	of << "BEGIN;\n";

	// ---- objects ---------------------------------------------------------
	{
		auto& obj = dart::Object::Handle();
		std::string row;
		for (auto objPtr : knownObjectPtrs) {
			obj = dart::ObjectPtr(objPtr);
			const bool simpleForm = false;
			const bool nestedObj = true;
			auto description = dumpInstance(obj, simpleForm, nestedObj, 0);

			intptr_t cid = -1;
			std::string cls_name;
			if (!obj.IsNull()) {
				cid = obj.GetClassId();
				if (cid >= 0 && static_cast<size_t>(cid) < app.classes.size() && app.classes[cid] != nullptr)
					cls_name = app.classes[cid]->FullName();
			}

			row.clear();
			row.append("INSERT INTO objects VALUES (");
			row.append(std::to_string(static_cast<intptr_t>(objPtr)));
			row.append(", ");
			row.append(std::to_string(cid));
			row.append(", ");
			appendSqlQuoted(row, cls_name);
			row.append(", ");
			appendSqlQuoted(row, description);
			row.append(");\n");
			of << row;
		}
	}

	// ---- pool ------------------------------------------------------------
	{
		const auto& pool = app.GetObjectPool();
		intptr_t num = pool.Length();
		std::string row;
		for (intptr_t i = 0; i < num; i++) {
			intptr_t offset = dart::ObjectPool::OffsetFromIndex(i);
			auto description = getPoolObjectDescription(offset + 1, false);

			row.clear();
			row.append("INSERT INTO pool VALUES (");
			row.append(std::to_string(i));
			row.append(", ");
			row.append(std::to_string(offset + 1));
			row.append(", ");
			appendSqlQuoted(row, description);
			row.append(");\n");
			of << row;

			// UnlinkedCall occupies two pool slots; mirror the text-dump skip.
			if (description.compare(description.find(']'), 15, "] UnlinkedCall:") == 0)
				i++;
		}
	}

	// ---- functions + params ---------------------------------------------
	// Iterate the address-keyed map so each compiled function entry point
	// produces exactly one row. Walking lib->classes->Functions() can yield
	// duplicate addresses when Dart's dedup_instructions folds multiple
	// FunctionPtrs to the same code, which would collide with the PRIMARY KEY.
	{
		std::string row;
		std::string paramRow;
		for (const auto& [addr, dartFn] : app.functions) {
			const auto& cls = dartFn->Class();
			const auto& clsName = cls.Name();
			const std::string libName = const_cast<DartLibrary&>(cls.Library()).GetName();
			const auto& fnName = dartFn->Name();

			std::string retTxt;
			auto* rt = dartFn->Signature().ReturnType();
			if (rt != nullptr)
				retTxt = rt->ToString();

			row.clear();
			row.append("INSERT INTO functions VALUES (");
			row.append(std::to_string(static_cast<intptr_t>(addr)));
			row.append(", ");
			appendSqlQuoted(row, fnName);
			row.append(", ");
			appendSqlQuoted(row, clsName);
			row.append(", ");
			appendSqlQuoted(row, libName);
			row.append(", ");
			row.append(std::to_string(dartFn->NumParam()));
			row.append(", ");
			row.append(std::to_string(dartFn->NumOptionalParam()));
			row.append(", ");
			row.append(dartFn->HasNamedParam() ? "1" : "0");
			row.append(", ");
			row.append(dartFn->IsStatic() ? "1" : "0");
			row.append(", ");
			row.append(dartFn->IsClosure() ? "1" : "0");
			row.append(", ");
			appendSqlQuoted(row, retTxt);
			row.append(");\n");
			of << row;

			// Emit one row per parameter slot. Even empty-name positional
			// params get recorded so argc == COUNT(*)-per-fn for callers.
			int idx = 0;
			for (auto& p : dartFn->Signature().params) {
				paramRow.clear();
				paramRow.append("INSERT INTO params VALUES (");
				paramRow.append(std::to_string(static_cast<intptr_t>(addr)));
				paramRow.append(", ");
				paramRow.append(std::to_string(idx));
				paramRow.append(", ");
				appendSqlQuoted(paramRow, p.name);
				paramRow.append(", ");
				appendSqlQuoted(paramRow, p.type ? p.type->ToString() : std::string());
				paramRow.append(", ");
				paramRow.append(p.isRequired ? "1" : "0");
				paramRow.append(");\n");
				of << paramRow;
				idx++;
			}
		}
	}

	of << "COMMIT;\n";

	of << "CREATE INDEX IF NOT EXISTS idx_objects_cid ON objects(cid);\n";
	of << "CREATE INDEX IF NOT EXISTS idx_functions_cls ON functions(cls);\n";
	of << "CREATE INDEX IF NOT EXISTS idx_functions_lib ON functions(lib);\n";
	of << "CREATE INDEX IF NOT EXISTS idx_params_fn ON params(fn_addr);\n";
}