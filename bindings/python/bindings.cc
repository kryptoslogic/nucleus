#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "../../bb.h"
#include "../../cfg.h"
#include "../../nucleus.h"
#include "../../disasm.h"
#include "../../loader.h"
#include "../../util.h"
#include "../../exception.h"
#include "../../options.h"
#include "../../export.h"

namespace py = pybind11;

class Context {
public:
  std::list<DisasmSection> disasm;
  Binary binary;
  CFG cfg;

  ~Context() {
    unload_binary(&binary);
  }

  /* exporting */
  void export_ida(const std::string& fname) {
    (void)export_bin2ida(options.exports.ida, &binary, &disasm, &cfg);
  }
  void export_binja(const std::string& fname) {
    (void)export_bin2binja(options.exports.binja, &binary, &disasm, &cfg);
  }
  void export_dot(const std::string& fname) {
    (void)export_cfg2dot(options.exports.dot, &cfg);
  }

  /* processing */
  bool load(const std::string& fname) {
    std::string filename = fname; // TODO: Declare constant filename in load_binary
    return load_binary(filename, &binary, options.binary.type) >= 0;
  }
  bool disassemble() {
    return nucleus_disasm(&binary, &disasm) >= 0;
  }
  bool make_cfg() {
    return cfg.make_cfg(&binary, &disasm) >= 0;
  }
};

Context* load(
    const std::string& filename,
    bool analyze_data = false,
    bool analyze_priv = false,
    uint64_t binary_base = 0,
    Binary::BinaryType binary_type = Binary::BinaryType::BIN_TYPE_AUTO,
    Binary::BinaryArch binary_arch = Binary::BinaryArch::ARCH_NONE,
    const std::string& strategy = std::string("linear"))
{
  Context* ctx = new Context();

  set_exception_handlers();

  /* options */
  options.verbosity = 0;
  options.warnings = 0;
  options.only_code_sections = !analyze_data;
  options.allow_privileged = analyze_priv;
  options.strategy_function.name = strategy;

  options.binary.filename = filename;
  options.binary.type = binary_type;
  options.binary.arch = binary_arch;
  options.binary.base_vma = binary_base;

  /* process binary */
  if(!ctx->load(filename)) {
    return nullptr;
  }
  if(!ctx->disassemble()) {
    return nullptr;
  }
  if(!ctx->make_cfg()) {
    return nullptr;
  }
  return ctx;
}

/* Bindings */

PYBIND11_MODULE(nucleus, m) {
  /* bb.h */
  py::class_<BB> class_BB(m, "BB");
  class_BB
    .def("reset", &BB::reset)
    .def("set", &BB::set)
    .def("is_addrtaken", &BB::is_addrtaken)
    .def("is_invalid", &BB::is_invalid)
    .def("is_padding", &BB::is_padding)
    .def("is_called", &BB::is_called)
    .def("is_trap", &BB::is_trap)
    .def("returns", &BB::returns)
    .def("comparator", &BB::comparator)
    .def_readwrite("start", &BB::start)
    .def_readwrite("end", &BB::end)
    .def_readwrite("insns", &BB::insns)
    .def_readwrite("function", &BB::function)
    .def_readwrite("section", &BB::section)
    .def_readwrite("score", &BB::score)
    .def_readwrite("alive", &BB::score)
    .def_readwrite("invalid", &BB::score)
    .def_readwrite("privileged", &BB::score)
    .def_readwrite("addrtaken", &BB::score)
    .def_readwrite("padding", &BB::score)
    .def_readwrite("trap", &BB::score)
    .def_readwrite("ancestors", &BB::ancestors)
    .def_readwrite("targets", &BB::targets);

  /* cfg.h */
  py::class_<CFG> class_CFG(m, "CFG");
  class_CFG
    .def("get_bb", &CFG::get_bb)
    .def("print_functions", &CFG::print_functions)
    .def("print_function_summaries", &CFG::print_function_summaries)
    .def_readwrite("binary", &CFG::binary)
    .def_readwrite("entry", &CFG::entry)
    .def_readwrite("functions", &CFG::functions)
    .def_readwrite("start2bb", &CFG::start2bb)
    .def_readwrite("bad_bbs", &CFG::bad_bbs);

  /* dataregion.h */
  py::class_<DataRegion> class_DataRegion(m, "DataRegion");
  class_DataRegion
    .def_readwrite("start", &DataRegion::start)
    .def_readwrite("end", &DataRegion::end);

  /* disasm.h */
  py::class_<AddressMap> class_AddressMap(m, "AddressMap");
  class_AddressMap
    .def("insert", &AddressMap::insert)
    .def("contains", &AddressMap::contains)
    .def("get_addr_type", &AddressMap::get_addr_type)
    .def("set_addr_type", &AddressMap::set_addr_type)
    .def("add_addr_flag", &AddressMap::add_addr_flag)
    .def("addr_type", &AddressMap::addr_type)
    .def("unmapped_count", &AddressMap::addr_type)
    .def("get_unmapped", &AddressMap::addr_type)
    .def("erase", &AddressMap::addr_type)
    .def("erase_unmapped", &AddressMap::addr_type);
  py::enum_<AddressMap::DisasmRegion>(class_AddressMap, "DisasmRegion", py::arithmetic())
    .value("DISASM_REGION_UNMAPPED",   AddressMap::DisasmRegion::DISASM_REGION_UNMAPPED)
    .value("DISASM_REGION_CODE",       AddressMap::DisasmRegion::DISASM_REGION_CODE)
    .value("DISASM_REGION_DATA",       AddressMap::DisasmRegion::DISASM_REGION_DATA)
    .value("DISASM_REGION_INS_START",  AddressMap::DisasmRegion::DISASM_REGION_INS_START)
    .value("DISASM_REGION_BB_START",   AddressMap::DisasmRegion::DISASM_REGION_BB_START)
    .value("DISASM_REGION_FUNC_START", AddressMap::DisasmRegion::DISASM_REGION_FUNC_START)
    .export_values();

  py::class_<DisasmSection> class_DisasmSection(m, "DisasmSection");
  class_DisasmSection
    .def("print_BBs", &DisasmSection::print_BBs)
    .def_readwrite("section", &DisasmSection::section)
    .def_readwrite("addrmap", &DisasmSection::addrmap)
    .def_readwrite("BBs", &DisasmSection::BBs)
    .def_readwrite("data", &DisasmSection::data);

  /* edge.h */
  py::class_<Edge> class_Edge(m, "Edge");
  class_Edge
    .def("type2str", &Edge::type2str)
    .def_readwrite("type", &Edge::type)
    .def_readwrite("src", &Edge::src)
    .def_readwrite("dst", &Edge::dst)
    .def_readwrite("is_switch", &Edge::is_switch)
    .def_readwrite("jmptab", &Edge::jmptab)
    .def_readwrite("offset", &Edge::offset);
  py::enum_<Edge::EdgeType>(class_Edge, "EdgeType")
    .value("EDGE_TYPE_NONE",          Edge::EdgeType::EDGE_TYPE_NONE)
    .value("EDGE_TYPE_JMP",           Edge::EdgeType::EDGE_TYPE_JMP)
    .value("EDGE_TYPE_CALL",          Edge::EdgeType::EDGE_TYPE_CALL)
    .value("EDGE_TYPE_JMP_INDIRECT",  Edge::EdgeType::EDGE_TYPE_JMP_INDIRECT)
    .value("EDGE_TYPE_CALL_INDIRECT", Edge::EdgeType::EDGE_TYPE_CALL_INDIRECT)
    .value("EDGE_TYPE_RET",           Edge::EdgeType::EDGE_TYPE_RET)
    .value("EDGE_TYPE_FALLTHROUGH",   Edge::EdgeType::EDGE_TYPE_FALLTHROUGH)
    .export_values();

  /* function.h */
  py::class_<Function> class_Function(m, "Function");
  class_Function
    .def("print", &Function::print)
    .def("print_summary", &Function::print_summary)
    .def("add_bb", &Function::add_bb)
    .def_readwrite("cfg", &Function::cfg)
    .def_readwrite("id", &Function::id)
    .def_readwrite("start", &Function::start)
    .def_readwrite("end", &Function::end)
    .def_readwrite("entry", &Function::entry)
    .def_readwrite("BBs", &Function::BBs);

  /* insn.h */
  py::class_<Operand> class_Operand(m, "Operand");
  class_Operand
    .def_readwrite("type", &Operand::type)
    .def_readwrite("size", &Operand::size)
    .def_readwrite("aarch64_value", &Operand::aarch64_value)
    .def_readwrite("arm_value", &Operand::arm_value)
    .def_readwrite("mips_value", &Operand::mips_value)
    .def_readwrite("ppc_value", &Operand::ppc_value)
    .def_readwrite("x86_value", &Operand::x86_value);
  py::enum_<Operand::OperandType>(class_Operand, "OperandType")
    .value("OP_TYPE_NONE", Operand::OperandType::OP_TYPE_NONE)
    .value("OP_TYPE_REG",  Operand::OperandType::OP_TYPE_REG)
    .value("OP_TYPE_IMM",  Operand::OperandType::OP_TYPE_IMM)
    .value("OP_TYPE_MEM",  Operand::OperandType::OP_TYPE_MEM)
    .value("OP_TYPE_FP",   Operand::OperandType::OP_TYPE_FP)
    .export_values();
#if 0
  py::class_<Operand::AArch64Value>(class_Operand, "AArch64Value")
    .def_readwrite("reg", &Operand::AArch64Value::reg)
    .def_readwrite("imm", &Operand::AArch64Value::imm)
    .def_readwrite("fp",  &Operand::AArch64Value::fp)
    .def_readwrite("mem", &Operand::AArch64Value::mem);
  py::class_<Operand::ARMValue>(class_Operand, "ARMValue")
    .def_readwrite("reg", &Operand::ARMValue::reg)
    .def_readwrite("imm", &Operand::ARMValue::imm)
    .def_readwrite("fp",  &Operand::ARMValue::fp)
    .def_readwrite("mem", &Operand::ARMValue::mem);
  py::class_<Operand::MIPSValue>(class_Operand, "MIPSValue")
    .def_readwrite("reg", &Operand::MIPSValue::reg)
    .def_readwrite("imm", &Operand::MIPSValue::imm)
    .def_readwrite("fp",  &Operand::MIPSValue::fp)
    .def_readwrite("mem", &Operand::MIPSValue::mem);
  py::class_<Operand::PPCValue>(class_Operand, "PPCValue")
    .def_readwrite("reg", &Operand::PPCValue::reg)
    .def_readwrite("imm", &Operand::PPCValue::imm)
    .def_readwrite("mem", &Operand::PPCValue::mem);
  py::class_<Operand::X86Value>(class_Operand, "X86Value")
    .def_readwrite("reg", &Operand::X86Value::reg)
    .def_readwrite("imm", &Operand::X86Value::imm)
    .def_readwrite("fp",  &Operand::X86Value::fp)
    .def_readwrite("mem", &Operand::X86Value::mem);
#endif

  py::class_<Instruction> class_Instruction(m, "Instruction");
  class_Instruction
    .def("print", &Instruction::print)
    .def("edge_type", &Instruction::edge_type)
    .def_readwrite("id", &Instruction::id)
    .def_readwrite("start", &Instruction::start)
    .def_readwrite("size", &Instruction::size)
    .def_readwrite("addr_size", &Instruction::addr_size)
    .def_readwrite("target", &Instruction::target)
    .def_readwrite("flags", &Instruction::flags)
    .def_readwrite("mnem", &Instruction::mnem)
    .def_readwrite("op_str", &Instruction::op_str)
    .def_readwrite("operands", &Instruction::operands)
    .def_readwrite("invalid", &Instruction::invalid)
    .def_readwrite("privileged", &Instruction::privileged)
    .def_readwrite("trap", &Instruction::trap);
  py::enum_<Instruction::InstructionFlags>(class_Instruction, "InstructionFlags", py::arithmetic())
    .value("INS_FLAG_CFLOW",    Instruction::InstructionFlags::INS_FLAG_CFLOW)
    .value("INS_FLAG_COND",     Instruction::InstructionFlags::INS_FLAG_COND)
    .value("INS_FLAG_INDIRECT", Instruction::InstructionFlags::INS_FLAG_INDIRECT)
    .value("INS_FLAG_JMP",      Instruction::InstructionFlags::INS_FLAG_JMP)
    .value("INS_FLAG_CALL",     Instruction::InstructionFlags::INS_FLAG_CALL)
    .value("INS_FLAG_RET",      Instruction::InstructionFlags::INS_FLAG_RET)
    .value("INS_FLAG_NOP",      Instruction::InstructionFlags::INS_FLAG_NOP)
    .export_values();

  /* loader.h */
  py::class_<Symbol> class_Symbol(m, "Symbol");
  class_Symbol
    .def_readwrite("type", &Symbol::type)
    .def_readwrite("name", &Symbol::name)
    .def_readwrite("addr", &Symbol::addr);
  py::enum_<Symbol::SymbolType>(class_Symbol, "SymbolType")
    .value("SYM_TYPE_UKN",  Symbol::SymbolType::SYM_TYPE_UKN)
    .value("SYM_TYPE_FUNC", Symbol::SymbolType::SYM_TYPE_FUNC)
    .export_values();

  py::class_<Section> class_Section(m, "Section");
  class_Section
    .def("contains", &Section::contains)
    .def("is_import_table", &Section::is_import_table)
    .def_readwrite("binary", &Section::binary)
    .def_readwrite("name", &Section::name)
    .def_readwrite("type", &Section::type)
    .def_readwrite("vma", &Section::vma)
    .def_readwrite("size", &Section::size)
    .def_readwrite("bytes", &Section::bytes);
  py::enum_<Section::SectionType>(class_Section, "SectionType")
    .value("SEC_TYPE_NONE", Section::SectionType::SEC_TYPE_NONE)
    .value("SEC_TYPE_CODE", Section::SectionType::SEC_TYPE_CODE)
    .value("SEC_TYPE_DATA", Section::SectionType::SEC_TYPE_DATA)
    .export_values();

  py::class_<Binary> class_Binary(m, "Binary");
  class_Binary
    .def_readwrite("filename", &Binary::filename)
    .def_readwrite("type", &Binary::type)
    .def_readwrite("arch", &Binary::arch)
    .def_readwrite("type_str", &Binary::type_str)
    .def_readwrite("arch_str", &Binary::arch_str)
    .def_readwrite("bits", &Binary::bits)
    .def_readwrite("entry", &Binary::entry)
    .def_readwrite("sections", &Binary::sections)
    .def_readwrite("symbols", &Binary::symbols);
  py::enum_<Binary::BinaryType>(class_Binary, "BinaryType")
    .value("BIN_TYPE_AUTO", Binary::BinaryType::BIN_TYPE_AUTO)
    .value("BIN_TYPE_RAW",  Binary::BinaryType::BIN_TYPE_RAW)
    .value("BIN_TYPE_ELF",  Binary::BinaryType::BIN_TYPE_ELF)
    .value("BIN_TYPE_PE",   Binary::BinaryType::BIN_TYPE_PE)
    .export_values();
  py::enum_<Binary::BinaryArch>(class_Binary, "BinaryArch")
    .value("ARCH_NONE",    Binary::BinaryArch::ARCH_NONE)
    .value("ARCH_AARCH64", Binary::BinaryArch::ARCH_AARCH64)
    .value("ARCH_ARM",     Binary::BinaryArch::ARCH_ARM)
    .value("ARCH_MIPS",    Binary::BinaryArch::ARCH_MIPS)
    .value("ARCH_PPC",     Binary::BinaryArch::ARCH_PPC)
    .value("ARCH_X86",     Binary::BinaryArch::ARCH_X86)
    .export_values();

  /* Module */
  m.doc() = R"pbdoc(
      Nucleus module
      --------------

      .. currentmodule:: nucleus
  )pbdoc";

  py::class_<Context>(m, "Context")
    .def_readwrite("binary", &Context::binary)
    .def_readwrite("cfg", &Context::cfg);

  m.def("load", &load, py::return_value_policy::move, R"pbdoc(
      Parse an executable file or binary blob with Nucleus.
    )pbdoc",
    py::arg("filename"),
    py::arg("analyze_data") = false,
    py::arg("analyze_priv") = false,
    py::arg("binary_base") = 0,
    py::arg("binary_type") = Binary::BinaryType::BIN_TYPE_AUTO,
    py::arg("binary_arch") = Binary::BinaryArch::ARCH_NONE,
    py::arg("strategy") = "linear");

  #ifdef VERSION_INFO
  m.attr("__version__") = VERSION_INFO;
  #else
  m.attr("__version__") = "dev";
  #endif
}
