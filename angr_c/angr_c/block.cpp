#include <stdint.h>
#include <pybind11/pybind11.h>
#include <libvex.h>
#include <vector>

#include "block.hpp"

namespace py = pybind11;
using namespace py::literals;


namespace angr_c
{
	py::object DEFAULT_VEX_ENGINE;

	Block::Block(
		uint64_t addr,
		py::object project,
		py::object arch,
		uint32_t size,
		uint8_t optLevel,
		int32_t numInst,
		uint32_t traceflags,
		bool strictBlockEnd,
		bool collectDataRefs,
		bool crossInsnOpt,
		bool loadFromRoRegions,
		py::object initialRegs
	)
	{

	}

	Block::Block(
		uint64_t addr,
		py::object project,
		py::object arch,
		py::bytes byteString,
		uint8_t optLevel,
		int32_t numInst,
		uint32_t traceflags,
		bool strictBlockEnd,
		bool collectDataRefs,
		bool crossInsnOpt,
		bool loadFromRoRegions,
		py::object initialRegs
	) :
		m_Addr(addr),
		m_Project(project),
		m_OptLevel(optLevel),
		m_Instructions(numInst),
		m_StrictBlockEnd(strictBlockEnd),
		m_CollectDataRefs(collectDataRefs),
		m_CrossInsnOpt(crossInsnOpt),
		m_LoadFromRoRegions(loadFromRoRegions),
		m_InitialRegs(initialRegs),
		m_Capstone(py::none())
	{
		if (byteString.is_none()) {
			throw std::invalid_argument("\"byteString\" must be provided. Otherwise, please call block_from_state() instead.");
		}

		if (!project.is_none()) {
			m_Arch = project.attr("arch");
		}
		else {
			m_Arch = arch;
		}

		if (m_Arch.is_none()) {
			throw std::invalid_argument("Either \"project\" or \"arch\" has to be specified.");
		}

		// TODO: Handling THUMB

		if (project.is_none() && byteString.is_none()) {
			throw std::invalid_argument("\"byte_string\" has to be specified if \"project\" is not provided.");
		}

		m_Size = py::cast<uint32_t>(byteString.attr("__len__")());

		if (m_Vex.has_value()) {
			ParseVexInfo(*m_Vex);
		}

		auto tmpStr = std::string(byteString);
		m_Size = static_cast<int32_t>(tmpStr.size());
		m_Bytes = new uint8_t(m_Size);
		memcpy(m_Bytes, tmpStr.c_str(), m_Size);
		m_OwnBytes = true;
	}

	Block::Block(
		uint64_t addr,
		py::object project,
		py::object arch,
		py::object vex,
		uint8_t optLevel,
		int32_t numInst,
		bool strictBlockEnd,
		bool collectDataRefs,
		bool crossInsnOpt,
		bool loadFromRoRegions,
		py::object initialRegs
	) :
		m_Addr(addr),
		m_Project(project),
		m_Arch(arch),
		m_Vex(vex),
		m_OptLevel(optLevel),
		m_Instructions(numInst),
		m_StrictBlockEnd(strictBlockEnd),
		m_CollectDataRefs(collectDataRefs),
		m_CrossInsnOpt(crossInsnOpt),
		m_LoadFromRoRegions(loadFromRoRegions),
		m_InitialRegs(initialRegs),
		m_Capstone(py::none())
	{
		m_Bytes = nullptr;
		m_OwnBytes = false;
		m_Size = py::cast<uint32_t>(vex.attr("size"));
	}

	Block::Block(
		uint64_t addr,
		const py::kwargs& kwargs
	) :
		m_Addr(addr),
		m_Vex(std::nullopt),
		m_OwnBytes(false),
		m_Bytes(NULL)
	{
		// Dispatch to various initializers based on which keyword arguments are available
		if (kwargs) {
			std::optional<py::object> project(std::nullopt);
			std::optional<py::object> arch(std::nullopt);
			bool thumb = false;
			int optLevel = 0;
			py::object vex;
			size_t size;
			int numInst = -1;
			int traceflags = 0;
			bool strictBlockEnd = false;
			bool collectDataRefs = false;
			bool crossInsnOpt = true;
			bool loadFromRoRegions = false;
			std::optional<py::bytes> byteString(std::nullopt);

			if (kwargs.contains("project")) {
				py::object arg = kwargs["project"];
				if (!arg.is_none()) {
					project = arg;
				}
			}

			if (kwargs.contains("arch")) {
				py::object arg = kwargs["arch"];
				if (!arg.is_none()) {
					arch = arg;
				}
			}
			else {
				if (project.has_value()) {
					arch = (*project).attr("arch");
				}
			}

			if (!project.has_value() && !arch.has_value()) {
				throw py::value_error("Either \"project\" or \"arch\" has to be specified");
			}

			// TODO: Set thumb if ARM
			if (kwargs.contains("thumb")) {
				thumb = kwargs["thumb"].cast<bool>();
			}

			if (kwargs.contains("opt_level")) {
				py::object arg = kwargs["opt_level"];
				if (!arg.is_none()) {
					optLevel = arg.cast<int>();
				}
			}

			if (kwargs.contains("byte_string")) {
				py::object arg = kwargs["byte_string"];
				if (!arg.is_none()) {
					byteString = arg.cast<py::bytes>();
				}
			}

			if (kwargs.contains("vex")) {
				vex = kwargs["vex"];
			}
			else {
				vex = py::none();
			}

			if (kwargs.contains("traceflags")) {
				py::object arg = kwargs["traceflags"];
				if (!arg.is_none()) {
					traceflags = arg.cast<int>();
				}
			}

			if (kwargs.contains("collect_data_refs")) {
				py::object arg = kwargs["collect_data_refs"];
				if (!arg.is_none()) {
					collectDataRefs = arg.cast<bool>();
				}
			}

			if (kwargs.contains("strict_block_end")) {
				py::object arg = kwargs["strict_block_end"];
				if (!arg.is_none()) {
					strictBlockEnd = arg.cast<bool>();
				}
			}

			if (kwargs.contains("cross_insn_opt")) {
				py::object arg = kwargs["cross_insn_opt"];
				if (!arg.is_none()) {
					crossInsnOpt = arg.cast<bool>();
				}
			}

			if (kwargs.contains("load_from_ro_regions")) {
				py::object arg = kwargs["load_from_ro_regions"];
				if (!arg.is_none()) {
					loadFromRoRegions = arg.cast<bool>();
				}
			}

			if (kwargs.contains("num_inst")) {
				py::object arg = kwargs["num_inst"];
				if (!arg.is_none()) {
					numInst = arg.cast<int>();
				}
			}

			size = 0xffffffffffffffff;
			if (kwargs.contains("size")) {
				py::object arg = kwargs["size"];
				if (!arg.is_none()) {
					size = arg.cast<size_t>();
				}
			}

			if (size == 0xffffffffffffffff) {
				if (byteString.has_value()) {
					py::buffer_info info(py::buffer(*byteString).request());
					size = info.size;
				}
				else if (!vex.is_none()) {
					size = vex.attr("size").cast<size_t>();
					m_Vex = vex;
				}
				else {
					// lift the block!
					py::object vexEngine;
					if (!project.has_value()) {
						vexEngine = DEFAULT_VEX_ENGINE;
					}
					else {
						vexEngine = (*project).attr("factory").attr("default_engine");
					}

					py::object clemory;
					if (!project.has_value()) {
						clemory = (*project).attr("loader").attr("memory");
					}
					else {
						clemory = py::none();
					}

					py::dict kwargs = py::dict(
						"clemory"_a = clemory,
						"addr"_a = addr,
						// TODO: Handle THUMB
						"size"_a = size,
						"opt_level"_a = optLevel,
						"arch"_a = *arch,
						"traceflags"_a = traceflags,
						"collect_data_refs"_a = collectDataRefs,
						"strict_block_end"_a = strictBlockEnd,
						"cross_insn_opt"_a = crossInsnOpt,
						"load_from_ro_regions"_a = loadFromRoRegions
					);

					if (numInst != -1) {
						kwargs["num_inst"] = numInst;
					}

					vex = vexEngine.attr("lift_vex")(**kwargs);
					size = vex.attr("size").cast<size_t>();

					m_Vex = vex;
				}
			}

			m_Project = *project;
			m_Arch = *arch;
			m_Size = size;
			m_OptLevel = optLevel;
			m_Instructions = numInst;
			m_StrictBlockEnd = strictBlockEnd;
			m_CollectDataRefs = collectDataRefs;
			m_CrossInsnOpt = crossInsnOpt;
			m_LoadFromRoRegions = loadFromRoRegions;

			if (m_Vex.has_value()) {
				ParseVexInfo(*m_Vex);
			}

			if (byteString.has_value()) {
				// TODO: fill in self._bytes
			}
			else {
				// TODO:
			}
		}
		else {
			throw py::value_error("\"kwargs\" cannot be empty or unspecified");
		}
	}

	Block::~Block()
	{
		if (m_OwnBytes && m_Bytes)
		{
			delete m_Bytes;
		}
	}

	uint8_t* Block::GetBytes() const
	{
		return m_Bytes;
	}

	void Block::SetBytes(uint8_t* data, bool ownBytes)
	{
		if (m_OwnBytes && m_Bytes)
		{
			delete m_Bytes;
		}

		m_Bytes = data;
		m_OwnBytes = ownBytes;
	}

	void Block::ParseVexInfo(py::object vex)
	{
		if (!vex.is_none()) {
			m_Instructions = py::cast<int32_t>(vex.attr("instructions"));
			// TODO:
			// m_InstructionAddrs = py::cast<std::vector<uint64_t>>(vex.attr("instruction_addresses"));
			m_Size = py::cast<uint32_t>(vex.attr("size"));
		}
	}

	py::object Block::GetVex()
	{
		if (!m_Vex.has_value())
		{
			py::object vexEngine;
			if (m_Project.is_none()) {
				vexEngine = DEFAULT_VEX_ENGINE;
			}
			else {
				vexEngine = m_Project.attr("factory").attr("default_engine");
			}

			py::object clemory;
			if (!m_Project.is_none()) {
				clemory = m_Project.attr("loader").attr("memory");
			}
			else {
				clemory = py::none();
			}

			m_Vex = vexEngine.attr("lift_vex")(
				"clemory"_a = clemory,
				"insn_bytes"_a = py::bytes((char*)m_Bytes, m_Size),
				"addr"_a = m_Addr,
				// TODO: Handle THUMB
				"size"_a = m_Size,
				"num_inst"_a = m_Instructions,
				"opt_level"_a = m_OptLevel,
				"arch"_a = m_Arch,
				"collect_data_refs"_a = m_CollectDataRefs,
				"strict_block_end"_a = m_StrictBlockEnd,
				"cross_insn_opt"_a = m_CrossInsnOpt,
				"load_from_ro_regions"_a = m_LoadFromRoRegions
				);

			// TODO: unset initial regs
			if (m_Vex.has_value()) {
				ParseVexInfo(*m_Vex);
			}
		}
		return *m_Vex;
	}

	Block BlockFromState(
		uint64_t addr,
		py::object project,
		py::object arch,
		py::object backupState,
		py::object extraStopPoints,
		uint8_t optLevel = 1,
		int32_t numInst = -1,
		uint32_t traceflags = 0,
		bool strictBlockEnd = false,
		bool collectDataRefs = false,
		bool crossInsnOpt = true,
		bool loadFromRoRegions = false,
		py::object initialRegs = py::none()
	)
	{
		// TODO: set initial regs

		py::object vexEngine;
		if (project.is_none()) {
			vexEngine = DEFAULT_VEX_ENGINE;
		}
		else {
			vexEngine = project.attr("factory").attr("default_engine");
		}

		py::object vex = vexEngine.attr("lift_vex")(
			"clemory"_a=project.is_none()? py::none(): project.attr("loader").attr("memory"),
			"state"_a=backupState,
			"insn_bytes"_a=py::none(),
			"addr"_a=addr,
			// TODO: THUMB support
			// "thumb"_a=thumb,
			"extra_stop_points"_a=extraStopPoints,
			"opt_level"_a=optLevel,
			"num_inst"_a=numInst, // TODO: Make sure -1 is treated as None in PyVEX
			"traceflags"_a=traceflags,
			"strict_block_end"_a=strictBlockEnd,
			"collect_data_refs"_a=collectDataRefs,
			"load_from_ro_regions"_a=loadFromRoRegions,
			"cross_insn_opt"_a=crossInsnOpt
			);

		// TODO: unset initial regs

		return Block(
			addr,
			project,
			arch,
			vex,
			optLevel,
			numInst,
			traceflags,
			strictBlockEnd,
			collectDataRefs,
			crossInsnOpt,
			loadFromRoRegions,
			initialRegs
		);
	}

	void initialize_block()
	{
		py::object VEXLifter = py::module_::import("angr").attr("engines").attr("vex").attr("VEXLifter");
		DEFAULT_VEX_ENGINE = VEXLifter(py::none());
	}

	void Perf(const py::kwargs& args)
	{
		;
	}

	void register_block_class(py::module_ &m)
	{
		py::class_<Block>(m, "Block")
			.def(py::init<
				uint64_t,
				py::object,
				py::object,
				uint32_t,  // size
				uint8_t,
				int32_t,
				uint32_t,
				bool,
				bool,
				bool,
				bool,
				py::object>())
			.def(py::init<
				uint64_t,
				py::object,
				py::object,
				py::bytes, // byteString
				uint8_t,
				int32_t,
				uint32_t,
				bool,
				bool,
				bool,
				bool,
				py::object>())
			.def(py::init<
				uint64_t,
				py::object,
				py::object,
				py::object, // vex
				uint8_t,
				int32_t,
				bool,
				bool,
				bool,
				bool,
				py::object>())
			.def(py::init<
				uint64_t,
				const py::kwargs&>())
			.def_property("addr", &Block::GetAddr, &Block::SetAddr)
			.def_property("size", &Block::GetSize, &Block::SetSize)
			.def_property("_bytes", &Block::GetBytes, &Block::SetBytes)
			.def_property("_vex", &Block::GetVexBlock, &Block::SetVexBlock, py::return_value_policy::reference)
			.def_property("_disassembly", &Block::GetDisassembly, &Block::SetDisassembly)
			.def_property("_capstone", &Block::GetCapstone, &Block::SetCapstone)
			.def_property("arch", &Block::GetArch, &Block::SetArch)
			.def_property("_instructions", &Block::GetInstructions, &Block::SetInstructions)
			.def_property("_instruction_addrs", &Block::GetInstructionAddrs, &Block::SetInstructionAddrs)
			.def_property("_opt_level", &Block::GetOptLevel, &Block::SetOptLevel)
			.def_property("_collect_data_refs", &Block::GetCollectDataRefs, &Block::SetCollectDataRefs)
			.def_property("_strict_block_end", &Block::GetStrictBlockEnd, &Block::SetStrictBlockEnd)
			.def_property("_cross_insn_opt", &Block::GetCrossInsnOpt, &Block::SetCrossInsnOpt)
			.def_property("_load_from_ro_regions", &Block::GetLoadFromRoRegions, &Block::SetLoadFromRoRegions)
			.def_property("_initial_regs", &Block::GetInitialRegs, &Block::SetInitialRegs)
			.def_property("_project", &Block::GetProject, &Block::SetProject)
			.def("_parse_vex_info", &Block::ParseVexInfo, "Parse information out of a VEX IRSB.")
			.def_property_readonly("vex", &Block::GetVex, py::return_value_policy::reference);
		m.def("block_from_state",
			&BlockFromState,
			"Create a block from a given SimState instance."
			"addr"_a,
			"project"_a,
			"arch"_a,
			"backup_state"_a,
			"extra_stop_points"_a,
			"opt_level"_a,
			"num_inst"_a,
			"traceflags"_a,
			"strict_block_end"_a,
			"collect_data_refs"_a,
			"cross_insn_opt"_a,
			"load_from_ro_regions"_a,
			"initial_regs"_a);
		// m.def("initialize", &initialize_block, "Initialize singletons. Must be called before using any functions in Block.");
		m.def("perf", &Perf, "Performance evaluation.");
	}
}
