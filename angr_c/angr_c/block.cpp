#include <stdint.h>
#include <nanobind/nanobind.h>
#include <libvex.h>
#include <vector>

#include "block.hpp"

namespace nb = nanobind;
using namespace nb::literals;


namespace angr_c
{
	nb::object DEFAULT_VEX_ENGINE;

	Block::Block(
		uint64_t addr,
		nb::object project,
		nb::object arch,
		uint32_t size,
		uint8_t optLevel,
		int32_t numInst,
		uint32_t traceflags,
		bool strictBlockEnd,
		bool collectDataRefs,
		bool crossInsnOpt,
		bool loadFromRoRegions,
		nb::object initialRegs
	)
	{

	}

	Block::Block(
		uint64_t addr,
		nb::object project,
		nb::object arch,
		nb::bytes byteString,
		uint8_t optLevel,
		int32_t numInst,
		uint32_t traceflags,
		bool strictBlockEnd,
		bool collectDataRefs,
		bool crossInsnOpt,
		bool loadFromRoRegions,
		nb::object initialRegs
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
		m_Capstone(nb::none())
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

		m_Size = nb::cast<uint32_t>(byteString.attr("__len__")());

		if (m_Vex.has_value()) {
			ParseVexInfo(*m_Vex);
		}

		auto tmpStr = std::string(static_cast<const char*>(byteString.data()), byteString.size());
		m_Size = static_cast<int32_t>(tmpStr.size());
		m_Bytes = new uint8_t(m_Size);
		memcpy(m_Bytes, tmpStr.c_str(), m_Size);
		m_OwnBytes = true;
	}

	Block::Block(
		uint64_t addr,
		nb::object project,
		nb::object arch,
		nb::object vex,
		uint8_t optLevel,
		int32_t numInst,
		uint32_t traceflags,
		bool strictBlockEnd,
		bool collectDataRefs,
		bool crossInsnOpt,
		bool loadFromRoRegions,
		nb::object initialRegs
	) :
		m_Addr(addr),
		m_Project(project),
		m_Arch(arch),
		m_Vex(vex),
		m_OptLevel(optLevel),
		m_Instructions(numInst),
		m_Traceflags(traceflags),
		m_StrictBlockEnd(strictBlockEnd),
		m_CollectDataRefs(collectDataRefs),
		m_CrossInsnOpt(crossInsnOpt),
		m_LoadFromRoRegions(loadFromRoRegions),
		m_InitialRegs(initialRegs),
		m_Capstone(nb::none())
	{
		m_Bytes = nullptr;
		m_OwnBytes = false;
		m_Size = nb::cast<uint32_t>(vex.attr("size"));
	}

	Block::Block(
		uint64_t addr,
		const nb::kwargs& kwargs
	) :
		m_Addr(addr),
		m_Vex(std::nullopt),
		m_OwnBytes(false),
		m_Bytes(NULL)
	{
		// Dispatch to various initializers based on which keyword arguments are available
		if (kwargs) {
			std::optional<nb::object> project(std::nullopt);
			std::optional<nb::object> arch(std::nullopt);
			bool thumb = false;
			int optLevel = 0;
			nb::object vex;
			size_t size;
			int numInst = -1;
			int traceflags = 0;
			bool strictBlockEnd = false;
			bool collectDataRefs = false;
			bool crossInsnOpt = true;
			bool loadFromRoRegions = false;
			std::optional<nb::bytes> byteString(std::nullopt);

			if (kwargs.contains("project")) {
				nb::object arg = kwargs["project"];
				if (!arg.is_none()) {
					project = arg;
				}
			}

			if (kwargs.contains("arch")) {
				nb::object arg = kwargs["arch"];
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
				throw nb::value_error("Either \"project\" or \"arch\" has to be specified");
			}

			// TODO: Set thumb if ARM
			if (kwargs.contains("thumb")) {
				thumb = nb::cast<bool>(kwargs["thumb"]);
			}

			if (kwargs.contains("opt_level")) {
				nb::object arg = kwargs["opt_level"];
				if (!arg.is_none()) {
					optLevel = nb::cast<int>(arg);
				}
			}

			if (kwargs.contains("byte_string")) {
				nb::object arg = kwargs["byte_string"];
				if (!arg.is_none()) {
					byteString = nb::cast<nb::bytes>(arg);
				}
			}

			if (kwargs.contains("vex")) {
				vex = kwargs["vex"];
			}
			else {
				vex = nb::none();
			}

			if (kwargs.contains("traceflags")) {
				nb::object arg = kwargs["traceflags"];
				if (!arg.is_none()) {
					traceflags = nb::cast<int>(arg);
				}
			}

			if (kwargs.contains("collect_data_refs")) {
				nb::object arg = kwargs["collect_data_refs"];
				if (!arg.is_none()) {
					collectDataRefs = nb::cast<bool>(arg);
				}
			}

			if (kwargs.contains("strict_block_end")) {
				nb::object arg = kwargs["strict_block_end"];
				if (!arg.is_none()) {
					strictBlockEnd = nb::cast<bool>(arg);
				}
			}

			if (kwargs.contains("cross_insn_opt")) {
				nb::object arg = kwargs["cross_insn_opt"];
				if (!arg.is_none()) {
					crossInsnOpt = nb::cast<bool>(arg);
				}
			}

			if (kwargs.contains("load_from_ro_regions")) {
				nb::object arg = kwargs["load_from_ro_regions"];
				if (!arg.is_none()) {
					loadFromRoRegions = nb::cast<bool>(arg);
				}
			}

			if (kwargs.contains("num_inst")) {
				nb::object arg = kwargs["num_inst"];
				if (!arg.is_none()) {
					numInst = nb::cast<int>(arg);
				}
			}

			size = 0xffffffffffffffff;
			if (kwargs.contains("size")) {
				nb::object arg = kwargs["size"];
				if (!arg.is_none()) {
					size = nb::cast<size_t>(arg);
				}
			}

			if (size == 0xffffffffffffffff) {
				if (byteString.has_value()) {
					nb::bytes info(*byteString);
					size = info.size();
				}
				else if (!vex.is_none()) {
					size = nb::cast<size_t>(vex.attr("size"));
					m_Vex = vex;
				}
				else {
					// lift the block!
					nb::object vexEngine;
					if (!project.has_value()) {
						vexEngine = DEFAULT_VEX_ENGINE;
					}
					else {
						vexEngine = (*project).attr("factory").attr("default_engine");
					}

					nb::object clemory;
					if (!project.has_value()) {
						clemory = (*project).attr("loader").attr("memory");
					}
					else {
						clemory = nb::none();
					}

					nb::dict kwargs;
					kwargs["clemory"] = clemory;
					kwargs["addr"] = addr;
					// TODO: Handle THUMB
					kwargs["size"] = size;
					kwargs["opt_level"] = optLevel;
					kwargs["arch"] = *arch;
					kwargs["traceflags"] = traceflags;
					kwargs["collect_data_refs"] = collectDataRefs;
					kwargs["strict_block_end"] = strictBlockEnd;
					kwargs["cross_insn_opt"] = crossInsnOpt;
					kwargs["load_from_ro_regions"] = loadFromRoRegions;

					if (numInst != -1) {
						kwargs["num_inst"] = numInst;
					}

					vex = vexEngine.attr("lift_vex")(**kwargs);
					size = nb::cast<size_t>(vex.attr("size"));

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
			throw nb::value_error("\"kwargs\" cannot be empty or unspecified");
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

	void Block::ParseVexInfo(nb::object vex)
	{
		if (!vex.is_none()) {
			m_Instructions = nb::cast<int32_t>(vex.attr("instructions"));
			// TODO:
			// m_InstructionAddrs = nb::cast<std::vector<uint64_t>>(vex.attr("instruction_addresses"));
			m_Size = nb::cast<uint32_t>(vex.attr("size"));
		}
	}

	nb::object Block::GetVex()
	{
		if (!m_Vex.has_value()) {
			nb::object vexEngine;
			if (m_Project.is_none()) {
				vexEngine = DEFAULT_VEX_ENGINE;
			}
			else {
				vexEngine = m_Project.attr("factory").attr("default_engine");
			}

			nb::object clemory;
			if (!m_Project.is_none()) {
				clemory = m_Project.attr("loader").attr("memory");
			}
			else {
				clemory = nb::none();
			}

			m_Vex = vexEngine.attr("lift_vex")(
				"clemory"_a = clemory,
				"insn_bytes"_a = nb::bytes((char*)m_Bytes, m_Size),
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
		nb::object project,
		nb::object arch,
		nb::object backupState,
		nb::object extraStopPoints,
		uint8_t optLevel = 1,
		int32_t numInst = -1,
		uint32_t traceflags = 0,
		bool strictBlockEnd = false,
		bool collectDataRefs = false,
		bool crossInsnOpt = true,
		bool loadFromRoRegions = false,
		nb::object initialRegs = nb::none()
	)
	{
		// TODO: set initial regs

		nb::object vexEngine;
		if (project.is_none()) {
			vexEngine = DEFAULT_VEX_ENGINE;
		}
		else {
			vexEngine = project.attr("factory").attr("default_engine");
		}

		nb::object vex = vexEngine.attr("lift_vex")(
			"clemory"_a=project.is_none()? nb::none(): project.attr("loader").attr("memory"),
			"state"_a=backupState,
			"insn_bytes"_a=nb::none(),
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
		nb::object VEXLifter = nb::module_::import_("angr").attr("engines").attr("vex").attr("VEXLifter");
		DEFAULT_VEX_ENGINE = VEXLifter(nb::none());
	}

	void Perf(const nb::kwargs& args)
	{
		;
	}

	void register_block_class(nb::module_ &m)
	{
		nb::class_<Block>(m, "Block")
			.def(nb::init<
				uint64_t,
				nb::object,
				nb::object,
				uint32_t,  // size
				uint8_t,
				int32_t,
				uint32_t,
				bool,
				bool,
				bool,
				bool,
				nb::object>())
			.def(nb::init<
				uint64_t,
				nb::object,
				nb::object,
				nb::bytes, // byteString
				uint8_t,
				int32_t,
				uint32_t,
				bool,
				bool,
				bool,
				bool,
				nb::object>())
			.def(nb::init<
				uint64_t,
				nb::object,
				nb::object,
				nb::object, // vex
				uint8_t,
				int32_t,
				uint32_t,
				bool,
				bool,
				bool,
				bool,
				nb::object>())
			.def(nb::init<
				uint64_t,
				const nb::kwargs&>())
			.def_prop_rw("addr", &Block::GetAddr, &Block::SetAddr)
			.def_prop_rw("size", &Block::GetSize, &Block::SetSize)
			.def_prop_rw("_bytes", &Block::GetBytes, &Block::SetBytes)
			.def_prop_rw("_vex", &Block::GetVexBlock, &Block::SetVexBlock, nb::rv_policy::reference)
			.def_prop_rw("_disassembly", &Block::GetDisassembly, &Block::SetDisassembly)
			.def_prop_rw("_capstone", &Block::GetCapstone, &Block::SetCapstone)
			.def_prop_rw("arch", &Block::GetArch, &Block::SetArch)
			.def_prop_rw("_instructions", &Block::GetInstructions, &Block::SetInstructions)
			.def_prop_rw("_instruction_addrs", &Block::GetInstructionAddrs, &Block::SetInstructionAddrs)
			.def_prop_rw("_opt_level", &Block::GetOptLevel, &Block::SetOptLevel)
			.def_prop_rw("_collect_data_refs", &Block::GetCollectDataRefs, &Block::SetCollectDataRefs)
			.def_prop_rw("_strict_block_end", &Block::GetStrictBlockEnd, &Block::SetStrictBlockEnd)
			.def_prop_rw("_cross_insn_opt", &Block::GetCrossInsnOpt, &Block::SetCrossInsnOpt)
			.def_prop_rw("_load_from_ro_regions", &Block::GetLoadFromRoRegions, &Block::SetLoadFromRoRegions)
			.def_prop_rw("_initial_regs", &Block::GetInitialRegs, &Block::SetInitialRegs)
			.def_prop_rw("_project", &Block::GetProject, &Block::SetProject)
			.def("_parse_vex_info", &Block::ParseVexInfo, "Parse information out of a VEX IRSB.")
			.def_prop_ro("vex", &Block::GetVex, nb::rv_policy::reference);
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
