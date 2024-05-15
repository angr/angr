#include <optional>
#include <vector>
#include <stdio.h>

namespace nb = nanobind;

namespace angr_c
{
	class Block
	{
	public:
		Block(
			uint64_t addr,
			nb::object project,
			nb::object arch,
			uint32_t size,
			uint8_t optLevel = 1,
			int32_t numInst = -1,
			uint32_t traceflags = 0,
			bool strictBlockEnd = false,
			bool collectDataRefs = false,
			bool crossInsnOpt = true,
			bool loadFromRoRegions = false,
			nb::object initialRegs = nb::none()
		);
		Block(
			uint64_t addr,
			nb::object project,
			nb::object arch,
			nb::bytes byteString,
			uint8_t optLevel = 1,
			int32_t numInst = -1,
			uint32_t traceflags = 0,
			bool strictBlockEnd = false,
			bool collectDataRefs = false,
			bool crossInsnOpt = true,
			bool loadFromRoRegions = false,
			nb::object initialRegs = nb::none()
		);
		Block(
			uint64_t addr,
			nb::object project,
			nb::object arch,
			nb::object vex,
			uint8_t optLevel = 1,
			int32_t numInst = -1,
			uint32_t traceflags = 0,
			bool strictBlockEnd = false,
			bool collectDataRefs = false,
			bool crossInsnOpt = true,
			bool loadFromRoRegions = false,
			nb::object initialRegs = nb::none()
		);
		Block(
			uint64_t addr,
			const nb::kwargs& kwargs
		);

		/*
		Block(uint64_t addr,
			nb::object project,
			nb::object arch,
			uint32_t size,
			nb::bytes byteString=nb::cast<nb::none>(Py_None),
			nb::object vex=nb::cast<nb::none>(Py_None),
			bool thumb=false,
			nb::object backupState=nb::cast<nb::none>(Py_None),
			nb::object extraStopPoints=nb::cast<nb::none>(Py_None),
			uint8_t optLevel=1,
			int32_t numInst=-1,
			uint32_t traceflags=0,
			bool strictBlockEnd=false,
			bool collectDataRefs=false,
			bool crossInsnOpt=true,
			bool loadFromRoRegions=false,
			nb::object initialRegs=nb::cast<nb::none>(Py_None));*/
		~Block();

		uint64_t GetAddr() const { return m_Addr; }
		void SetAddr(uint64_t addr) { m_Addr = addr; }
		int32_t GetSize() const { return m_Size; }
		void SetSize(int32_t size) { m_Size = size; }
		uint8_t* GetBytes() const;
		void SetBytes(uint8_t* data, bool ownBytes);
		nb::object GetVexBlock() const { return *m_Vex; }
		void SetVexBlock(nb::object vex) { m_Vex = vex; }
		nb::object GetDisassembly() const { return m_Disassembly; }
		void SetDisassembly(nb::object disassembly) { m_Disassembly = disassembly; }
		nb::object GetCapstone() const { return m_Capstone; }
		void SetCapstone(nb::object capstone) { m_Capstone = capstone; }
		nb::object GetArch() const { return m_Arch; }
		void SetArch(nb::object arch) { m_Arch = arch; }
		int32_t GetInstructions() const { return m_Instructions; }
		void SetInstructions(int32_t instructions) { m_Instructions = instructions; }
		std::vector<uint64_t>& GetInstructionAddrs() { return m_InstructionAddrs; }
		void SetInstructionAddrs(std::vector<uint64_t> addrs) { m_InstructionAddrs = addrs; }
		uint8_t GetOptLevel() const { return m_OptLevel; }
		void SetOptLevel(uint8_t optLevel) { m_OptLevel = optLevel; }
		bool GetCollectDataRefs() const { return m_CollectDataRefs; }
		void SetCollectDataRefs(bool collectDataRefs) { m_CollectDataRefs = collectDataRefs; }
		bool GetStrictBlockEnd() const { return m_StrictBlockEnd; }
		void SetStrictBlockEnd(bool strictBlockEnd) { m_StrictBlockEnd = strictBlockEnd; }
		bool GetCrossInsnOpt() const { return m_CrossInsnOpt; }
		void SetCrossInsnOpt(bool crossInsnOpt) { m_CrossInsnOpt = crossInsnOpt; }
		bool GetLoadFromRoRegions() const { return m_LoadFromRoRegions; }
		void SetLoadFromRoRegions(bool loadFromRoRegions) { m_LoadFromRoRegions = loadFromRoRegions; }
		nb::object GetInitialRegs() const { return m_InitialRegs; }
		void SetInitialRegs(nb::object initialRegs) { m_InitialRegs = initialRegs; }
		nb::object GetProject() const { return m_Project; }
		void SetProject(nb::object project) { m_Project = project; }

		void ParseVexInfo(nb::object vex);
		nb::object GetVex();

	private:
		uint64_t m_Addr;
		int m_Size;
		uint8_t* m_Bytes;
		bool m_OwnBytes;
		bool m_Thumb;
		std::optional<nb::object> m_Vex;
		nb::object m_Disassembly;
		nb::object m_Capstone;
		nb::object m_Arch;
		int32_t m_Instructions;
		uint32_t m_Traceflags;
		std::vector<uint64_t> m_InstructionAddrs;
		uint8_t m_OptLevel;
		bool m_CollectDataRefs;
		bool m_StrictBlockEnd;
		bool m_CrossInsnOpt;
		bool m_LoadFromRoRegions;
		nb::object m_InitialRegs;
		nb::object m_Project;
	};

	void initialize_block();
	void register_block_class(nb::module_& m);
}