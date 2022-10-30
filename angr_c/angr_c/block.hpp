#include <optional>

namespace py = pybind11;

namespace angr_c
{
	class Block
	{
	public:
		Block(
			uint64_t addr,
			py::object project,
			py::object arch,
			uint32_t size,
			uint8_t optLevel = 1,
			int32_t numInst = -1,
			uint32_t traceflags = 0,
			bool strictBlockEnd = false,
			bool collectDataRefs = false,
			bool crossInsnOpt = true,
			bool loadFromRoRegions = false,
			py::object initialRegs = py::none()
		);
		Block(
			uint64_t addr,
			py::object project,
			py::object arch,
			py::bytes byteString,
			uint8_t optLevel = 1,
			int32_t numInst = -1,
			uint32_t traceflags = 0,
			bool strictBlockEnd = false,
			bool collectDataRefs = false,
			bool crossInsnOpt = true,
			bool loadFromRoRegions = false,
			py::object initialRegs = py::none()
		);
		Block(
			uint64_t addr,
			py::object project,
			py::object arch,
			py::object vex,
			uint8_t optLevel = 1,
			int32_t numInst = -1,
			bool strictBlockEnd = false,
			bool collectDataRefs = false,
			bool crossInsnOpt = true,
			bool loadFromRoRegions = false,
			py::object initialRegs = py::none()
		);
		Block(
			uint64_t addr,
			const py::kwargs& kwargs
		);

		/*
		Block(uint64_t addr,
			py::object project,
			py::object arch,
			uint32_t size,
			py::bytes byteString=py::cast<py::none>(Py_None),
			py::object vex=py::cast<py::none>(Py_None),
			bool thumb=false,
			py::object backupState=py::cast<py::none>(Py_None),
			py::object extraStopPoints=py::cast<py::none>(Py_None),
			uint8_t optLevel=1,
			int32_t numInst=-1,
			uint32_t traceflags=0,
			bool strictBlockEnd=false,
			bool collectDataRefs=false,
			bool crossInsnOpt=true,
			bool loadFromRoRegions=false,
			py::object initialRegs=py::cast<py::none>(Py_None));*/
		~Block();

		uint64_t GetAddr() const { return m_Addr; }
		void SetAddr(uint64_t addr) { m_Addr = addr; }
		int32_t GetSize() const { return m_Size; }
		void SetSize(int32_t size) { m_Size = size; }
		uint8_t* GetBytes() const;
		void SetBytes(uint8_t* data, bool ownBytes);
		py::object GetVexBlock() const { return *m_Vex; }
		void SetVexBlock(py::object vex) { m_Vex = vex; }
		py::object GetDisassembly() const { return m_Disassembly; }
		void SetDisassembly(py::object disassembly) { m_Disassembly = disassembly; }
		py::object GetCapstone() const { return m_Capstone; }
		void SetCapstone(py::object capstone) { m_Capstone = capstone; }
		py::object GetArch() const { return m_Arch; }
		void SetArch(py::object arch) { m_Arch = arch; }
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
		py::object GetInitialRegs() const { return m_InitialRegs; }
		void SetInitialRegs(py::object initialRegs) { m_InitialRegs = initialRegs; }
		py::object GetProject() const { return m_Project; }
		void SetProject(py::object project) { m_Project = project; }

		void ParseVexInfo(py::object vex);
		py::object GetVex();

	private:
		uint64_t m_Addr;
		int32_t m_Size;
		uint8_t* m_Bytes;
		bool m_OwnBytes;
		bool m_Thumb;
		std::optional<py::object> m_Vex;
		py::object m_Disassembly;
		py::object m_Capstone;
		py::object m_Arch;
		int32_t m_Instructions;
		std::vector<uint64_t> m_InstructionAddrs;
		uint8_t m_OptLevel;
		bool m_CollectDataRefs;
		bool m_StrictBlockEnd;
		bool m_CrossInsnOpt;
		bool m_LoadFromRoRegions;
		py::object m_InitialRegs;
		py::object m_Project;
	};

	void initialize_block();
	void register_block_class(py::module_& m);
}