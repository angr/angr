#ifndef SIM_UNICORN_HPP
#define SIM_UNICORN_HPP

extern "C" {
	#include <libvex_guest_offsets.h>
}

// Maximum size of a qemu/unicorn basic block
// See State::step for why this is necessary
static const uint32_t MAX_BB_SIZE = 800;

static const uint8_t MAX_MEM_ACCESS_SIZE = 8;

// The size of the longest register in archinfo's uc_regs for all architectures
static const uint8_t MAX_REGISTER_BYTE_SIZE = 32;

static const uint16_t ANGR_PAGE_SIZE = 0x1000;
static const uint8_t PAGE_SHIFT = 12;

typedef uint64_t address_t;
typedef uint64_t unicorn_reg_id_t;
typedef int64_t vex_reg_offset_t;
typedef int64_t vex_tmp_id_t;

enum simos_t: uint8_t {
	SIMOS_CGC = 0,
	SIMOS_LINUX = 1,
	SIMOS_OTHER = 2,
};

enum taint_t: uint8_t {
	TAINT_NONE = 0,
	TAINT_SYMBOLIC = 1, // this should be 1 to match the UltraPage impl
	TAINT_DIRTY = 2,
};

enum taint_entity_enum_t: uint8_t {
	TAINT_ENTITY_REG = 0,
	TAINT_ENTITY_TMP = 1,
	TAINT_ENTITY_MEM = 2,
	TAINT_ENTITY_NONE = 3,
};

enum taint_status_result_t: uint8_t {
	TAINT_STATUS_CONCRETE = 0,
	TAINT_STATUS_DEPENDS_ON_READ_FROM_SYMBOLIC_ADDR,
	TAINT_STATUS_SYMBOLIC,
};

struct taint_entity_t {
	taint_entity_enum_t entity_type;

	// The actual entity data. Only one of them is valid at a time depending on entity_type.
	// This could have been in a union but std::vector has a constructor and datatypes with
	// constructors are not allowed inside unions
	// VEX Register ID
	vex_reg_offset_t reg_offset;
	// VEX temp ID
	vex_tmp_id_t tmp_id;
	// List of registers and VEX temps. Used in case of memory references.
	std::vector<taint_entity_t> mem_ref_entity_list;
	// Instruction in which the entity is used. Used for taint sinks; ignored for taint sources.
	address_t instr_addr;
	// Index of VEX statement that last modified this entity.
	int64_t stmt_idx;
	// Index of statement where entity is used. Valid only for memory reads to find info of value read. Ignored in other
	// cases.
	int64_t sink_stmt_idx;
	int64_t value_size;

	taint_entity_t() {
		reset();
	}

	void reset() {
		reg_offset = -1;
		tmp_id = -1;
		mem_ref_entity_list.clear();
		instr_addr = 0;
		stmt_idx = -1;
		sink_stmt_idx = -1;
		value_size = -1;
	}

	bool operator==(const taint_entity_t &other_entity) const {
		if (entity_type != other_entity.entity_type) {
			return false;
		}
		if (entity_type == TAINT_ENTITY_REG) {
			return (reg_offset == other_entity.reg_offset);
		}
		if (entity_type == TAINT_ENTITY_TMP) {
			return (tmp_id == other_entity.tmp_id);
		}
		return (mem_ref_entity_list == other_entity.mem_ref_entity_list);
	}

	// Hash function for use in unordered_map. Defined in class and invoked from hash struct.
	// TODO: Check performance of hash and come up with better one if too bad
	std::size_t operator()(const taint_entity_t &taint_entity) const {
		if (taint_entity.entity_type == TAINT_ENTITY_REG) {
			return std::hash<uint64_t>()(taint_entity.entity_type) ^
				   std::hash<uint64_t>()(taint_entity.reg_offset);
		}
		else if (taint_entity.entity_type == TAINT_ENTITY_TMP) {
			return std::hash<uint64_t>()(taint_entity.entity_type) ^
				   std::hash<uint64_t>()(taint_entity.tmp_id);
		}
		else if (taint_entity.entity_type == TAINT_ENTITY_MEM) {
			std::size_t taint_entity_hash = std::hash<uint64_t>()(taint_entity.entity_type);
			for (auto &sub_entity: taint_entity.mem_ref_entity_list) {
				taint_entity_hash ^= sub_entity.operator()(sub_entity);
			}
			return taint_entity_hash;
		}
		else {
			return std::hash<uint64_t>()(taint_entity.entity_type);
		}
	}
};

// Hash function for unordered_map. Needs to be defined this way in C++.
namespace std {
	template <>
	struct hash<taint_entity_t> {
		std::size_t operator()(const taint_entity_t &entity) const {
			return entity.operator()(entity);
		}
	};
}

struct memory_value_t {
	uint64_t address;
	uint8_t value;
	bool is_value_set;
	bool is_value_symbolic;

	bool operator==(const memory_value_t &other_mem_value) const {
		if ((address != other_mem_value.address) || (value != other_mem_value.value) ||
			(is_value_symbolic != other_mem_value.is_value_symbolic)) {
			return false;
		}
		return true;
	}

	memory_value_t() {
		address = 0;
		value = 0;
		is_value_set = false;
		is_value_symbolic = false;
	}
};

struct mem_read_result_t {
	address_t first_byte_addr;
	std::vector<memory_value_t> memory_values;
	bool is_mem_read_symbolic;
	uint32_t read_size;

	mem_read_result_t() {
		first_byte_addr = 0;
		memory_values.clear();
		is_mem_read_symbolic = false;
		read_size = 0;
	}
};

struct register_value_t {
	uint64_t offset;
	uint8_t value[MAX_REGISTER_BYTE_SIZE];
	int64_t size;

	register_value_t() {
		offset = 0;
		size = -1;
		memset(value, 0, MAX_REGISTER_BYTE_SIZE);
	}

	bool operator==(const register_value_t &reg_value) const {
		if (offset != reg_value.offset) {
			return false;
		}
		return (memcmp(value, reg_value.value, MAX_REGISTER_BYTE_SIZE) == 0);
	}

	std::size_t operator()(const register_value_t &reg_value) const {
		return std::hash<uint64_t>()(reg_value.offset);
	}
};

namespace std {
	template <>
	struct hash<register_value_t> {
		std::size_t operator()(const register_value_t &value) const {
			return value.operator()(value);
		}
	};
}

struct vex_stmt_details_t {
	address_t instr_addr;
	int64_t stmt_idx;
	int64_t mem_write_addr;
	int64_t mem_write_size;
	bool has_concrete_memory_dep;
	bool has_symbolic_memory_dep;
	bool has_read_from_symbolic_addr;
	bool has_memory_write;
	// Mark fields as mutable so that they can be updated after inserting into std::set
	mutable memory_value_t *memory_values;
	mutable uint64_t memory_values_count;
	std::unordered_set<address_t> symbolic_mem_deps;
	std::set<vex_stmt_details_t> stmt_deps;
	std::unordered_set<register_value_t> reg_deps;

	vex_stmt_details_t() {
		stmt_idx = -1;
		has_concrete_memory_dep = false;
		has_symbolic_memory_dep = false;
		has_read_from_symbolic_addr = false;
		has_memory_write = false;
		stmt_deps.clear();
		mem_write_addr = -1;
		mem_write_size = -1;
		reg_deps.clear();
	}

	bool operator==(const vex_stmt_details_t &other_stmt) const {
		if ((instr_addr != other_stmt.instr_addr) || (stmt_idx != other_stmt.stmt_idx) ||
			(has_concrete_memory_dep != other_stmt.has_concrete_memory_dep) || (reg_deps != other_stmt.reg_deps) ||
			(has_symbolic_memory_dep != other_stmt.has_symbolic_memory_dep) || (stmt_deps != other_stmt.stmt_deps)) {
				return false;
		}
		return true;
	}

	bool operator<(const vex_stmt_details_t &other_stmt) const {
		return (instr_addr < other_stmt.instr_addr) || (stmt_idx < other_stmt.stmt_idx);
	}
};

struct block_details_t {
	address_t block_addr;
	uint64_t block_size;
	int64_t block_trace_ind;
	bool has_symbolic_exit;
	bool marks_vex_cc_reg_symbolic;
	std::vector<vex_stmt_details_t> symbolic_stmts;
	std::vector<vex_stmt_details_t> vex_cc_reg_setter_details;
	bool vex_lift_failed;
	// A pointer to VEX lift result is stored only to avoid lifting twice on ARM. All blocks are lifted on ARM to check
	// if they end in syscall. Remove it after syscalls are correctly setup on ARM in native interface itself.
	VEXLiftResult *vex_lift_result;

	block_details_t() {
		reset();
	}

	void reset() {
		block_addr = 0;
		block_size = 0;
		block_trace_ind = -1;
		has_symbolic_exit = false;
		marks_vex_cc_reg_symbolic = false;
		symbolic_stmts.clear();
		vex_cc_reg_setter_details.clear();
		vex_lift_failed = false;
		vex_lift_result = NULL;
	}
};

// sym_block_details_t and sym_vex_stmt_details_t are used to store data, references to which are returned to state plugin
struct sym_vex_stmt_details_t {
	int64_t stmt_idx;
	bool has_memory_dep;
	memory_value_t *memory_values;
	uint64_t memory_values_count;

	bool operator==(const sym_vex_stmt_details_t &other_instr) const {
		if ((stmt_idx != other_instr.stmt_idx) || (has_memory_dep != other_instr.has_memory_dep) ||
			(memory_values_count != other_instr.memory_values_count)) {
				return false;
		}
		for (auto counter = 0; counter < memory_values_count; counter++) {
			if (!(memory_values[counter] == other_instr.memory_values[counter])) {
				return false;
			}
		}
		return true;
	}

	bool operator<(const sym_vex_stmt_details_t &other_instr) const {
		return (stmt_idx < other_instr.stmt_idx);
	}
};

struct sym_block_details_t {
	address_t block_addr;
	uint64_t block_size;
	int64_t block_trace_ind;
	bool has_symbolic_exit;
	std::vector<sym_vex_stmt_details_t> symbolic_stmts;
	std::vector<register_value_t> register_values;

	sym_block_details_t() {
		reset();
	}

	void reset() {
		block_addr = 0;
		block_size = 0;
		block_trace_ind = -1;
		has_symbolic_exit = false;
		symbolic_stmts.clear();
		register_values.clear();
	}
};

// This struct is used only to return data to the state plugin since ctypes doesn't natively handle
// C++ STL containers
struct sym_block_details_ret_t {
	uint64_t block_addr;
	uint64_t block_size;
	int64_t block_trace_ind;
	bool has_symbolic_exit;
    sym_vex_stmt_details_t *symbolic_stmts;
    uint64_t symbolic_stmts_count;
    register_value_t *register_values;
    uint64_t register_values_count;
};

enum stop_t {
	STOP_NORMAL=0,
	STOP_STOPPOINT,
	STOP_ERROR,
	STOP_SYSCALL,
	STOP_EXECNONE,
	STOP_ZEROPAGE,
	STOP_NOSTART,
	STOP_SEGFAULT,
	STOP_ZERO_DIV,
	STOP_NODECODE,
	STOP_HLT,
	STOP_VEX_LIFT_FAILED,
	STOP_SYMBOLIC_PC,
	STOP_SYMBOLIC_READ_ADDR,
	STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED,
	STOP_SYMBOLIC_WRITE_ADDR,
	STOP_SYMBOLIC_BLOCK_EXIT_CONDITION,
	STOP_SYMBOLIC_BLOCK_EXIT_TARGET,
	STOP_UNSUPPORTED_STMT_PUTI,
	STOP_UNSUPPORTED_STMT_STOREG,
	STOP_UNSUPPORTED_STMT_LOADG,
	STOP_UNSUPPORTED_STMT_CAS,
	STOP_UNSUPPORTED_STMT_LLSC,
	STOP_UNSUPPORTED_STMT_DIRTY,
	STOP_UNSUPPORTED_STMT_UNKNOWN,
	STOP_UNSUPPORTED_EXPR_GETI,
	STOP_UNSUPPORTED_EXPR_UNKNOWN,
	STOP_UNKNOWN_MEMORY_WRITE_SIZE,
	STOP_SYSCALL_ARM,
	STOP_X86_CPUID,
};

typedef std::vector<std::pair<taint_entity_t, std::unordered_set<taint_entity_t>>> taint_vector_t;

struct vex_stmt_taint_entry_t {
	taint_entity_t sink;
	std::unordered_set<taint_entity_t> sources;

	// List of taint entities in ITE expression's condition, if any
	std::unordered_set<taint_entity_t> ite_cond_entity_list;

	// Indicates if statement has a floating point operation for which taint should not be propagated
	bool floating_point_op_skip;

	// Count number of bytes read from memory by the instruction
	uint32_t mem_read_size;

	bool has_memory_read;

	// Count number of bytes written to memory by the instruction
	uint32_t mem_write_size;

	// Is statement a VEX exit?
	bool is_exit;

	bool operator==(const vex_stmt_taint_entry_t &other_stmt) const {
		return (sink == other_stmt.sink) && (sources == other_stmt.sources) &&
			   (ite_cond_entity_list == other_stmt.ite_cond_entity_list) &&
			   (has_memory_read == other_stmt.has_memory_read) &&
			   (is_exit == other_stmt.is_exit) && (floating_point_op_skip == other_stmt.floating_point_op_skip) &&
			   (mem_read_size == other_stmt.mem_read_size) &&
			   (mem_write_size == other_stmt.mem_write_size);
	}

	vex_stmt_taint_entry_t() {
		reset();
	}

	void reset() {
		sink.reset();
		sources.clear();
		ite_cond_entity_list.clear();
		floating_point_op_skip = false;
		has_memory_read = false;
		is_exit = false;
		mem_read_size = 0;
		mem_write_size = 0;
		return;
	}
};

struct block_taint_entry_t {
	std::map<int64_t, vex_stmt_taint_entry_t> block_stmts_taint_data;
	bool has_cpuid_instr;
	bool has_exit_stmt;
	bool has_unsupported_stmt_or_expr_type;
	stop_t unsupported_stmt_stop_reason;
	std::unordered_set<taint_entity_t> block_next_entities;
	std::unordered_set<int64_t> vex_cc_setter_stmts;

	block_taint_entry_t() {
		block_stmts_taint_data.clear();
		has_cpuid_instr = false;
		has_exit_stmt = false;
		has_unsupported_stmt_or_expr_type = false;
		block_next_entities.clear();
		vex_cc_setter_stmts.clear();
	}

	bool operator==(const block_taint_entry_t &other_entry) const {
		return (block_stmts_taint_data == other_entry.block_stmts_taint_data) &&
			   (has_cpuid_instr == other_entry.has_cpuid_instr) &&
			   (has_exit_stmt == other_entry.has_exit_stmt) &&
			   (vex_cc_setter_stmts == other_entry.vex_cc_setter_stmts) &&
			   (block_next_entities == other_entry.block_next_entities);
	}
};

struct stop_details_t {
	stop_t stop_reason;
	address_t block_addr;
	uint64_t block_size;
};

struct processed_vex_expr_t {
	std::unordered_set<taint_entity_t> taint_sources;
	std::unordered_set<taint_entity_t> ite_cond_entities;
	bool has_floating_point_op_to_skip;
	bool has_unsupported_expr;
	stop_t unsupported_expr_stop_reason;
	uint32_t mem_read_size;
	int64_t value_size;

	processed_vex_expr_t() {
		reset();
	}

	void reset() {
		taint_sources.clear();
		ite_cond_entities.clear();
		has_floating_point_op_to_skip = false;
		has_unsupported_expr = false;
		mem_read_size = 0;
		value_size = -1;
	}
};

struct CachedPage {
	size_t size;
	uint8_t *bytes;
	uint64_t perms;
};

typedef std::map<address_t, CachedPage> PageCache;

struct caches_t {
	PageCache *page_cache;
};

typedef taint_t PageBitmap[ANGR_PAGE_SIZE];
typedef std::unordered_map<address_t, block_taint_entry_t> BlockTaintCache;
std::map<uint64_t, caches_t> global_cache;

typedef std::unordered_set<vex_reg_offset_t> RegisterSet;
typedef std::unordered_set<vex_tmp_id_t> TempSet;

struct fd_data {
	char *bytes;
	taint_t *taints;
	uint64_t curr_pos;
	uint64_t len;

	fd_data(char *fd_bytes, taint_t *fd_taints, uint64_t fd_len, uint64_t fd_read_pos) {
		bytes = fd_bytes;
		taints = fd_taints;
		curr_pos = fd_read_pos;
		len = fd_len;
	}
};

struct mem_write_t {
	address_t address;
	std::vector<uint8_t> value;
	int size;
	std::vector<taint_t> previous_taint;
};

struct mem_write_taint_t {
	address_t instr_addr;
	bool is_symbolic;
	uint32_t size;

	mem_write_taint_t(address_t write_instr, bool symbolic, uint32_t write_size) {
		instr_addr = write_instr;
		is_symbolic = symbolic;
		size = write_size;
	}
};

struct mem_update_t {
	address_t address;
	uint64_t length;
	struct mem_update_t *next;
};

struct transmit_record_t {
	uint32_t fd;
	void *data;
	uint32_t count;
};

// These prototypes may be found in <unicorn/unicorn.h> by searching for "Callback"
static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static bool hook_mem_unmapped(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static bool hook_mem_prot(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void hook_block(uc_engine *uc, uint64_t address, int32_t size, void *user_data);
static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data);

class State {
	uc_engine *uc;
	PageCache *page_cache;
	BlockTaintCache block_taint_cache;
	bool hooked;

	uc_context *saved_regs;

	std::vector<mem_write_t> mem_writes;
	// List of all memory writes and their taint status
	// Memory write instruction address -> is_symbolic
	// TODO: Need to modify memory write taint handling for architectures that perform multiple
	// memory writes in a single instruction
	std::vector<mem_write_taint_t> block_mem_writes_taint_data;

	// List of instructions in a block that should be executed symbolically. These are stored
	// separately for easy rollback in case of errors.
	block_details_t curr_block_details;

	// List of symbolic statements in processed basic blocks that need not be re-executed. Will be removed on commit.
	std::unordered_map<uint32_t, std::unordered_set<uint32_t>> symbolic_stmts_to_erase;

	// Similar to memory reads in a block, we track the state of registers and VEX temps when
	// propagating taint in a block for easy rollback if we need to abort due to read from/write to
	// a symbolic address
	RegisterSet block_symbolic_registers, block_concrete_registers;
	TempSet block_symbolic_temps;

	// Set of register dependencies that were concrete before a VEX statement was executed
	std::unordered_map<int64_t, std::unordered_map<vex_reg_offset_t, int64_t>> block_stmt_concrete_regs;

	// List of instructions that should be executed symbolically
	std::vector<block_details_t> blocks_with_symbolic_stmts;

	// the latter part of the pair is a pointer to the page data if the page is direct-mapped, otherwise NULL
	std::map<address_t, std::pair<taint_t *, uint8_t *>> active_pages;
	//std::map<uint64_t, taint_t *> active_pages;
	std::set<uint64_t> stop_points;

	address_t trace_last_block_addr;
	int64_t trace_last_block_curr_count;
	int64_t trace_last_block_tot_count;

	address_t taint_engine_stop_mem_read_instruction;
	int64_t taint_engine_next_stmt_idx;
	uint32_t taint_engine_stop_mem_read_size;
	bool symbolic_read_in_progress;

	address_t unicorn_next_instr_addr;

	// Vector of values from previous memory reads. Serves as archival storage for pointers in details
	// of symbolic instructions returned via ctypes to Python land.
	std::vector<std::vector<memory_value_t>> archived_memory_values;

	// Pointer to memory writes' data passed to Python land
	mem_update_t *mem_updates_head;

	// Input fd bytes for tracing in unicorn
	std::unordered_map<uint64_t, fd_data> fd_details;

	// Random syscall data
	std::vector<std::pair<int, int>> random_bytes;

	// OS being simulated
	simos_t simos;

	// Determine if symbolic memory addresses should be handled or not
	bool handle_symbolic_addrs;

	// Determine if symbolic conditions should be handled or not
	bool handle_symbolic_conditions;

	// Count of blocks executed in native interface
	int64_t executed_blocks_count;

	// Details of symbolic memory dependencies of all VEX statements to be re-executed. Stores address and number of VEX
	// statements the location is a dependency of. Only dependencies of statements that will be re-executed are tracked.
	std::unordered_map<address_t, uint64_t> symbolic_mem_deps;
	// Symbolic memory dependencies of all symbolic VEX statements in current block.
	std::unordered_set<address_t> block_symbolic_mem_deps;

	// List of all values read from memory in current block
	std::vector<memory_value_t> block_mem_reads_data;

	// Result of all memory reads executed. VEX statement ID -> memory read result
	std::unordered_map<int64_t, mem_read_result_t> block_mem_reads_map;

	// List of memory read addresses and VEX statements that read values from them
	std::unordered_map<address_t, std::unordered_set<int64_t>> block_mem_read_addr_details;

	// Private functions

	std::pair<taint_t *, uint8_t *> page_lookup(address_t address) const;

	void compute_slice_of_stmt(vex_stmt_details_t &instr);
	vex_stmt_details_t compute_vex_stmt_details(const vex_stmt_taint_entry_t &vex_stmt_taint_entry);
	void get_register_value(uint64_t vex_reg_offset, uint8_t *out_reg_value, bool from_saved_context=false) const;
	// Return list of all dependent instructions including dependencies of those dependent instructions
	std::set<vex_stmt_details_t> get_list_of_dep_stmts(const vex_stmt_details_t &instr) const;

	// Returns a pair (taint sources, list of taint entities in ITE condition expression)
	processed_vex_expr_t process_vex_expr(IRExpr *expr, IRTypeEnv *vex_block_tyenv, address_t instr_addr,
										  int64_t curr_stmt_idx, const std::unordered_map<taint_entity_t, int> &entity_setter,
										  bool is_exit_stmt);

	// Determine cumulative result of taint statuses of a set of taint entities
	// EG: This is useful to determine the taint status of a taint sink given it's taint sources
	taint_status_result_t get_final_taint_status(const std::unordered_set<taint_entity_t> &taint_sources) const;

	// A vector version of get_final_taint_status for checking mem_ref_entity_list which can't be an
	// unordered_set
	taint_status_result_t get_final_taint_status(const std::vector<taint_entity_t> &taint_sources) const;

	int32_t get_vex_expr_result_size(IRExpr *expr, IRTypeEnv* tyenv) const;

	bool is_block_next_target_symbolic() const;
	bool is_symbolic_register(vex_reg_offset_t reg_offset, int64_t reg_size) const;
	bool is_symbolic_temp(vex_tmp_id_t temp_id) const;

	bool is_cpuid_in_block(address_t block_address, int32_t block_size);
	VEXLiftResult* lift_block(address_t block_address, int32_t block_size);

	void mark_register_symbolic(vex_reg_offset_t reg_offset, int64_t reg_size);
	void mark_register_concrete(vex_reg_offset_t reg_offset, int64_t reg_size);
	void mark_temp_symbolic(vex_tmp_id_t temp_id);

	void process_vex_block(IRSB *vex_block, address_t address);

	void set_deps_mem_addr_status(const taint_entity_t &entity, vex_stmt_taint_entry_t &instr_taint_entry);
	void update_deps_mem_addr_status(const taint_entity_t &entity, vex_stmt_taint_entry_t &instr_taint_entry);

	void propagate_taints();
	void propagate_taint_of_one_stmt(const vex_stmt_taint_entry_t &instr_taint_entry);

	// Save values of concrete memory reads performed by an instruction and it's dependencies
	void save_concrete_memory_deps(vex_stmt_details_t &instr);

	// Save memory values of concrete deps
	void save_mem_values(mem_read_result_t &mem_read_result);

	// Inline functions

	inline bool is_valid_dependency_register(vex_reg_offset_t reg_offset) const {
		return ((artificial_vex_registers.count(reg_offset) == 0) && (blacklisted_registers.count(reg_offset) == 0));
	}

	inline bool is_blacklisted_register(vex_reg_offset_t reg_offset) const {
		return (blacklisted_registers.count(reg_offset) > 0);
	}

	inline unsigned int arch_pc_reg_vex_offset() const {
		switch (arch) {
			case UC_ARCH_X86:
				return unicorn_mode == UC_MODE_64 ? OFFSET_amd64_RIP : OFFSET_x86_EIP;
			case UC_ARCH_ARM:
				return OFFSET_arm_R15T;
			case UC_ARCH_ARM64:
				return OFFSET_arm64_PC;
			case UC_ARCH_MIPS:
				return unicorn_mode == UC_MODE_64 ? OFFSET_mips64_PC : OFFSET_mips32_PC;
			default:
				return -1;
		}
	}

	inline int arch_pc_reg() const {
		switch (arch) {
			case UC_ARCH_X86:
				return unicorn_mode == UC_MODE_64 ? UC_X86_REG_RIP : UC_X86_REG_EIP;
			case UC_ARCH_ARM:
				return UC_ARM_REG_PC;
			case UC_ARCH_ARM64:
				return UC_ARM64_REG_PC;
			case UC_ARCH_MIPS:
				return UC_MIPS_REG_PC;
			default:
				return -1;
		}
	}

	inline int arch_sp_reg() const {
		switch (arch) {
			case UC_ARCH_X86:
				return unicorn_mode == UC_MODE_64 ? UC_X86_REG_RSP : UC_X86_REG_ESP;
			case UC_ARCH_ARM:
				return UC_ARM_REG_SP;
			case UC_ARCH_ARM64:
				return UC_ARM64_REG_SP;
			case UC_ARCH_MIPS:
				return UC_MIPS_REG_SP;
			default:
				return -1;
		}
	}

	inline bool is_thumb_mode() const {
		// unicorn engine mode doesn't reflect the current execution mode correctly and so we check T bit in the CPSR
		// register to determine if we are executing in ARM or THUMB mode.
		uint32_t cpsr_reg_val;
		uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr_reg_val);
		return ((cpsr_reg_val & 32) != 0);
	}

	public:
		std::vector<address_t> bbl_addrs;
		std::vector<address_t> stack_pointers;
		std::unordered_set<address_t> executed_pages;
		std::unordered_set<address_t>::iterator *executed_pages_iterator;
		uint64_t syscall_count;
		std::vector<transmit_record_t> transmit_records;
		uint64_t cur_steps, max_steps;
		uc_hook h_read, h_write, h_block, h_prot, h_unmap, h_intr;
		bool stopped;

		bool ignore_next_block;
		bool ignore_next_selfmod;
		address_t cur_address;
		int32_t cur_size;

		uc_arch arch;
		uc_mode unicorn_mode;
		bool interrupt_handled;
		int32_t cgc_random_sysno;
		uint64_t cgc_random_bbl;
		int32_t cgc_receive_sysno;
		uint64_t cgc_receive_bbl;
		uint64_t cgc_receive_max_size;
		int32_t cgc_transmit_sysno;
		uint64_t cgc_transmit_bbl;
		bool handle_symbolic_syscalls;

		VexArch vex_guest;
		VexArchInfo vex_archinfo;
		RegisterSet symbolic_registers; // tracking of symbolic registers
		RegisterSet blacklisted_registers;  // Registers which shouldn't be saved as a concrete dependency
		// Mapping of VEX offsets to unicorn register IDs and register sizes
		std::map<vex_reg_offset_t, std::pair<unicorn_reg_id_t, uint64_t>> vex_to_unicorn_map;
		// VEX CC registers
		std::unordered_map<vex_reg_offset_t, uint64_t> vex_cc_regs;
		RegisterSet artificial_vex_registers; // Artificial VEX registers
		// VEX flag register offset, corresponding unicorn register ID and bitmask for CPU flags
		std::unordered_map<vex_reg_offset_t, std::pair<uint64_t, uint64_t>> cpu_flags;
		stop_details_t stop_details;

		// Address of all bytes to which symbolic value is written in this run and number of writes to them
		std::unordered_map<address_t, uint64_t> symbolic_mem_writes;

		// Address of all bytes to which symbolic value is written by this block
		std::unordered_set<address_t> block_symbolic_mem_writes;

		// Address of concrete writes in block to re-execute. Value will be saved in commit by when write will be
		// complete
		std::unordered_set<uint64_t> block_concrete_writes_to_reexecute;

		// Concrete writes to re-execute to avoid write-write conflicts
		std::unordered_map<uint64_t, uint8_t> concrete_writes_to_reexecute;

		// Concrete writes performed by syscalls. Used to determine if any write-write conflicts occur when syscall is
		// re-executed.
		std::unordered_set<address_t> syscall_concrete_writes;

		// List of instructions that should be executed symbolically; used to store data to return
		std::vector<sym_block_details_t> block_details_to_return;

		bool track_bbls;
		bool track_stack;

		uc_cb_eventmem_t py_mem_callback;

		// List of floating point operations
		std::unordered_set<uint64_t> fp_ops_to_avoid;

		// Floating point registers
		std::pair<uint64_t, uint64_t> fp_reg_vex_data;

		State(uc_engine *_uc, uint64_t cache_key, simos_t curr_os, bool symb_addrs, bool symb_cond, bool symb_syscalls);

		~State() {
			for (auto it = active_pages.begin(); it != active_pages.end(); it++) {
				// only delete if not direct-mapped
				if (!it->second.second) {
					// delete should use the bracket operator since PageBitmap is an array typedef
					delete[] it->second.first;
				}
			}
			mem_update_t *next;
			for (mem_update_t *cur = mem_updates_head; cur; cur = next) {
				next = cur->next;
				delete cur;
			}
			active_pages.clear();
			mem_updates_head = NULL;
			uc_free(saved_regs);
		}

		void hook();

		void unhook();

		uc_err start(address_t pc, uint64_t step = 1);

		void stop(stop_t reason, bool do_commit=false, uint64_t commit_addr=0);

		void step(address_t current_address, int32_t size, bool check_stop_points=true);

		/*
		* commit all memory actions.
		*/
		void commit(uint64_t address);

		/*
		 * undo recent memory actions.
		 */
		void rollback();

		/*
		 * allocate a new PageBitmap and put into active_pages.
		 */
		void page_activate(address_t address, uint8_t *taint, uint8_t *data);

		/*
		 * record consecutive dirty bit range, return a linked list of ranges
		 */
		mem_update_t *sync();

		/*
		 * set details of the last block of trace
		 */
		void set_last_block_details(address_t block_addr, int64_t curr_count, int64_t tot_count);

		/*
		 * set a list of stops to stop execution at
		 */
		void set_stops(uint64_t count, address_t *stops);

		std::pair<address_t, size_t> cache_page(address_t address, size_t size, char* bytes, uint64_t permissions);

		void wipe_page_from_cache(address_t address);

		void uncache_pages_touching_region(address_t address, uint64_t length);

		void clear_page_cache();

		bool map_cache(address_t address, size_t size);

		bool in_cache(address_t address) const;

		// Finds tainted data in the provided range and returns the address.
		// Returns -1 if no tainted data is present.
		int64_t find_tainted(address_t address, int size);

		void handle_write(address_t address, int size, bool is_interrupt, bool interrupt_value_symbolic);

		void propagate_taint_of_mem_read_instr_and_continue(address_t read_address, int read_size);

		void start_propagating_taint();

		void continue_propagating_taint();

		void set_curr_block_details(address_t block_address, int32_t block_size);

		address_t get_instruction_pointer() const;

		address_t get_stack_pointer() const;

		void fd_init_bytes(uint64_t fd, char *bytes, taint_t *taints, uint64_t len, uint64_t read_pos);

		uint64_t fd_read(uint64_t fd, char *buf, taint_t *&taints, uint64_t count);

		// Set random syscall data for replaying
		void init_random_bytes(uint64_t *values, uint64_t *sizes, uint64_t count);

		// CGC syscall handlers
		void perform_cgc_random();

		void perform_cgc_receive();

		void perform_cgc_transmit();

		// Inline functions

		inline simos_t get_simos() const {
			return simos;
		}

		/*
		* Feasibility checks for unicorn
		*/

		inline bool is_symbolic_tracking_disabled() const {
			return (vex_guest == VexArch_INVALID);
		}

		inline bool is_symbolic_taint_propagation_disabled() const {
			return (is_symbolic_tracking_disabled() || curr_block_details.vex_lift_failed);
		}
};

#endif /* SIM_UNICORN_HPP */
