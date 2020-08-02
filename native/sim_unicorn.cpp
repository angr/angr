#define __STDC_FORMAT_MACROS 1
#include <unicorn/unicorn.h>

#include <cinttypes>
#include <cstring>
#include <cstdint>

#include <memory>
#include <map>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <set>
#include <algorithm>
#include <sstream>

extern "C" {
#include <assert.h>
#include <libvex.h>
#include <pyvex.h>
}

//#include "log.h"

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12

// Maximum size of a qemu/unicorn basic block
// See State::step for why this is necessary
static const uint32_t MAX_BB_SIZE = 800;

static const uint8_t MAX_MEM_ACCESS_SIZE = 8;

// The size of the longest register in archinfo's uc_regs for all architectures
static const uint8_t MAX_REGISTER_BYTE_SIZE = 32;

typedef enum taint: uint8_t {
	TAINT_NONE = 0,
	TAINT_SYMBOLIC = 1, // this should be 1 to match the UltraPage impl
	TAINT_DIRTY = 2,
} taint_t;

typedef enum : uint8_t {
	TAINT_ENTITY_REG = 0,
	TAINT_ENTITY_TMP = 1,
	TAINT_ENTITY_MEM = 2,
	TAINT_ENTITY_NONE = 3,
} taint_entity_enum_t;

typedef enum : uint8_t {
	TAINT_STATUS_CONCRETE = 0,
	TAINT_STATUS_DEPENDS_ON_READ_FROM_SYMBOLIC_ADDR,
	TAINT_STATUS_SYMBOLIC,
} taint_status_result_t;

typedef uint64_t address_t;
typedef uint64_t unicorn_reg_id_t;
typedef uint64_t vex_reg_offset_t;
typedef uint64_t vex_tmp_id_t;

typedef struct taint_entity_t {
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
} taint_entity_t;

// Hash function for unordered_map. Needs to be defined this way in C++.
template <>
struct std::hash<taint_entity_t> {
	std::size_t operator()(const taint_entity_t &entity) const {
		return entity.operator()(entity);
	}
};

typedef struct {
	address_t address;
	uint8_t value[MAX_MEM_ACCESS_SIZE]; // Assume size of read is not more than 8 just like write
	size_t size;
	bool is_value_symbolic;
} mem_read_result_t;

typedef struct memory_value_t {
	uint64_t address;
    uint8_t value[MAX_MEM_ACCESS_SIZE];
    uint64_t size;

	bool operator==(const memory_value_t &other_mem_value) {
		if ((address != other_mem_value.address) || (size != other_mem_value.size)) {
			return false;
		}
		return (memcmp(value, other_mem_value.value, size) == 0);
	}
} memory_value_t;

typedef struct {
	uint64_t offset;
	uint8_t value[MAX_REGISTER_BYTE_SIZE];
} register_value_t;

typedef struct instr_details_t {
	address_t instr_addr;
	bool has_memory_dep;
	memory_value_t memory_value;

	bool operator==(const instr_details_t &other_instr) {
		return ((instr_addr == other_instr.instr_addr) && (has_memory_dep == other_instr.has_memory_dep) &&
			(memory_value == other_instr.memory_value));
	}

	bool operator<(const instr_details_t &other_instr) const {
		return (instr_addr < other_instr.instr_addr);
	}
} instr_details_t;

typedef struct {
	address_t block_addr;
	uint64_t block_size;
	std::vector<instr_details_t> symbolic_instrs;
	std::vector<register_value_t> register_values;
	bool vex_lift_failed;

	void reset() {
		block_addr = 0;
		block_size = 0;
		vex_lift_failed = false;
		symbolic_instrs.clear();
		register_values.clear();
	}
} block_details_t;

// This struct is used only to return data to the state plugin since ctypes doesn't natively handle
// C++ STL containers
typedef struct {
	uint64_t block_addr;
    uint64_t block_size;
    instr_details_t *symbolic_instrs;
    uint64_t symbolic_instrs_count;
    register_value_t *register_values;
    uint64_t register_values_count;
} block_details_ret_t;

typedef enum stop {
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
	STOP_SYMBOLIC_CONDITION,
	STOP_SYMBOLIC_PC,
	STOP_SYMBOLIC_READ_ADDR,
	STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED,
	STOP_SYMBOLIC_WRITE_ADDR,
	STOP_SYMBOLIC_BLOCK_EXIT_STMT,
	STOP_MULTIPLE_MEMORY_WRITES,
	STOP_UNSUPPORTED_STMT_PUTI,
	STOP_UNSUPPORTED_STMT_STOREG,
	STOP_UNSUPPORTED_STMT_LOADG,
	STOP_UNSUPPORTED_STMT_CAS,
	STOP_UNSUPPORTED_STMT_LLSC,
	STOP_UNSUPPORTED_STMT_DIRTY,
	STOP_UNSUPPORTED_STMT_UNKNOWN,
	STOP_UNSUPPORTED_EXPR_GETI,
	STOP_UNSUPPORTED_EXPR_UNKNOWN,
	STOP_UNKNOWN_MEMORY_WRITE,
	STOP_UNKNOWN_MEMORY_READ,
} stop_t;

typedef std::vector<std::pair<taint_entity_t, std::unordered_set<taint_entity_t>>> taint_vector_t;

typedef struct instruction_taint_entry_t {
	// List of direct taint sources for a taint sink
	taint_vector_t taint_sink_src_map;

	// List of registers a taint sink depends on
	std::unordered_set<taint_entity_t> dependencies_to_save;

	// List of taint entities in ITE expression's condition, if any
	std::unordered_set<taint_entity_t> ite_cond_entity_list;

	bool has_memory_read;
	bool has_memory_write;

	bool operator==(const instruction_taint_entry_t &other_instr_deps) const {
		return (taint_sink_src_map == other_instr_deps.taint_sink_src_map) &&
			   (dependencies_to_save == other_instr_deps.dependencies_to_save) &&
			   (has_memory_read == other_instr_deps.has_memory_read) &&
			   (has_memory_write == other_instr_deps.has_memory_write);
	}

	void reset() {
		dependencies_to_save.clear();
		ite_cond_entity_list.clear();
		taint_sink_src_map.clear();
		has_memory_read = false;
		has_memory_write = false;
		return;
	}
} instruction_taint_entry_t;

typedef struct block_taint_entry_t {
	std::map<address_t, instruction_taint_entry_t> block_instrs_taint_data_map;
	std::unordered_set<taint_entity_t> exit_stmt_guard_expr_deps;
	address_t exit_stmt_instr_addr;
	bool has_unsupported_stmt_or_expr_type;
	stop_t unsupported_stmt_stop_reason;

	bool operator==(const block_taint_entry_t &other_entry) const {
		return (block_instrs_taint_data_map == other_entry.block_instrs_taint_data_map) &&
			   (exit_stmt_guard_expr_deps == other_entry.exit_stmt_guard_expr_deps);
	}
} block_taint_entry_t;

typedef struct {
	address_t block_addr;
	uint64_t block_size;
} stopped_instr_details_t;

typedef struct {
	std::unordered_set<taint_entity_t> sources;
	std::unordered_set<taint_entity_t> ite_cond_entities;
	bool has_unsupported_expr;
	stop_t unsupported_expr_stop_reason;
} taint_sources_and_and_ite_cond_t;

typedef struct {
	std::set<instr_details_t> dependent_instrs;
	std::unordered_set<vex_reg_offset_t> concrete_registers;
} instr_slice_details_t;

typedef struct CachedPage {
	size_t size;
	uint8_t *bytes;
	uint64_t perms;
} CachedPage;

typedef taint_t PageBitmap[PAGE_SIZE];
typedef std::map<address_t, CachedPage> PageCache;
typedef std::unordered_map<address_t, block_taint_entry_t> BlockTaintCache;
typedef struct caches {
	PageCache *page_cache;
} caches_t;
std::map<uint64_t, caches_t> global_cache;

typedef std::unordered_set<vex_reg_offset_t> RegisterSet;
typedef std::unordered_map<vex_reg_offset_t, unicorn_reg_id_t> RegisterMap;
typedef std::unordered_set<vex_tmp_id_t> TempSet;

typedef struct mem_access {
	address_t address;
	uint8_t value[MAX_MEM_ACCESS_SIZE]; // assume size of any memory write is no more than 8
	int size;
	int clean; // save current page bitmap
	bool is_symbolic;
} mem_access_t; // actually it should be `mem_write_t` :)

typedef struct mem_update {
	address_t address;
	uint64_t length;
	struct mem_update *next;
} mem_update_t;

typedef struct transmit_record {
	void *data;
	uint32_t count;
} transmit_record_t;

// These prototypes may be found in <unicorn/unicorn.h> by searching for "Callback"
static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static bool hook_mem_unmapped(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static bool hook_mem_prot(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void hook_block(uc_engine *uc, uint64_t address, int32_t size, void *user_data);
static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data);

class State {
private:
	uc_engine *uc;
	PageCache *page_cache;
	BlockTaintCache block_taint_cache;
	bool hooked;

	uc_context *saved_regs;

	std::vector<mem_access_t> mem_writes;
	// List of all memory writes and their taint status
	// Memory write instruction address -> is_symbolic
	// TODO: Need to modify memory write taint handling for architectures that perform multiple
	// memory writes in a single instruction
	std::unordered_map<address_t, bool> mem_writes_taint_map;

	// Slice of current block to set the value of a register
	std::unordered_map<vex_reg_offset_t, std::vector<instr_details_t>> reg_instr_slice;

	// Slice of current block for an instruction
	std::unordered_map<address_t, instr_slice_details_t> instr_slice_details_map;

	// List of instructions in a block that should be executed symbolically. These are stored
	// separately for easy rollback in case of errors.
	block_details_t block_details;

	// List of registers which are concrete dependencies of a block's instructions executed symbolically
	std::unordered_set<vex_reg_offset_t> block_concrete_dependencies;

	// List of register values at start of block
	std::unordered_map<vex_reg_offset_t, register_value_t> block_start_reg_values;

	// Similar to memory reads in a block, we track the state of registers and VEX temps when
	// propagating taint in a block for easy rollback if we need to abort due to read from/write to
	// a symbolic address
	RegisterSet block_symbolic_registers, block_concrete_registers;
	TempSet block_symbolic_temps;

	// the latter part of the pair is a pointer to the page data if the page is direct-mapped, otherwise NULL
	std::map<address_t, std::pair<taint_t *, uint8_t *>> active_pages;
	//std::map<uint64_t, taint_t *> active_pages;
	std::set<uint64_t> stop_points;

	address_t taint_engine_next_instr_address, taint_engine_mem_read_stop_instruction;

	address_t unicorn_next_instr_addr;

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
	stop_t stop_reason;

	bool ignore_next_block;
	bool ignore_next_selfmod;
	address_t cur_address;
	int32_t cur_size;

	uc_arch arch;
	uc_mode mode;
	bool interrupt_handled;
	uint32_t transmit_sysno;
	uint32_t transmit_bbl_addr;

	VexArch vex_guest;
	VexArchInfo vex_archinfo;
	RegisterSet symbolic_registers; // tracking of symbolic registers
	RegisterSet blacklisted_registers;  // Registers which shouldn't be saved as a concrete dependency
	RegisterMap vex_to_unicorn_map; // Mapping of VEX offsets to unicorn registers
	RegisterMap vex_sub_reg_map; // Mapping of VEX sub-registers to their main register
	std::unordered_map<vex_reg_offset_t, uint64_t> reg_size_map;
	RegisterSet artificial_vex_registers; // Artificial VEX registers
	std::unordered_map<vex_reg_offset_t, uint64_t> cpu_flags;	// VEX register offset and bitmask for CPU flags
	int64_t cpu_flags_register;
	stopped_instr_details_t stopped_at_instr;
	const char *stop_reason_msg;

	// Result of all memory reads executed. Instruction address -> memory read result
	std::unordered_map<address_t, mem_read_result_t> mem_reads_map;

	// List of instructions that should be executed symbolically
	std::vector<block_details_t> blocks_with_symbolic_instrs;

	bool track_bbls;
	bool track_stack;

	uc_cb_eventmem_t py_mem_callback;

	State(uc_engine *_uc, uint64_t cache_key):uc(_uc)
	{
		hooked = false;
		h_read = h_write = h_block = h_prot = 0;
		max_steps = cur_steps = 0;
		stopped = true;
		stop_reason = STOP_NOSTART;
		ignore_next_block = false;
		ignore_next_selfmod = false;
		interrupt_handled = false;
		transmit_sysno = -1;
		vex_guest = VexArch_INVALID;
		syscall_count = 0;
		uc_context_alloc(uc, &saved_regs);
		executed_pages_iterator = NULL;
		cpu_flags_register = -1;

		auto it = global_cache.find(cache_key);
		if (it == global_cache.end()) {
			page_cache = new PageCache();
			global_cache[cache_key] = {page_cache};
		} else {
			page_cache = it->second.page_cache;
		}
		arch = *((uc_arch*)uc); // unicorn hides all its internals...
		mode = *((uc_mode*)((uc_arch*)uc + 1));
		block_details.reset();
	}

	/*
	 * HOOK_MEM_WRITE is called before checking if the address is valid. so we might
	 * see uninitialized pages. Using HOOK_MEM_PROT is too late for tracking taint.
	 * so we don't have to use HOOK_MEM_PROT to track dirty pages.
	 */
	void hook() {
		if (hooked) {
			//LOG_D("already hooked");
			return ;
		}
		uc_err err;
		err = uc_hook_add(uc, &h_read, UC_HOOK_MEM_READ, (void *)hook_mem_read, this, 1, 0);

		err = uc_hook_add(uc, &h_write, UC_HOOK_MEM_WRITE, (void *)hook_mem_write, this, 1, 0);

		err = uc_hook_add(uc, &h_block, UC_HOOK_BLOCK, (void *)hook_block, this, 1, 0);

		err = uc_hook_add(uc, &h_prot, UC_HOOK_MEM_PROT, (void *)hook_mem_prot, this, 1, 0);

		err = uc_hook_add(uc, &h_unmap, UC_HOOK_MEM_UNMAPPED, (void *)hook_mem_unmapped, this, 1, 0);

		err = uc_hook_add(uc, &h_intr, UC_HOOK_INTR, (void *)hook_intr, this, 1, 0);

		hooked = true;
	}

	void unhook() {
		if (!hooked)
			return ;

		uc_err err;
		err = uc_hook_del(uc, h_read);
		err = uc_hook_del(uc, h_write);
		err = uc_hook_del(uc, h_block);
		err = uc_hook_del(uc, h_prot);
		err = uc_hook_del(uc, h_unmap);
		err = uc_hook_del(uc, h_intr);

		hooked = false;
		h_read = h_write = h_block = h_prot = h_unmap = 0;
	}

	~State() {
		for (auto it = active_pages.begin(); it != active_pages.end(); it++) {
			// only delete if not direct-mapped
			if (!it->second.second) {
                // delete should use the bracket operator since PageBitmap is an array typedef
                delete[] it->second.first;
            }
		}
		active_pages.clear();
		uc_free(saved_regs);
	}

	uc_err start(address_t pc, uint64_t step = 1) {
		stopped = false;
		stop_reason = STOP_NOSTART;
		max_steps = step;
		cur_steps = -1;
		unicorn_next_instr_addr = pc;
		executed_pages.clear();

		// error if pc is 0
		// TODO: why is this check here and not elsewhere
		if (pc == 0) {
			stop_reason = STOP_ZEROPAGE;
			cur_steps = 0;
			return UC_ERR_MAP;
		}

		// Initialize slice tracker for registers and flags
		for (auto &reg_entry: vex_to_unicorn_map) {
			reg_instr_slice.emplace(reg_entry.first, std::vector<instr_details_t>());
		}

		for (auto &cpu_flag_entry: cpu_flags) {
			reg_instr_slice.emplace(cpu_flag_entry.first, std::vector<instr_details_t>());
		}

		uc_err out = uc_emu_start(uc, unicorn_next_instr_addr, 0, 0, 0);
		if (out == UC_ERR_OK && stop_reason == STOP_NOSTART && get_instruction_pointer() == 0) {
		    // handle edge case where we stop because we reached our bogus stop address (0)
		    commit();
		    stop_reason = STOP_ZEROPAGE;
		}
		rollback();

		if (out == UC_ERR_INSN_INVALID) {
			stop_reason = STOP_NODECODE;
		}

		// if we errored out right away, fix the step count to 0
		if (cur_steps == -1) cur_steps = 0;

		return out;
	}

	void stop(stop_t reason) {
		stopped = true;
		switch (reason) {
			case STOP_NORMAL:
				stop_reason_msg = "reached maximum steps";
				break;
			case STOP_STOPPOINT:
				stop_reason_msg = "hit a stop point";
				break;
			case STOP_ERROR:
				stop_reason_msg = "something wrong";
				break;
			case STOP_SYSCALL:
				stop_reason_msg = "unable to handle syscall";
				commit();
				break;
			case STOP_ZEROPAGE:
				stop_reason_msg = "accessing zero page";
				break;
			case STOP_EXECNONE:
				stop_reason_msg = "fetching empty page";
				break;
			case STOP_NOSTART:
				stop_reason_msg = "failed to start";
				break;
			case STOP_SEGFAULT:
				stop_reason_msg = "permissions or mapping error";
				break;
			case STOP_ZERO_DIV:
				stop_reason_msg = "divide by zero";
				break;
			case STOP_NODECODE:
				stop_reason_msg = "instruction decoding error";
				break;
			case STOP_VEX_LIFT_FAILED:
				stop_reason_msg = "failed to lift block to VEX";
				break;
			case STOP_SYMBOLIC_CONDITION:
				stop_reason_msg = "symbolic condition for ITE";
				break;
			case STOP_SYMBOLIC_READ_ADDR:
				stop_reason_msg = "attempted to read from symbolic address";
				break;
			case STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED:
				stop_reason_msg = "attempted to read symbolic data from memory but symbolic tracking is disabled";
				break;
			case STOP_SYMBOLIC_WRITE_ADDR:
				stop_reason_msg = "attempted to write to symbolic address";
				break;
			case STOP_SYMBOLIC_PC:
				stop_reason_msg = "Instruction pointer became symbolic";
				break;
			case STOP_SYMBOLIC_BLOCK_EXIT_STMT:
				stop_reason_msg = "Guard condition of block's exit statement is symbolic";
				break;
			case STOP_MULTIPLE_MEMORY_WRITES:
				stop_reason_msg = "Symbolic taint propagation when multiple memory writes occur in single instruction not yet supported";
				break;
			case STOP_UNSUPPORTED_STMT_PUTI:
				stop_reason_msg = "Symbolic taint propagation for PutI statement not yet supported";
				break;
			case STOP_UNSUPPORTED_STMT_STOREG:
				stop_reason_msg = "Symbolic taint propagation for StoreG statement not yet supported";
				break;
			case STOP_UNSUPPORTED_STMT_LOADG:
				stop_reason_msg = "Symbolic taint propagation for LoadG statement not yet supported";
				break;
			case STOP_UNSUPPORTED_STMT_CAS:
				stop_reason_msg = "Symbolic taint propagation for CAS statement not yet supported";
				break;
			case STOP_UNSUPPORTED_STMT_LLSC:
				stop_reason_msg = "Symbolic taint propagation for LLSC statement not yet supported";
				break;
			case STOP_UNSUPPORTED_STMT_DIRTY:
				stop_reason_msg = "Symbolic taint propagation for Dirty statement not yet supported";
				break;
			case STOP_UNSUPPORTED_EXPR_GETI:
				stop_reason_msg = "Symbolic taint propagation for GetI expression not yet supported";
				break;
			case STOP_UNSUPPORTED_STMT_UNKNOWN:
				stop_reason_msg = "Cannot propagate symbolic taint for VEX statement of unknown type";
				break;
			case STOP_UNSUPPORTED_EXPR_UNKNOWN:
				stop_reason_msg = "Cannot propagate symbolic taint for VEX expression of unknown type";
				break;
			case STOP_UNKNOWN_MEMORY_WRITE:
				// This likely happened because unicorn misreported PC value in memory write hook. See handle_write.
				stop_reason_msg = "Cannot find a memory write at instruction; likely because unicorn reported PC value incorrectly";
				break;
			case STOP_UNKNOWN_MEMORY_READ:
				// This likely happened because unicorn misreported PC value in memory read hook.
				stop_reason_msg = "Unexpected PC value for memory read; likely because unicorn reported PC value incorrectly";
				break;
			default:
				stop_reason_msg = "unknown error";
		}
		stop_reason = reason;
		save_stopped_at_instruction_details();
		//LOG_D("stop: %s", stop_reason_msg);
		uc_emu_stop(uc);
	}

	inline void save_stopped_at_instruction_details() {
		// Save details of block of instruction where we stopped
		stopped_at_instr.block_addr = block_details.block_addr;
		stopped_at_instr.block_size = block_details.block_size;
		return;
	}

	void step(address_t current_address, int32_t size, bool check_stop_points=true) {
		if (track_bbls) {
			bbl_addrs.push_back(current_address);
		}
		if (track_stack) {
			stack_pointers.push_back(get_stack_pointer());
		}
		executed_pages.insert(current_address & ~0xFFFULL);
		cur_address = current_address;
		cur_size = size;

		if (cur_steps >= max_steps) {
			stop(STOP_NORMAL);
		} else if (check_stop_points) {
			// If size is zero, that means that the current basic block was too large for qemu
			// and it got split into multiple parts. unicorn will only call this hook for the
			// first part and not for the remaining ones, so it is impossible to find the
			// accurate size of the BB block here.
			//
			// See https://github.com/unicorn-engine/unicorn/issues/874
			//
			// Until that is resolved, we use the maximum size of a Qemu basic block here. This means
			// that some stop points may not work, but there is no way to do better.
			uint32_t real_size = size == 0 ? MAX_BB_SIZE : size;

			// if there are any stop points in the current basic block, then there is no chance
			// for us to stop in the middle of a block.
			// since we do not support stopping in the middle of a block.

			auto stop_point = stop_points.lower_bound(current_address);
			if (stop_point != stop_points.end() && *stop_point < current_address + real_size) {
				stop(STOP_STOPPOINT);
			}
		}
	}

	/*
	 * commit all memory actions.
	 * end_block denotes whether this is done at the end of the block or not
	 */
	void commit() {
		// save registers
		uc_context_save(uc, saved_regs);

		// mark memory sync status
		// we might miss some dirty bits, this happens if hitting the memory
		// write before mapping
		/*  THIS SHOULDN'T BE REQUIRED, we have the same logic to do this in the page activation code
		for (auto it = mem_writes.begin(); it != mem_writes.end(); it++) {
			if (it->clean == -1) {
				taint_t *bitmap = page_lookup(it->address);
				if (it->is_symbolic) {
					memset(&bitmap[it->address & 0xFFFULL], TAINT_SYMBOLIC, sizeof(taint_t) * it->size);
				}
				else {
					memset(&bitmap[it->address & 0xFFFULL], TAINT_DIRTY, sizeof(taint_t) * it->size);
					it->clean = (1 << it->size) - 1;
					//LOG_D("commit: lazy initialize mem_write [%#lx, %#lx]", it->address, it->address + it->size);
				}
			}
		}
		*/

		// clear memory rollback status
		mem_writes.clear();
		cur_steps++;

		// Sync all block level taint statuses reads with state's taint statuses and block level
		// symbolic instruction list with state's symbolic instruction list
		for (auto &reg_offset: block_symbolic_registers) {
			mark_register_symbolic(reg_offset, false);
		}
		for (auto &reg_offset: block_concrete_registers) {
			mark_register_concrete(reg_offset, false);
		}
		if (block_details.symbolic_instrs.size() > 0) {
			for (auto &concrete_reg: block_concrete_dependencies) {
				block_details.register_values.emplace_back(block_start_reg_values.at(concrete_reg));
			}
			blocks_with_symbolic_instrs.emplace_back(block_details);
		}
		// Clear all block level taint status trackers and symbolic instruction list
		block_symbolic_registers.clear();
		block_concrete_registers.clear();
		block_details.reset();
		block_concrete_dependencies.clear();
		instr_slice_details_map.clear();
		mem_reads_map.clear();
		mem_writes_taint_map.clear();
		return;
	}

	/*
	 * undo recent memory actions.
	 */
	void rollback() {
		// roll back memory changes
		for (auto rit = mem_writes.rbegin(); rit != mem_writes.rend(); rit++) {
            uc_err err = uc_mem_write(uc, rit->address, rit->value, rit->size);
            if (err) {
                //LOG_I("rollback: %s", uc_strerror(err));
                break;
            }
            auto page = page_lookup(rit->address);
            taint_t *bitmap = page.first;
            uint8_t *data = page.second;

            if (data == NULL) {
				if (rit->clean) {
					// should untaint some bits
					address_t start = rit->address & 0xFFF;
					int size = rit->size;
					int clean = rit->clean;
					for (int i = 0; i < size; i++) {
						if ((clean >> i) & 1) {
							// this byte is untouched before this memory action
							// in the rollback, we already failed to execute, so
							// we don't care about symoblic address, just mark
							// it's clean.
							bitmap[start + i] = TAINT_NONE;
						}
					}
				}
			} else {
                uint64_t start = rit->address & 0xFFF;
                int size = rit->size;
                int clean = rit->clean;
                for (int i = 0; i < size; i++) {
                    bitmap[start + i] = (clean & (1 << i)) != 0 ? TAINT_NONE : TAINT_SYMBOLIC;
                }
			}
		}
		mem_writes.clear();

		// restore registers
		uc_context_restore(uc, saved_regs);

		if (track_bbls) bbl_addrs.pop_back();
		if (track_stack) stack_pointers.pop_back();
	}

	/*
	 * return the PageBitmap only if the page is remapped for writing,
	 * or initialized with symbolic variable, otherwise return NULL.
	 */
	std::pair<taint_t *, uint8_t *> page_lookup(address_t address) const {
		address &= ~0xFFFULL;
		auto it = active_pages.find(address);
		if (it == active_pages.end()) {
			return std::pair<taint_t *, uint8_t *>(NULL, NULL);
		}
		return it->second;
	}

	/*
	 * allocate a new PageBitmap and put into active_pages.
	 */
	void page_activate(address_t address, uint8_t *taint, uint8_t *data) {
		address &= ~0xFFFULL;
		auto it = active_pages.find(address);
		if (it == active_pages.end()) {
		    if (data == NULL) {
		        // We need to copy the taint bitmap
                taint_t *bitmap = new PageBitmap;
                memcpy(bitmap, taint, sizeof(PageBitmap));

                active_pages.insert(std::pair<address_t, std::pair<taint_t*, uint8_t*>>(address, std::pair<taint_t*, uint8_t*>(bitmap, NULL)));
            } else {
                // We can directly use the passed taint and data
                taint_t *bitmap = (taint_t*)taint;
                active_pages.insert(std::pair<uint64_t, std::pair<taint_t*, uint8_t*>>(address, std::pair<taint_t*, uint8_t*>(bitmap, data)));
			}
		} else {
		    // TODO: un-hardcode this address, or at least do this warning from python land
			if (address == 0x4000) {
				printf("[sim_unicorn] You've mapped something at 0x4000! "
					"Please don't do that, I put my GDT there!\n");
			} else {
				printf("[sim_unicorn] Something very bad is happening; please investigate. "
					"Trying to activate the page at %#" PRIx64 " but it's already activated.\n", address);
				// to the person who sees this error:
				// you're gonna need to spend some time looking into it.
				// I'm not 100% sure that this is necessarily a bug condition.
			}
		}

        /*  SHOULD NOT BE NECESSARY
		for (auto a = mem_writes.begin(); a != mem_writes.end(); a++)
			if (a->clean == -1 && (a->address & ~0xFFFULL) == address) {
			    // This mapping was prompted by this write.
				// initialize this memory access immediately so that the
				// record is valid.
				//printf("page_activate: lazy initialize mem_write [%#lx, %#lx]\n", a->address, a->address + a->size);
				if (data == NULL) {
                    memset(&bitmap[a->address & 0xFFFULL], TAINT_DIRTY, sizeof(taint_t) * a->size);
                    a->clean = (1ULL << a->size) - 1;
                } else {
                    a->clean = 0;
                    for (int i = 0; i < a->size; i++) {
                        if (bitmap[(a->address & 0xFFFULL) + i] == TAINT_SYMBOLIC) {
                            a->clean |= 1 << i;
                        }
                    }
                    memset(&bitmap[a->address & 0xFFFULL], TAINT_CLEAN, sizeof(taint_t) * a->size);
                    memcpy(a->value, &data[a->address & 0xFFFULL], a->size);
                }
			}
		*/
	}

	/*
	 * record consecutive dirty bit rage, return a linked list of ranges
	 */
	mem_update_t *sync() {
		mem_update *head = NULL;

		for (auto it = active_pages.begin(); it != active_pages.end(); it++) {
			uint8_t *data = it->second.second;
			if (data != NULL) {
			    // nothing to sync, direct mapped :)
			    continue;
			}
			taint_t *start = it->second.first;
			taint_t *end = &it->second.first[0x1000];
			//LOG_D("found active page %#lx (%p)", it->first, start);
			for (taint_t *i = start; i < end; i++)
				if ((*i) == TAINT_DIRTY) {
					taint_t *j = i;
					while (j < end && (*j) == TAINT_DIRTY) j++;

					char buf[0x1000];
					uc_mem_read(uc, it->first + (i - start), buf, j - i);
					//LOG_D("sync [%#lx, %#lx] = %#lx", it->first + (i - start), it->first + (j - start), *(uint64_t *)buf);

					mem_update_t *range = new mem_update_t;
					range->address = it->first + (i - start);
					range->length = j - i;
					range->next = head;
					head = range;

					i = j;
				}
		}

		return head;
	}

	/*
	 * set a list of stops to stop execution at
	 */

	void set_stops(uint64_t count, address_t *stops)
	{
		stop_points.clear();
		for (int i = 0; i < count; i++) {
			stop_points.insert(stops[i]);
		}
	}

	std::pair<address_t, size_t> cache_page(address_t address, size_t size, char* bytes, uint64_t permissions)
	{
		assert(address % 0x1000 == 0);
		assert(size % 0x1000 == 0);

		for (uint64_t offset = 0; offset < size; offset += 0x1000)
		{
			auto page = page_cache->find(address+offset);
			if (page != page_cache->end())
			{
				fprintf(stderr, "[%#" PRIx64 ", %#" PRIx64 "](%#zx) already in cache.\n", address+offset, address+offset + 0x1000, 0x1000lu);
				assert(page->second.size == 0x1000);
				assert(memcmp(page->second.bytes, bytes + offset, 0x1000) == 0);

				continue;
			}

			uint8_t *copy = (uint8_t *)malloc(0x1000);
			CachedPage cached_page = {
				0x1000,
				copy,
				permissions
			};
			// address should be aligned to 0x1000
			memcpy(copy, &bytes[offset], 0x1000);
			page_cache->insert(std::pair<address_t, CachedPage>(address+offset, cached_page));
		}
		return std::make_pair(address, size);
	}

    void wipe_page_from_cache(address_t address) {
		auto page = page_cache->find(address);
		if (page != page_cache->end()) {
			//printf("Internal: unmapping %#llx size %#x, result %#x", page->first, page->second.size, uc_mem_unmap(uc, page->first, page->second.size));
			uc_err err = uc_mem_unmap(uc, page->first, page->second.size);
			//if (err) {
			//	fprintf(stderr, "wipe_page_from_cache [%#lx, %#lx]: %s\n", page->first, page->first + page->second.size, uc_strerror(err));
			//}
			free(page->second.bytes); // might explode
			page_cache->erase(page);
		} else {
			//printf("Uh oh! Couldn't find page at %#llx\n", address);
		}
    }

    void uncache_pages_touching_region(address_t address, uint64_t length)
    {
    	    address &= ~(0x1000-1);

	    for (uint64_t offset = 0; offset < length; offset += 0x1000)
	    {
            	    wipe_page_from_cache(address + offset);
	    }

    }

    void clear_page_cache()
    {
        while (!page_cache->empty())
        {
            wipe_page_from_cache(page_cache->begin()->first);
        }
    }

	bool map_cache(address_t address, size_t size) {
		assert(address % 0x1000 == 0);
		assert(size % 0x1000 == 0);

		bool success = true;

		for (uint64_t offset = 0; offset < size; offset += 0x1000)
		{
			auto page = page_cache->find(address+offset);
			if (page == page_cache->end())
			{
				success = false;
				continue;
			}

			auto cached_page = page->second;
			size_t page_size = cached_page.size;
			uint8_t *bytes = cached_page.bytes;
			uint64_t permissions = cached_page.perms;

			assert(page_size == 0x1000);

			//LOG_D("hit cache [%#lx, %#lx]", address, address + size);
			uc_err err = uc_mem_map_ptr(uc, page->first, page_size, permissions, bytes);
			if (err) {
				fprintf(stderr, "map_cache [%#lx, %#lx]: %s\n", address, address + size, uc_strerror(err));
				success = false;
				continue;
			}
		}
		return success;
	}

	bool in_cache(address_t address) const {
		return page_cache->find(address) != page_cache->end();
	}

	//
	// Feasibility checks for unicorn
	//

	inline bool is_symbolic_tracking_disabled() {
		return (vex_guest == VexArch_INVALID);
	}

	// Finds tainted data in the provided range and returns the address.
	// Returns -1 if no tainted data is present.
	int64_t find_tainted(address_t address, int size)
	{
		taint_t *bitmap = page_lookup(address).first;

		int start = address & 0xFFF;
		int end = (address + size - 1) & 0xFFF;

		if (end >= start) {
			if (bitmap) {
				for (int i = start; i <= end; i++) {
					if (bitmap[i] & TAINT_SYMBOLIC) {
						return (address & ~0xFFF) + i;
					}
				}
			}
		} else {
			// cross page boundary
			if (bitmap) {
				for (int i = start; i <= 0xFFF; i++) {
					if (bitmap[i] & TAINT_SYMBOLIC) {
						return (address & ~0xFFF) + i;
					}
				}
			}

			bitmap = page_lookup(address + size - 1).first;
			if (bitmap) {
				for (int i = 0; i <= end; i++) {
					if (bitmap[i] & TAINT_SYMBOLIC) {
						return ((address + size - 1) & ~0xFFF) + i;
					}
				}
			}
		}

		return -1;
	}

	void handle_write(address_t address, int size, bool is_interrupt) {
	    // If the write spans a page, chop it up
	    if ((address & 0xfff) + size > 0x1000) {
	        int chopsize = 0x1000 - (address & 0xfff);
	        handle_write(address, chopsize, is_interrupt);
	        handle_write(address + chopsize, size - chopsize, is_interrupt);
	        return;
	    }

	    // From here, we are definitely only dealing with one page

		mem_access_t record;
		record.address = address;
		record.size = size;
		uc_err err = uc_mem_read(uc, address, record.value, size);
		if (err == UC_ERR_READ_UNMAPPED) {
		    if (py_mem_callback(uc, UC_MEM_WRITE_UNMAPPED, address, size, 0, (void*)1)) {
		        err = UC_ERR_OK;
		    }
		}
		if (err) {
		    stop(STOP_ERROR);
		    return;
		}

		auto pair = page_lookup(address);
		taint_t *bitmap = pair.first;
		uint8_t *data = pair.second;
		int start = address & 0xFFF;
		int end = (address + size - 1) & 0xFFF;
		short clean;
		address_t instr_addr;
		bool is_dst_symbolic;

		if (!bitmap) {
		    // We should never have a missing bitmap because we explicitly called the callback!
		    printf("This should never happen, right? %#" PRIx64 "\n", address);
		    abort();
		}

        clean = 0;
		if (is_interrupt || is_symbolic_tracking_disabled() || block_details.vex_lift_failed) {
			// If symbolic tracking is disabled, all writes are concrete
			// is_interrupt flag is a workaround for CGC transmit syscall, which never passes symbolic data
			// If VEX lift failed, then write is definitely concrete since execution continues only
			// if no symbolic data is present
			is_dst_symbolic = false;
		}
		else {
			address_t instr_addr = get_instruction_pointer();
			auto mem_writes_taint_map_entry = mem_writes_taint_map.find(instr_addr);
			if (mem_writes_taint_map_entry != mem_writes_taint_map.end()) {
				is_dst_symbolic = mem_writes_taint_map_entry->second;
			}
			// We did not find a memory write at this instruction when processing the VEX statements.
			// This likely means unicorn reported the current PC register value wrong.
			// If there are no symbolic registers, assume write is concrete and continue concrete execution else stop.
			else if ((symbolic_registers.size() == 0) && (block_symbolic_registers.size() == 0)) {
				is_dst_symbolic = false;
			}
			else {
				stop(STOP_UNKNOWN_MEMORY_WRITE);
				return;
			}
		}
        if (data == NULL) {
            for (int i = start; i <= end; i++) {
                if (is_dst_symbolic) {
					// Don't mark as TAINT_DIRTY since we don't want to sync it back to angr
					// Also, no need to set clean: rollback will set it to TAINT_NONE which
					// is fine for symbolic bytes and rollback is called when exiting unicorn
					// due to an error encountered
					bitmap[i] = TAINT_SYMBOLIC;
				}
				else if (bitmap[i] != TAINT_DIRTY) {
                    clean |= 1 << i; // this bit should not be marked as taint if we undo this action
                    bitmap[i] = TAINT_DIRTY;
                }
            }
        } else {
            for (int i = start; i <= end; i++) {
                if (is_dst_symbolic) {
					// Don't mark as TAINT_DIRTY since we don't want to sync it back to angr
					// Also, no need to set clean: rollback will set it to TAINT_NONE which
					// is fine for symbolic bytes and rollback is called when exiting unicorn
					// due to an error encountered
					bitmap[i] = TAINT_SYMBOLIC;
				}
				else if (bitmap[i] == TAINT_NONE) {
                    clean |= 1 << (i - start);
                } else {
                    bitmap[i] = TAINT_NONE;
                }
            }
        }

		record.clean = clean;
		mem_writes.push_back(record);
	}

	std::pair<std::unordered_set<taint_entity_t>, bool> compute_dependencies_to_save(const std::unordered_set<taint_entity_t> &taint_sources) const {
		std::unordered_set<taint_entity_t> reg_dependency_list;
		bool has_memory_read = false;
		for (auto &taint_source: taint_sources) {
			// If register is an artificial VEX register, we can't save it from unicorn.
			if ((taint_source.entity_type == TAINT_ENTITY_REG) && is_valid_dependency_register(taint_source.reg_offset)) {
				reg_dependency_list.emplace(taint_source);
			}
			else if (taint_source.entity_type == TAINT_ENTITY_MEM) {
				has_memory_read = true;
			}
		}
		return std::make_pair(reg_dependency_list, has_memory_read);
	}

	void compute_slice_of_instrs(address_t instr_addr, const instruction_taint_entry_t &instr_taint_entry) {
		instr_slice_details_t instr_slice_details;
		for (auto &dependency: instr_taint_entry.dependencies_to_save) {
			if (dependency.entity_type == TAINT_ENTITY_REG) {
				vex_reg_offset_t dependency_full_register_offset = get_full_register_offset(dependency.reg_offset);
				if (!is_symbolic_register(dependency_full_register_offset)) {
					auto dep_reg_slice_instrs = reg_instr_slice.at(dependency_full_register_offset);
					if (dep_reg_slice_instrs.size() == 0) {
						// The register was not modified in this block by any preceding instruction
						// and so it's value at start of block is a dependency of the block
						instr_slice_details.concrete_registers.emplace(dependency_full_register_offset);
					}
					else {
						// The register was modified by some instructions in the block. We add those
						// instructions to the slice of this instruction and also any instructions
						// they depend on
						for (auto &dep_reg_slice_instr: dep_reg_slice_instrs) {
							auto dep_instr_slice_details = instr_slice_details_map.at(dep_reg_slice_instr.instr_addr);
							instr_slice_details.concrete_registers.insert(dep_instr_slice_details.concrete_registers.begin(), dep_instr_slice_details.concrete_registers.end());
							instr_slice_details.dependent_instrs.insert(dep_instr_slice_details.dependent_instrs.begin(), dep_instr_slice_details.dependent_instrs.end());
							instr_slice_details.dependent_instrs.emplace(dep_reg_slice_instr);
						}
					}
				}
			}
		}
		instr_slice_details_map.emplace(instr_addr, instr_slice_details);
		return;
	}

	block_taint_entry_t compute_taint_sink_source_relation_of_block(IRSB *vex_block, address_t address) {
		block_taint_entry_t block_taint_entry;
		instruction_taint_entry_t instruction_taint_entry;
		bool started_processing_instructions;
		address_t curr_instr_addr;

		started_processing_instructions = false;
		block_taint_entry.has_unsupported_stmt_or_expr_type = false;
		for (int i = 0; i < vex_block->stmts_used; i++) {
			auto stmt = vex_block->stmts[i];
			switch (stmt->tag) {
				case Ist_Put:
				{
					taint_entity_t sink;
					std::unordered_set<taint_entity_t> srcs, ite_cond_entity_list;

					sink.entity_type = TAINT_ENTITY_REG;
					sink.instr_addr = curr_instr_addr;
					sink.reg_offset = stmt->Ist.Put.offset;
					auto result = get_taint_sources_and_ite_cond(stmt->Ist.Put.data, curr_instr_addr, false);
					if (result.has_unsupported_expr) {
						block_taint_entry.has_unsupported_stmt_or_expr_type = true;
						block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
						break;
					}
					srcs = result.sources;
					ite_cond_entity_list = result.ite_cond_entities;

					// Store taint sources and compute dependencies to save
					instruction_taint_entry.taint_sink_src_map.emplace_back(sink, srcs);
					// TODO: Should we not compute dependencies to save if sink is an artificial register?
					auto dependencies_to_save = compute_dependencies_to_save(srcs);
					instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
					instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());

					// Store ITE condition entities and compute dependencies to save
					instruction_taint_entry.ite_cond_entity_list.insert(ite_cond_entity_list.begin(), ite_cond_entity_list.end());
					dependencies_to_save = compute_dependencies_to_save(ite_cond_entity_list);
					instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
					instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					break;
				}
				case Ist_WrTmp:
				{
					taint_entity_t sink;
					std::unordered_set<taint_entity_t> srcs, ite_cond_entity_list;

					sink.entity_type = TAINT_ENTITY_TMP;
					sink.instr_addr = curr_instr_addr;
					sink.tmp_id = stmt->Ist.WrTmp.tmp;
					auto result = get_taint_sources_and_ite_cond(stmt->Ist.WrTmp.data, curr_instr_addr, false);
					if (result.has_unsupported_expr) {
						block_taint_entry.has_unsupported_stmt_or_expr_type = true;
						block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
						break;
					}
					srcs = result.sources;
					ite_cond_entity_list = result.ite_cond_entities;

					// Store taint sources and compute dependencies to save
					instruction_taint_entry.taint_sink_src_map.emplace_back(sink, srcs);
					auto dependencies_to_save = compute_dependencies_to_save(srcs);
					instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
					instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());

					// Store ITE condition entities and compute dependencies to save
					instruction_taint_entry.ite_cond_entity_list.insert(ite_cond_entity_list.begin(), ite_cond_entity_list.end());
					dependencies_to_save = compute_dependencies_to_save(ite_cond_entity_list);
					instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
					instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					break;
				}
				case Ist_Store:
				{
					taint_entity_t sink;
					std::unordered_set<taint_entity_t> srcs, ite_cond_entity_list;

					sink.entity_type = TAINT_ENTITY_MEM;
					sink.instr_addr = curr_instr_addr;
					instruction_taint_entry.has_memory_write = true;
					auto result = get_taint_sources_and_ite_cond(stmt->Ist.Store.addr, curr_instr_addr, false);
					if (result.has_unsupported_expr) {
						block_taint_entry.has_unsupported_stmt_or_expr_type = true;
						block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
						break;
					}
					// TODO: What if memory addresses have ITE expressions in them?
					sink.mem_ref_entity_list.assign(result.sources.begin(), result.sources.end());
					result = get_taint_sources_and_ite_cond(stmt->Ist.Store.data, curr_instr_addr, false);
					if (result.has_unsupported_expr) {
						block_taint_entry.has_unsupported_stmt_or_expr_type = true;
						block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
						break;
					}
					srcs = result.sources;
					ite_cond_entity_list = result.ite_cond_entities;

					// Store taint sources and compute dependencies to save
					instruction_taint_entry.taint_sink_src_map.emplace_back(sink, srcs);
					auto dependencies_to_save = compute_dependencies_to_save(srcs);
					instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
					instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());

					// Store ITE condition entities and compute dependencies to save
					instruction_taint_entry.ite_cond_entity_list.insert(ite_cond_entity_list.begin(), ite_cond_entity_list.end());
					dependencies_to_save = compute_dependencies_to_save(ite_cond_entity_list);
					instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
					instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					break;
				}
				case Ist_Exit:
				{
					auto result = get_taint_sources_and_ite_cond(stmt->Ist.Exit.guard, curr_instr_addr, true);
					if (result.has_unsupported_expr) {
						block_taint_entry.has_unsupported_stmt_or_expr_type = true;
						block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
						break;
					}
					block_taint_entry.exit_stmt_guard_expr_deps = result.sources;
					block_taint_entry.exit_stmt_instr_addr = curr_instr_addr;
					if (block_taint_entry.exit_stmt_guard_expr_deps.size() > 0) {
						auto dependencies_to_save = compute_dependencies_to_save(block_taint_entry.exit_stmt_guard_expr_deps);
						instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
					}
					break;
				}
				case Ist_IMark:
				{
					// Save dependencies of previous instruction and clear it
					if (started_processing_instructions) {
						// TODO: Many instructions will not have dependencies. Can we save memory by not storing info for them?
						block_taint_entry.block_instrs_taint_data_map.emplace(curr_instr_addr, instruction_taint_entry);
					}
					instruction_taint_entry.reset();
					curr_instr_addr = stmt->Ist.IMark.addr;
					started_processing_instructions = true;
					break;
				}
				case Ist_PutI:
				{
					// TODO
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = STOP_UNSUPPORTED_STMT_PUTI;
					break;
				}
				case Ist_StoreG:
				{
					// TODO
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = STOP_UNSUPPORTED_STMT_STOREG;
					break;
				}
				case Ist_LoadG:
				{
					// TODO
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = STOP_UNSUPPORTED_STMT_LOADG;
					break;
				}
				case Ist_CAS:
				{
					// TODO
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = STOP_UNSUPPORTED_STMT_CAS;
					break;
				}
				case Ist_LLSC:
				{
					// TODO
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = STOP_UNSUPPORTED_STMT_LLSC;
					break;
				}
				case Ist_Dirty:
				{
					// TODO
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = STOP_UNSUPPORTED_STMT_DIRTY;
					break;
				}
				case Ist_MBE:
				case Ist_NoOp:
				case Ist_AbiHint:
					break;
				default:
				{
					fprintf(stderr, "[sim_unicorn] Unsupported statement type encountered: ");
					fprintf(stderr, "Block: 0x%zx, statement index: %d, statement type: %u\n", address, i, stmt->tag);
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = STOP_UNSUPPORTED_STMT_UNKNOWN;
					break;
				}
			}
		}
		// Save last instruction's entry
		block_taint_entry.block_instrs_taint_data_map.emplace(curr_instr_addr, instruction_taint_entry);
		return block_taint_entry;
	}

	inline void get_register_value(uint64_t vex_reg_offset, uint8_t *out_reg_value) const {
		uint64_t reg_value;
		if (cpu_flags_register != -1) {
			// Check if VEX register is actually a CPU flag
			auto cpu_flags_entry = cpu_flags.find(vex_reg_offset);
			if (cpu_flags_entry != cpu_flags.end()) {
				uc_reg_read(uc, cpu_flags_register, &reg_value);
				if ((reg_value & cpu_flags_entry->second) == 1) {
					// This hack assumes that a flag register is not MAX_REGISTER_BYTE_SIZE bytes long
					// so that it works on both big and little endian registers.
					out_reg_value[0] = 1;
					out_reg_value[MAX_REGISTER_BYTE_SIZE - 1] = 1;
				}
				return;
			}
		}
		uc_reg_read(uc, vex_to_unicorn_map.at(vex_reg_offset), out_reg_value);
		return;
	}

	// Returns a pair (taint sources, list of taint entities in ITE condition expression)
	taint_sources_and_and_ite_cond_t get_taint_sources_and_ite_cond(IRExpr *expr, address_t instr_addr, bool is_exit_stmt) {
		taint_sources_and_and_ite_cond_t result;
		result.has_unsupported_expr = false;
		switch (expr->tag) {
			case Iex_RdTmp:
			{
				taint_entity_t taint_entity;
				taint_entity.entity_type = TAINT_ENTITY_TMP;
				taint_entity.tmp_id = expr->Iex.RdTmp.tmp;
				taint_entity.instr_addr = instr_addr;
				result.sources.emplace(taint_entity);
				break;
			}
			case Iex_Get:
			{
				taint_entity_t taint_entity;
				taint_entity.entity_type = TAINT_ENTITY_REG;
				taint_entity.reg_offset = expr->Iex.Get.offset;
				taint_entity.instr_addr = instr_addr;
				result.sources.emplace(taint_entity);
				break;
			}
			case Iex_Unop:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Unop.arg, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());
				break;
			}
			case Iex_Binop:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Binop.arg1, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());

				temp = get_taint_sources_and_ite_cond(expr->Iex.Binop.arg2, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());
				break;
			}
			case Iex_Triop:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Triop.details->arg1, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());

				temp = get_taint_sources_and_ite_cond(expr->Iex.Triop.details->arg2, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());

				temp = get_taint_sources_and_ite_cond(expr->Iex.Triop.details->arg3, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());
				break;
			}
			case Iex_Qop:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Qop.details->arg1, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.sources.begin(), temp.ite_cond_entities.end());

				temp = get_taint_sources_and_ite_cond(expr->Iex.Qop.details->arg2, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());

				temp = get_taint_sources_and_ite_cond(expr->Iex.Qop.details->arg3, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());

				temp = get_taint_sources_and_ite_cond(expr->Iex.Qop.details->arg4, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());
				break;
			}
			case Iex_ITE:
			{
				// We store the taint entities in the condition for ITE separately in order to check
				// if condition is symbolic and stop concrete execution if it is. However for VEX
				// exit statement, we don't need to store it separately since we process only the
				// guard condition for Exit statements
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.ITE.cond, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				if (is_exit_stmt) {
					result.sources.insert(temp.sources.begin(), temp.sources.end());
					result.sources.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());
				}
				else {
					result.ite_cond_entities.insert(temp.sources.begin(), temp.sources.end());
					result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());
				}

				temp = get_taint_sources_and_ite_cond(expr->Iex.ITE.iffalse, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());

				temp = get_taint_sources_and_ite_cond(expr->Iex.ITE.iftrue, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				result.sources.insert(temp.sources.begin(), temp.sources.end());
				result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());
				break;
			}
			case Iex_CCall:
			{
				IRExpr **ccall_args = expr->Iex.CCall.args;
				for (uint64_t i = 0; ccall_args[i]; i++) {
					auto temp = get_taint_sources_and_ite_cond(ccall_args[i], instr_addr, false);
					if (temp.has_unsupported_expr) {
						result.has_unsupported_expr = true;
						result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
						break;
					}
					result.sources.insert(temp.sources.begin(), temp.sources.end());
					result.ite_cond_entities.insert(temp.ite_cond_entities.begin(), temp.ite_cond_entities.end());
				}
				break;
			}
			case Iex_Load:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Load.addr, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				// TODO: What if memory addresses have ITE expressions in them?
				taint_entity_t source;
				source.entity_type = TAINT_ENTITY_MEM;
				source.mem_ref_entity_list.assign(temp.sources.begin(), temp.sources.end());
				source.instr_addr = instr_addr;
				result.sources.emplace(source);
				break;
			}
			case Iex_GetI:
			{
				// TODO
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = STOP_UNSUPPORTED_EXPR_GETI;
				break;
			}
			case Iex_Const:
			case Iex_VECRET:
			case Iex_GSPTR:
			case Iex_Binder:
				break;
			default:
			{
				fprintf(stderr, "[sim_unicorn] Unsupported expression type encountered: %u\n", expr->tag);
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = STOP_UNSUPPORTED_EXPR_UNKNOWN;
				break;
			}
		}
		return result;
	}

	// Determine cumulative result of taint statuses of a set of taint entities
	// EG: This is useful to determine the taint status of a taint sink given it's taint sources
	taint_status_result_t get_final_taint_status(const std::unordered_set<taint_entity_t> &taint_sources) {
		bool is_symbolic = false;
		for (auto &taint_source: taint_sources) {
			if (taint_source.entity_type == TAINT_ENTITY_NONE) {
				continue;
			}
			else if ((taint_source.entity_type == TAINT_ENTITY_REG) || (taint_source.entity_type == TAINT_ENTITY_TMP)) {
				if (is_symbolic_register_or_temp(taint_source)) {
					// Taint sink is symbolic. We don't stop here since we need to check for read
					// from a symbolic address
					is_symbolic = true;
				}
			}
			else if (taint_source.entity_type == TAINT_ENTITY_MEM) {
				// Check if the memory address being read from is symbolic
				auto mem_address_status = get_final_taint_status(taint_source.mem_ref_entity_list);
				if (mem_address_status == TAINT_STATUS_SYMBOLIC) {
					// Address is symbolic. We have to stop concrete execution and so can stop analysing
					return TAINT_STATUS_DEPENDS_ON_READ_FROM_SYMBOLIC_ADDR;
				}
				else {
					// Address is concrete so we check result of the memory read
					mem_read_result_t mem_read_result;
					try {
						mem_read_result = mem_reads_map.at(taint_source.instr_addr);
					}
					catch (std::out_of_range) {
						assert(false && "[sim_unicorn] Taint sink depends on a read not executed yet! This should not happen!");
					}
					is_symbolic = mem_read_result.is_value_symbolic;
				}
			}
		}
		if (is_symbolic) {
			return TAINT_STATUS_SYMBOLIC;
		}
		return TAINT_STATUS_CONCRETE;
	}

	// A vector version of get_final_taint_status for checking mem_ref_entity_list which can't be an
	// unordered_set
	taint_status_result_t get_final_taint_status(const std::vector<taint_entity_t> &taint_sources) {
		std::unordered_set<taint_entity_t> taint_sources_set(taint_sources.begin(), taint_sources.end());
		return get_final_taint_status(taint_sources_set);
	}

	inline void mark_register_symbolic(vex_reg_offset_t reg_offset, bool do_block_level) {
		if (!is_valid_dependency_register(reg_offset)) {
			return;
		}
		if (do_block_level) {
			// Mark register as symbolic in current block
			block_symbolic_registers.emplace(reg_offset);
			block_concrete_registers.erase(reg_offset);
		}
		else {
			// Mark register as symbolic in the state
			if (cpu_flags.find(reg_offset) != cpu_flags.end()) {
				symbolic_registers.emplace(reg_offset);
			}
			else {
				for (int i = 0; i < reg_size_map.at(reg_offset); i++) {
					symbolic_registers.emplace(reg_offset + i);
				}
			}
		}
		return;
	}

	inline void mark_temp_symbolic(vex_tmp_id_t temp_id) {
		// Mark VEX temp as symbolic in current block
		block_symbolic_temps.emplace(temp_id);
		return;
	}

	inline void mark_register_concrete(vex_reg_offset_t reg_offset, bool do_block_level) {
		if (!is_valid_dependency_register(reg_offset)) {
			return;
		}
		if (do_block_level) {
			// Mark this register as concrete in the current block
			block_concrete_registers.emplace(reg_offset);
			block_symbolic_registers.erase(reg_offset);
		}
		else {
			if (cpu_flags.find(reg_offset) != cpu_flags.end()) {
				symbolic_registers.erase(reg_offset);
			}
			else {
				for (int i = 0; i < reg_size_map.at(reg_offset); i++) {
					symbolic_registers.erase(reg_offset + i);
				}
			}
		}
		return;
	}

	inline bool is_valid_dependency_register(vex_reg_offset_t reg_offset) const {
		return ((artificial_vex_registers.count(reg_offset) == 0) && (blacklisted_registers.count(reg_offset) == 0));
	}

	inline bool is_symbolic_register(vex_reg_offset_t reg_offset) const {
		// We check if this register is symbolic or concrete in the block level taint statuses since
		// those are more recent. If not found in either, check the state's symbolic register list.
		if (block_symbolic_registers.count(reg_offset) > 0) {
			return true;
		}
		else if (block_concrete_registers.count(reg_offset) > 0) {
			return false;
		}
		else if (symbolic_registers.count(reg_offset) > 0) {
			return true;
		}
		return false;
	}

	inline bool is_symbolic_temp(vex_tmp_id_t temp_id) const {
		return (block_symbolic_temps.count(temp_id) > 0);
	}

	inline bool is_symbolic_register_or_temp(const taint_entity_t &entity) const {
		if (entity.entity_type == TAINT_ENTITY_REG) {
			return is_symbolic_register(entity.reg_offset);
		}
		return is_symbolic_temp(entity.tmp_id);
	}

	void propagate_taints() {
		if (is_symbolic_tracking_disabled()) {
			// We're not checking symbolic registers so no need to propagate taints
			return;
		}
		block_taint_entry_t block_taint_entry = this->block_taint_cache.at(block_details.block_addr);
		if (((symbolic_registers.size() > 0) || (block_symbolic_registers.size() > 0))
		   && block_taint_entry.has_unsupported_stmt_or_expr_type) {
			// There are symbolic registers and VEX statements in block for which taint propagation
			// is not supported. Stop concrete execution.
			stop(block_taint_entry.unsupported_stmt_stop_reason);
			return;
		}
		// Resume propagating taints using symbolic_registers and symbolic_temps from where we paused
		auto instr_taint_data_entries_it = block_taint_entry.block_instrs_taint_data_map.find(taint_engine_next_instr_address);
		auto instr_taint_data_stop_it = block_taint_entry.block_instrs_taint_data_map.end();
		// We continue propagating taint until we encounter 1) a memory read, 2) end of block or
		// 3) a stop state for concrete execution
		for (; instr_taint_data_entries_it != instr_taint_data_stop_it && !stopped; ++instr_taint_data_entries_it) {
			address_t curr_instr_addr = instr_taint_data_entries_it->first;
			instruction_taint_entry_t curr_instr_taint_entry = instr_taint_data_entries_it->second;
			if (curr_instr_taint_entry.has_memory_read) {
				// Pause taint propagation to process the memory read and continue from instruction
				// after the memory read.
				taint_engine_mem_read_stop_instruction = curr_instr_addr;
				taint_engine_next_instr_address = std::next(instr_taint_data_entries_it)->first;
				break;
			}
			propagate_taint_of_one_instr(curr_instr_addr, curr_instr_taint_entry);
			if (!stopped && (curr_instr_addr == block_taint_entry.exit_stmt_instr_addr)) {
				if (block_details.vex_lift_failed && ((symbolic_registers.size() > 0) || (block_symbolic_registers.size() > 0))) {
					// There are symbolic registers but VEX lift failed so we can't determine
					// status of guard condition
					stop(STOP_VEX_LIFT_FAILED);
					return;
				}
				else if (is_block_exit_guard_symbolic()) {
					stop(STOP_SYMBOLIC_BLOCK_EXIT_STMT);
				}
			}
		}
		return;
	}

	void propagate_taint_of_mem_read_instr(const address_t instr_addr) {
		if (is_symbolic_tracking_disabled()) {
			// We're not checking symbolic registers so no need to propagate taints
			return;
		}
		auto mem_read_result = mem_reads_map.at(instr_addr);
		if (block_details.vex_lift_failed) {
			if (mem_read_result.is_value_symbolic || (symbolic_registers.size() > 0) || (block_symbolic_registers.size() > 0)) {
				// Either the memory value is symbolic or there are symbolic registers: thus, taint
				// status of registers could change. But since VEX lift failed, the taint relations
				// are not known and so we can't propagate taint. Stop concrete execution.
				stop(STOP_VEX_LIFT_FAILED);
				return;
			}
			else {
				// We cannot propagate taint since VEX lift failed and so we stop here. But, since
				// there are no symbolic values, we do need need to propagate taint. Of course,
				// the register slices cannot be updated but those won't be needed since this
				// block will never be executed partially concretely and rest in VEX engine.
				return;
			}
		}

		auto block_taint_entry = block_taint_cache.at(block_details.block_addr);
		if (block_taint_entry.has_unsupported_stmt_or_expr_type) {
			if (mem_read_result.is_value_symbolic || (symbolic_registers.size() > 0) || (block_symbolic_registers.size() > 0)) {
				// There are symbolic registers and/or memory read was symbolic and there are VEX
				// statements in block for which taint propagation is not supported.
				stop(block_taint_entry.unsupported_stmt_stop_reason);
				return;
			}
		}
		else {
			auto instr_taint_data_entry = block_taint_entry.block_instrs_taint_data_map.at(instr_addr);
			propagate_taint_of_one_instr(instr_addr, instr_taint_data_entry);
		}
		return;
	}

	void propagate_taint_of_one_instr(address_t instr_addr, const instruction_taint_entry_t &instr_taint_entry) {
		instr_details_t instr_details;
		bool is_instr_symbolic;

		is_instr_symbolic = false;
		instr_details.instr_addr = instr_addr;
		compute_slice_of_instrs(instr_addr, instr_taint_entry);
		if (instr_taint_entry.has_memory_read) {
			auto mem_read_result = mem_reads_map.at(instr_addr);
			if (!mem_read_result.is_value_symbolic) {
				instr_details.memory_value.address = mem_read_result.address;
				instr_details.memory_value.size = mem_read_result.size;
				for (int i = 0; i < MAX_MEM_ACCESS_SIZE; i++) {
					instr_details.memory_value.value[i] = mem_read_result.value[i];
				}
				instr_details.has_memory_dep = true;
			}
			else {
				is_instr_symbolic = true;
				instr_details.has_memory_dep = false;
				instr_details.memory_value.address = 0;
				instr_details.memory_value.size = 0;
				memset(instr_details.memory_value.value, 0, MAX_MEM_ACCESS_SIZE);
			};
		}
		else {
			instr_details.has_memory_dep = false;
			instr_details.memory_value.address = 0;
			instr_details.memory_value.size = 0;
			memset(instr_details.memory_value.value, 0, MAX_MEM_ACCESS_SIZE);
		}
		for (auto &taint_data_entry: instr_taint_entry.taint_sink_src_map) {
			taint_entity_t taint_sink = taint_data_entry.first;
			std::unordered_set<taint_entity_t> taint_srcs = taint_data_entry.second;
			if (taint_sink.entity_type == TAINT_ENTITY_MEM) {
				auto addr_taint_status = get_final_taint_status(taint_sink.mem_ref_entity_list);
				// Check if address written to is symbolic or is read from memory
				if (addr_taint_status != TAINT_STATUS_CONCRETE) {
					stop(STOP_SYMBOLIC_WRITE_ADDR);
					return;
				}
				auto sink_taint_status = get_final_taint_status(taint_srcs);
				if (sink_taint_status == TAINT_STATUS_DEPENDS_ON_READ_FROM_SYMBOLIC_ADDR) {
					stop(STOP_SYMBOLIC_READ_ADDR);
					return;
				}
				auto mem_writes_taint_entry = mem_writes_taint_map.find(taint_sink.instr_addr);
				if (mem_writes_taint_entry != mem_writes_taint_map.end()) {
					bool is_curr_write_symbolic = (sink_taint_status == TAINT_STATUS_SYMBOLIC) ? true: false;
					if (is_curr_write_symbolic != mem_writes_taint_entry->second) {
						// Current write value and previous write value have different taint status.
						// Since we cannot compute exact addresses modified, stop concrete execution.
						stop(STOP_MULTIPLE_MEMORY_WRITES);
						return;
					}
				}
				else if (sink_taint_status == TAINT_STATUS_SYMBOLIC) {
					// Save the memory location written to be marked as symbolic in write hook
					mem_writes_taint_map.emplace(taint_sink.instr_addr, true);
					// Mark instruction as needing symbolic execution
					is_instr_symbolic = true;
				}
				else {
					// Save the memory location(s) written to be marked as concrete in the write hook
					mem_writes_taint_map.emplace(taint_sink.instr_addr, false);
				}
			}
			else if (taint_sink.entity_type != TAINT_ENTITY_NONE) {
				taint_status_result_t final_taint_status = get_final_taint_status(taint_srcs);
				if (final_taint_status == TAINT_STATUS_DEPENDS_ON_READ_FROM_SYMBOLIC_ADDR) {
					stop(STOP_SYMBOLIC_READ_ADDR);
					return;
				}
				else if (final_taint_status == TAINT_STATUS_SYMBOLIC) {
					if ((taint_sink.entity_type == TAINT_ENTITY_REG) && (taint_sink.reg_offset == arch_pc_reg_vex_offset())) {
						stop(STOP_SYMBOLIC_PC);
						return;
					}

					// Mark instruction as needing symbolic execution
					is_instr_symbolic = true;

					// Mark sink as symbolic
					if (taint_sink.entity_type == TAINT_ENTITY_REG) {
						mark_register_symbolic(get_full_register_offset(taint_sink.reg_offset), true);
					}
					else {
						mark_temp_symbolic(taint_sink.tmp_id);
					}
				}
				else if ((taint_sink.entity_type == TAINT_ENTITY_REG) && (taint_sink.reg_offset != arch_pc_reg_vex_offset())) {
					// Mark register as concrete since none of it's dependencies are symbolic. Also update it's slice.
					vex_reg_offset_t taint_sink_full_register_offset = get_full_register_offset(taint_sink.reg_offset);
					mark_register_concrete(taint_sink_full_register_offset, true);

					if (is_valid_dependency_register(taint_sink_full_register_offset)) {
						bool is_sink_source = false;
						for (auto &dependency: instr_taint_entry.dependencies_to_save) {
							if (dependency.entity_type != TAINT_ENTITY_REG) {
								continue;
							}
							vex_reg_offset_t dependency_full_register_offset = get_full_register_offset(dependency.reg_offset);
							if (taint_sink_full_register_offset == dependency_full_register_offset) {
								is_sink_source = true;
								break;
							}
						}
						if (!is_sink_source) {
							reg_instr_slice.at(taint_sink_full_register_offset).clear();
						}
						reg_instr_slice.at(taint_sink_full_register_offset).emplace_back(instr_details);
					}
				}
			}
			auto ite_cond_taint_status = get_final_taint_status(instr_taint_entry.ite_cond_entity_list);
			if (ite_cond_taint_status != TAINT_STATUS_CONCRETE) {
				stop(STOP_SYMBOLIC_CONDITION);
				return;
			}
		}
		if (is_instr_symbolic) {
			auto instr_slice_details = instr_slice_details_map.at(instr_addr);
			block_concrete_dependencies.insert(instr_slice_details.concrete_registers.begin(), instr_slice_details.concrete_registers.end());

			std::set<instr_details_t> symbolic_instrs_set(block_details.symbolic_instrs.begin(), block_details.symbolic_instrs.end());
			block_details.symbolic_instrs.clear();
			symbolic_instrs_set.insert(instr_slice_details.dependent_instrs.begin(), instr_slice_details.dependent_instrs.end());
			block_details.symbolic_instrs.insert(block_details.symbolic_instrs.end(), symbolic_instrs_set.begin(), symbolic_instrs_set.end());
			block_details.symbolic_instrs.emplace_back(instr_details);
		}
		return;
	}

	inline void read_memory_value(address_t address, uint64_t size, uint8_t *result, size_t result_size) const {
		memset(result, 0, result_size);
		uc_mem_read(uc, address, result, size);
		return;
	}

	void start_propagating_taint(address_t block_address, int32_t block_size) {
		block_details.block_addr = block_address;
		block_details.block_size = block_size;
		if (is_symbolic_tracking_disabled()) {
			// We're not checking symbolic registers so no need to propagate taints
			return;
		}
		if (this->block_taint_cache.find(block_address) == this->block_taint_cache.end()) {
			// Compute and cache taint sink-source relations for this block
			// Disable cross instruction optimization in IR so that dependencies of symbolic
			// instructions can be computed correctly.
			VexRegisterUpdates pxControl = VexRegUpdLdAllregsAtEachInsn;
			std::unique_ptr<uint8_t[]> instructions(new uint8_t[block_size]);
			uc_mem_read(this->uc, block_address, instructions.get(), block_size);
			VEXLiftResult *lift_ret = vex_lift(
				this->vex_guest, this->vex_archinfo, instructions.get(), block_address, 99, block_size, 1, 0, 1,
				1, 0, pxControl
			);

			if ((lift_ret == NULL) || (lift_ret->size == 0)) {
				// Failed to lift block to VEX.
				if (symbolic_registers.size() > 0) {
					// There are symbolic registers but VEX lift failed so we can't propagate taint
					stop(STOP_VEX_LIFT_FAILED);
				}
				else {
					// There are no symbolic registers so attempt to execute block. Mark block as VEX lift failed.
					block_details.vex_lift_failed = true;
				}
				return;
			}
			auto block_taint_entry = compute_taint_sink_source_relation_of_block(lift_ret->irsb, block_address);
			// Add entry to taint relations cache
			block_taint_cache.emplace(block_address, block_taint_entry);
		}
		taint_engine_next_instr_address = block_address;
		block_symbolic_temps.clear();
		block_start_reg_values.clear();
		for (auto &reg_instr_slice_entry: reg_instr_slice) {
			// Clear slice for register
			reg_instr_slice_entry.second.clear();
			// Save value of all registers
			register_value_t reg_value;
			reg_value.offset = reg_instr_slice_entry.first;
			memset(reg_value.value, 0, MAX_REGISTER_BYTE_SIZE);
			get_register_value(reg_value.offset, reg_value.value);
			block_start_reg_values.emplace(reg_value.offset, reg_value);
			// Reset the slice of register
			reg_instr_slice_entry.second.clear();
		}
		for (auto &cpu_flag: cpu_flags) {
			register_value_t flag_value;
			flag_value.offset = cpu_flag.first;
			memset(flag_value.value, 0, MAX_REGISTER_BYTE_SIZE);
			get_register_value(cpu_flag.first, flag_value.value);
			block_start_reg_values.emplace(flag_value.offset, flag_value);
		}
		propagate_taints();
		return;
	}

	void continue_propagating_taint() {
		if (is_symbolic_tracking_disabled()) {
			// We're not checking symbolic registers so no need to propagate taints
			return;
		}
		if (block_details.vex_lift_failed) {
			if ((symbolic_registers.size() > 0) || (block_symbolic_registers.size() > 0)) {
				// There are symbolic registers but VEX lift failed so we can't propagate taint
				stop(STOP_VEX_LIFT_FAILED);
				return;
			}
		}
		else {
			propagate_taints();
		}
		return;
	}

	inline unsigned int arch_pc_reg_vex_offset() {
		const unsigned int pc_reg_offset_x86 = 68;
		const unsigned int pc_reg_offset_amd64 = 184;
		const unsigned int pc_reg_offset_arm = 68;
		const unsigned int pc_reg_offset_arm64 = 272;
		const unsigned int pc_reg_offset_mips32 = 136;
		const unsigned int pc_reg_offset_mips64 = 272;
		switch (arch) {
			case UC_ARCH_X86:
				return mode == UC_MODE_64 ? pc_reg_offset_amd64 : pc_reg_offset_x86;
			case UC_ARCH_ARM:
				return pc_reg_offset_arm;
			case UC_ARCH_ARM64:
				return pc_reg_offset_arm64;
			case UC_ARCH_MIPS:
				return mode == UC_MODE_64 ? pc_reg_offset_mips64 : pc_reg_offset_mips32;
			default:
				return -1;
		}
	}

	inline unsigned int arch_pc_reg() {
		switch (arch) {
			case UC_ARCH_X86:
				return mode == UC_MODE_64 ? UC_X86_REG_RIP : UC_X86_REG_EIP;
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

	inline bool is_block_exit_guard_symbolic() {
		block_taint_entry_t block_taint_entry = block_taint_cache.at(block_details.block_addr);
		auto block_exit_guard_taint_status = get_final_taint_status(block_taint_entry.exit_stmt_guard_expr_deps);
		return (block_exit_guard_taint_status != TAINT_STATUS_CONCRETE);
	}

	inline unsigned int arch_sp_reg() {
		switch (arch) {
			case UC_ARCH_X86:
				return mode == UC_MODE_64 ? UC_X86_REG_RSP : UC_X86_REG_ESP;
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

	address_t get_instruction_pointer() {
		address_t out = 0;
		unsigned int reg = arch_pc_reg();
		if (reg == -1) {
			out = 0;
		} else {
			uc_reg_read(uc, reg, &out);
		}

		return out;
	}

	address_t get_stack_pointer() {
		address_t out = 0;
		unsigned int reg = arch_sp_reg();
		if (reg == -1) {
			out = 0;
		} else {
			uc_reg_read(uc, reg, &out);
		}

		return out;
	}

	inline vex_reg_offset_t get_full_register_offset(vex_reg_offset_t reg_offset) {
		auto vex_sub_reg_mapping_entry = vex_sub_reg_map.find(reg_offset);
		if (vex_sub_reg_mapping_entry != vex_sub_reg_map.end()) {
			return vex_sub_reg_mapping_entry->second;
		}
		return reg_offset;
	}

	inline address_t get_taint_engine_mem_read_stop_instruction() const {
		return taint_engine_mem_read_stop_instruction;
	}
};

static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	// uc_mem_read(uc, address, &value, size);
	// //LOG_D("mem_read [%#lx, %#lx] = %#lx", address, address + size);
	//LOG_D("mem_read [%#lx, %#lx]", address, address + size);
	State *state = (State *)user_data;
	mem_read_result_t mem_read_result;

	mem_read_result.address = address;
	mem_read_result.size = size;
	address_t curr_instr_addr = state->get_instruction_pointer();
	if (curr_instr_addr != state->get_taint_engine_mem_read_stop_instruction()) {
		// The instruction address unicorn reported is different from the expected value for memory read instruction.
		// Also see https://github.com/unicorn-engine/unicorn/issues/1312.
		state->stop(STOP_UNKNOWN_MEMORY_READ);
		return;
	}
	auto tainted = state->find_tainted(address, size);
	if (tainted != -1)
	{
		if (state->is_symbolic_tracking_disabled()) {
			// Symbolic register tracking is disabled but memory location has symbolic data.
			// We switch to VEX engine then.
			state->stop(STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED);
			return;
		}
		mem_read_result.is_value_symbolic = true;
	}
	else
	{
		mem_read_result.is_value_symbolic = false;
		state->read_memory_value(address, size, mem_read_result.value, MAX_MEM_ACCESS_SIZE);
	}
	auto mem_reads_map_entry = state->mem_reads_map.find(curr_instr_addr);
	if (mem_reads_map_entry == state->mem_reads_map.end()) {
		// Propagate taint if this is a memory read not encountered before.
		// Reads from XMM registers trigger multiple memory read hooks so
		// we should propagate taint only in first hook
		state->mem_reads_map.emplace(curr_instr_addr, mem_read_result);
		state->propagate_taint_of_mem_read_instr(curr_instr_addr);
		if (!state->stopped) {
			state->continue_propagating_taint();
		}
	}
	else if (mem_reads_map_entry->second.is_value_symbolic != mem_read_result.is_value_symbolic) {
		// The taint of previous memory read is different from taint of current memory read.
		// We stop concrete execution since we already propagated taint based on previous read.
		// Additionally, currently cannot determine exact memory address of taint source when
		// propagating taint and so we cannot fix any incorrect propagation.
		stop(STOP_MULTIPLE_MEMORY_READS);
	}
	return;
}

/*
 * the goal of hooking memory write is to determine the exact
 * positions of dirty bytes to writing chaneges back to angr
 * state. However if the hook is hit before mapping requested
 * page (as writable), we cannot find the bitmap for this page.
 * In this case, just mark all the position as clean (before
 * this access).
 */

static void hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	//LOG_D("mem_write [%#lx, %#lx]", address, address + size);
	State *state = (State *)user_data;

	if (state->ignore_next_selfmod) {
		// ...the self-modification gets repeated for internal qemu reasons
		state->ignore_next_selfmod = false;
	} else if ((address >= state->cur_address && address < state->cur_address + state->cur_size) ||
		// CODE IS SELF-MODIFYING: qemu will restart this basic block at this address.
		// discard the next block hook
		(state->cur_address >= address && state->cur_address < address + size)) {
		state->ignore_next_block = true;
	}

	state->handle_write(address, size, false);
}

static void hook_block(uc_engine *uc, uint64_t address, int32_t size, void *user_data) {
	//LOG_I("block [%#lx, %#lx]", address, address + size);

	State *state = (State *)user_data;
	if (state->ignore_next_block) {
		state->ignore_next_block = false;
		state->ignore_next_selfmod = true;
		return;
	}
	state->commit();
	state->step(address, size);

	if (!state->stopped) {
		state->start_propagating_taint(address, size);
	}
	return;
}

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data) {
	State *state = (State *)user_data;
	state->interrupt_handled = false;

	if (state->arch == UC_ARCH_X86 && intno == 0x80) {
		// this is the ultimate hack for cgc -- it must be enabled by explitly setting the transmit sysno from python
		// basically an implementation of the cgc transmit syscall

		for (auto sr : state->symbolic_registers)
		{
			// eax,ecx,edx,ebx,esi
			if ((sr >= 8 && sr <= 23) || (sr >= 32 && sr <= 35)) return;
		}

		uint32_t sysno;
		uc_reg_read(uc, UC_X86_REG_EAX, &sysno);
		//printf("SYSCALL: %d\n", sysno);
		if (sysno == state->transmit_sysno) {
			//printf(".. TRANSMIT!\n");
			uint32_t fd, buf, count, tx_bytes;

			uc_reg_read(uc, UC_X86_REG_EBX, &fd);

			if (fd == 2) {
				// we won't try to handle fd 2 prints here, they are uncommon.
				return;
			} else if (fd == 0 || fd == 1) {
				uc_reg_read(uc, UC_X86_REG_ECX, &buf);
				uc_reg_read(uc, UC_X86_REG_EDX, &count);
				uc_reg_read(uc, UC_X86_REG_ESI, &tx_bytes);

				// ensure that the memory we're sending is not tainted
				// TODO: Can transmit also work with symbolic bytes?
				void *dup_buf = malloc(count);
				uint32_t tmp_tx;
				if (uc_mem_read(uc, buf, dup_buf, count) != UC_ERR_OK)
				{
					//printf("... fault on buf\n");
					free(dup_buf);
					return;
				}

				if (tx_bytes != 0 && uc_mem_read(uc, tx_bytes, &tmp_tx, 4) != UC_ERR_OK)
				{
					//printf("... fault on tx\n");
					free(dup_buf);
					return;
				}

				if (state->find_tainted(buf, count) != -1)
				{
					//printf("... symbolic data\n");
					free(dup_buf);
					return;
				}

				state->step(state->transmit_bbl_addr, 0, false);
				state->commit();
				if (state->stopped)
				{
					//printf("... stopped after step()\n");
					free(dup_buf);
					return;
				}

				uc_err err = uc_mem_write(uc, tx_bytes, &count, 4);
				if (tx_bytes != 0) state->handle_write(tx_bytes, 4, true);
				state->transmit_records.push_back({dup_buf, count});
				int result = 0;
				uc_reg_write(uc, UC_X86_REG_EAX, &result);
				state->symbolic_registers.erase(8);
				state->symbolic_registers.erase(9);
				state->symbolic_registers.erase(10);
				state->symbolic_registers.erase(11);
				state->interrupt_handled = true;
				state->syscall_count++;
				return;
			}
		}
	}
}

static bool hook_mem_unmapped(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	State *state = (State *)user_data;
	uint64_t start = address & ~0xFFFULL;
	uint64_t end = (address + size - 1) & ~0xFFFULL;

	// only hook nonwritable pages
	if (type != UC_MEM_WRITE_UNMAPPED && state->map_cache(start, 0x1000) && (start == end || state->map_cache(end, 0x1000))) {
		//LOG_D("handle unmapped page natively");
		return true;
	}

	return false;
}

static bool hook_mem_prot(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	State *state = (State *)user_data;
	//printf("Segfault data: %d %#llx %d %#llx\n", type, address, size, value);
	state->stop(STOP_SEGFAULT);
	return true;
}

/*
 * C style bindings makes it simple and dirty
 */

extern "C"
State *simunicorn_alloc(uc_engine *uc, uint64_t cache_key) {
	State *state = new State(uc, cache_key);
	return state;
}

extern "C"
void simunicorn_dealloc(State *state) {
	delete state;
}

extern "C"
uint64_t *simunicorn_bbl_addrs(State *state) {
	return &(state->bbl_addrs[0]);
}

extern "C"
uint64_t *simunicorn_stack_pointers(State *state) {
	return &(state->stack_pointers[0]);
}

extern "C"
uint64_t simunicorn_bbl_addr_count(State *state) {
	return state->bbl_addrs.size();
}

extern "C"
uint64_t simunicorn_syscall_count(State *state) {
	return state->syscall_count;
}

extern "C"
void simunicorn_hook(State *state) {
	state->hook();
}

extern "C"
void simunicorn_unhook(State *state) {
	state->unhook();
}

extern "C"
uc_err simunicorn_start(State *state, uint64_t pc, uint64_t step) {
	return state->start(pc, step);
}

extern "C"
void simunicorn_stop(State *state, stop_t reason) {
	state->stop(reason);
}

extern "C"
mem_update_t *simunicorn_sync(State *state) {
	return state->sync();
}

extern "C"
void simunicorn_destroy(mem_update_t * head) {
	mem_update_t *next;
	for (mem_update_t *cur = head; cur; cur = next) {
		next = cur->next;
		delete cur;
	}
}

extern "C"
uint64_t simunicorn_step(State *state) {
	return state->cur_steps;
}

extern "C"
void simunicorn_set_stops(State *state, uint64_t count, uint64_t *stops)
{
	state->set_stops(count, stops);
}

extern "C"
void simunicorn_activate_page(State *state, uint64_t address, uint8_t *taint, uint8_t *data) {
    state->page_activate(address, taint, data);
}

extern "C"
uint64_t simunicorn_executed_pages(State *state) { // this is HORRIBLE
	if (state->executed_pages_iterator == NULL) {
		state->executed_pages_iterator = new std::unordered_set<address_t>::iterator;
		*state->executed_pages_iterator = state->executed_pages.begin();
	}

	if (*state->executed_pages_iterator == state->executed_pages.end()) {
		delete state->executed_pages_iterator;
		state->executed_pages_iterator = NULL;
		return -1;
	}

	uint64_t out = **state->executed_pages_iterator;
	(*state->executed_pages_iterator)++;
	return out;
}

//
// Stop analysis
//

extern "C"
stop_t simunicorn_stop_reason(State *state) {
	return state->stop_reason;
}

extern "C"
const char * simunicorn_stop_message(State *state) {
	return state->stop_reason_msg;
}

//
// Symbolic register tracking
//

extern "C"
void simunicorn_symbolic_register_data(State *state, uint64_t count, uint64_t *offsets)
{
	state->symbolic_registers.clear();
	for (int i = 0; i < count; i++)
	{
		state->symbolic_registers.insert(offsets[i]);
	}
}

extern "C"
uint64_t simunicorn_get_symbolic_registers(State *state, uint64_t *output)
{
	int i = 0;
	for (auto r : state->symbolic_registers)
	{
		output[i] = r;
		i++;
	}
	return i;
}

extern "C"
void simunicorn_enable_symbolic_reg_tracking(State *state, VexArch guest, VexArchInfo archinfo) {
	state->vex_guest = guest;
	state->vex_archinfo = archinfo;
}

extern "C"
void simunicorn_disable_symbolic_reg_tracking(State *state) {
	state->vex_guest = VexArch_INVALID;
}

//
// Concrete transmits
//

extern "C"
bool simunicorn_is_interrupt_handled(State *state) {
	return state->interrupt_handled;
}

extern "C"
void simunicorn_set_transmit_sysno(State *state, uint32_t sysno, uint64_t bbl_addr) {
	state->transmit_sysno = sysno;
	state->transmit_bbl_addr = bbl_addr;
}

extern "C"
transmit_record_t *simunicorn_process_transmit(State *state, uint32_t num) {
	if (num >= state->transmit_records.size()) {
		for (auto record_iter = state->transmit_records.begin();
				record_iter != state->transmit_records.end();
				record_iter++) {
			free(record_iter->data);
		}
		state->transmit_records.clear();
		return NULL;
	} else {
		transmit_record_t *out = &state->transmit_records[num];
		return out;
	}
}


/*
 * Page cache
 */

extern "C"
bool simunicorn_cache_page(State *state, uint64_t address, uint64_t length, char *bytes, uint64_t permissions) {
	//LOG_I("caching [%#lx, %#lx]", address, address + length);

	auto actual = state->cache_page(address, length, bytes, permissions);
	if (!state->map_cache(actual.first, actual.second)) {
		return false;
	}
	return true;
}

extern "C"
void simunicorn_uncache_pages_touching_region(State *state, uint64_t address, uint64_t length) {
	state->uncache_pages_touching_region(address, length);
}

extern "C"
void simunicorn_clear_page_cache(State *state) {
	state->clear_page_cache();
}

// Tracking settings
extern "C"
void simunicorn_set_tracking(State *state, bool track_bbls, bool track_stack) {
	state->track_bbls = track_bbls;
	state->track_stack = track_stack;
}

extern "C"
bool simunicorn_in_cache(State *state, uint64_t address) {
	return state->in_cache(address);
}

extern "C"
void simunicorn_set_map_callback(State *state, uc_cb_eventmem_t cb) {
    state->py_mem_callback = cb;
}

// VEX artificial registers list
extern "C"
void simunicorn_set_artificial_registers(State *state, uint64_t *offsets, uint64_t count) {
	state->artificial_vex_registers.clear();
	for (int i = 0; i < count; i++) {
		state->artificial_vex_registers.emplace(offsets[i]);
	}
	return;
}

// Register sizes mapping
extern "C"
void simunicorn_set_vex_offset_to_register_size_mapping(State *state, uint64_t *vex_offsets, uint64_t *reg_sizes, uint64_t count) {
	state->reg_size_map.clear();
	for (int i = 0; i < count; i++) {
		state->reg_size_map.emplace(vex_offsets[i], reg_sizes[i]);
	}
	return;
}

// VEX register offsets to unicorn register ID mappings
extern "C"
void simunicorn_set_vex_to_unicorn_reg_mappings(State *state, uint64_t *vex_offsets, uint64_t *unicorn_ids, uint64_t count) {
	state->vex_to_unicorn_map.clear();
	for (int i = 0; i < count; i++) {
		state->vex_to_unicorn_map.emplace(vex_offsets[i], unicorn_ids[i]);
	}
	return;
}

// VEX sub-registers to full register mapping
extern "C"
void simunicorn_set_vex_sub_reg_to_reg_mappings(State *state, uint64_t *vex_sub_reg_offsets, uint64_t *vex_reg_offsets, uint64_t count) {
	state->vex_sub_reg_map.clear();
	for (int i = 0; i < count; i++) {
		state->vex_sub_reg_map.emplace(vex_sub_reg_offsets[i], vex_reg_offsets[i]);
	}
	return;
}

// Mapping details for flags registers
extern "C"
void simunicorn_set_cpu_flags_details(State *state, uint64_t *flag_vex_id, uint64_t *bitmasks, uint64_t count) {
	state->cpu_flags.clear();
	for (int i = 0; i < count; i++) {
		state->cpu_flags.emplace(flag_vex_id[i], bitmasks[i]);
	}
	return;
}

// Flag register ID in unicorn
extern "C"
void simunicorn_set_unicorn_flags_register_id(State *state, int64_t reg_id) {
	state->cpu_flags_register = reg_id;
	return;
}

extern "C"
void simunicorn_set_register_blacklist(State *state, uint64_t *reg_list, uint64_t count) {
	state->blacklisted_registers.clear();
	for (int i = 0; i < count; i++) {
		state->blacklisted_registers.emplace(reg_list[i]);
	}
	return;
}

// VEX re-execution data

extern "C"
uint64_t simunicorn_get_count_of_blocks_with_symbolic_instrs(State *state) {
	return state->blocks_with_symbolic_instrs.size();
}

extern "C"
void simunicorn_get_details_of_blocks_with_symbolic_instrs(State *state, block_details_ret_t *ret_block_details) {
	for (auto i = 0; i < state->blocks_with_symbolic_instrs.size(); i++) {
		ret_block_details[i].block_addr = state->blocks_with_symbolic_instrs[i].block_addr;
		ret_block_details[i].block_size = state->blocks_with_symbolic_instrs[i].block_size;
		ret_block_details[i].symbolic_instrs = &(state->blocks_with_symbolic_instrs[i].symbolic_instrs[0]);
		ret_block_details[i].symbolic_instrs_count = state->blocks_with_symbolic_instrs[i].symbolic_instrs.size();
		ret_block_details[i].register_values = &(state->blocks_with_symbolic_instrs[i].register_values[0]);
		ret_block_details[i].register_values_count = state->blocks_with_symbolic_instrs[i].register_values.size();
	}
	return;
}

extern "C"
stopped_instr_details_t simunicorn_get_stopping_instruction_details(State *state) {
	return state->stopped_at_instr;
}
