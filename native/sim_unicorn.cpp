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

#define MAX_REG_SIZE 0x2000 // hope it's big enough

// Maximum size of a qemu/unicorn basic block
// See State::step for why this is necessary
static const uint32_t MAX_BB_SIZE = 800;

static const uint8_t MAX_MEM_ACCESS_SIZE = 8;

extern "C" void x86_reg_update(uc_engine *uc, uint8_t *buf, int save);
extern "C" void mips_reg_update(uc_engine *uc, uint8_t *buf, int save);

typedef enum taint: uint8_t {
	TAINT_NONE = 0,
	TAINT_SYMBOLIC = 1, // this should be 1 to match the UltraPage impl
	TAINT_DIRTY = 2,
} taint_t;

typedef enum taint_entity: uint8_t {
	TAINT_ENTITY_REG = 0,
	TAINT_ENTITY_TMP = 1,
	TAINT_ENTITY_MEM = 2,
	TAINT_ENTITY_NONE = 3,
} taint_entity_enum_t;

typedef enum taint_status_result_t {
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

typedef struct mem_read_result_t {
	address_t address;
	uint8_t value[MAX_MEM_ACCESS_SIZE]; // Assume size of read is not more than 8 just like write
	size_t size;
	bool is_value_symbolic;
} mem_read_result_t;

typedef struct saved_concrete_dependency_t {
	taint_entity_enum_t dependency_type;
	vex_reg_offset_t reg_offset;
	uint64_t reg_value;
	address_t mem_address;
	size_t mem_value_size;
	uint8_t mem_value[MAX_MEM_ACCESS_SIZE];
} saved_concrete_dependency_t;

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
} stop_t;

typedef struct block_entry {
	bool try_unicorn;
	std::unordered_set<vex_reg_offset_t> used_registers;
	std::unordered_set<vex_reg_offset_t> clobbered_registers;
} block_entry_t;

typedef std::vector<std::pair<taint_entity_t, std::unordered_set<taint_entity_t>>> taint_vector_t;

typedef struct instruction_taint_entry_t {
	// List of direct taint sources for a taint sink
	taint_vector_t taint_sink_src_map;

	// List of registers and memory a taint sink depends on directly or indirectly
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

	bool operator==(const block_taint_entry_t &other_entry) const {
		return (block_instrs_taint_data_map == other_entry.block_instrs_taint_data_map) &&
			   (exit_stmt_guard_expr_deps == other_entry.exit_stmt_guard_expr_deps);
	}
} block_taint_entry_t;

typedef struct CachedPage {
	size_t size;
	uint8_t *bytes;
	uint64_t perms;
} CachedPage;

typedef taint_t PageBitmap[PAGE_SIZE];
typedef std::map<address_t, CachedPage> PageCache;
typedef std::unordered_map<address_t, block_entry_t> BlockCache;
typedef std::unordered_map<address_t, block_taint_entry_t> BlockTaintCache;
typedef struct caches {
	PageCache *page_cache;
	BlockCache *block_cache;
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
static void hook_save_dependencies(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

class State {
private:
	uc_engine *uc;
	PageCache *page_cache;
	BlockCache *block_cache;
	BlockTaintCache block_taint_cache;
	bool hooked;

	uc_context *saved_regs;

	std::vector<mem_access_t> mem_writes;
	// List of all memory writes and their taint status
	// Memory write instruction address -> is_symbolic
	// TODO: Need to modify memory write taint handling for architectures that perform multiple
	// memory writes in a single instruction
	std::unordered_map<address_t, bool> mem_writes_taint_map;

	// List of all concrete dependencies to save. Currently only registers; memory saved in hooks.
	// Instruction address -> List of entitites to save
	std::unordered_map<address_t, std::unordered_set<taint_entity_t>> symbolic_instrs_dep_save_map;

	// List of all hooks inserted into a block for saving dependencies
	std::unordered_set<uc_hook> symbolic_instrs_dep_saving_hooks;

	// List of instructions that should be executed symbolically in each block
	std::unordered_map<address_t, std::unordered_set<address_t>> symbolic_instr_addrs;

	// List of instructions in a block that should be executed symbolically. These are stored
	// separately for easy rollback in case of errors.
	std::unordered_set<address_t> block_symbolic_instr_addrs;

	// Map with all saved dependencies
	std::unordered_map<address_t, std::vector<saved_concrete_dependency_t>> saved_dependencies_map;

	// Similar to memory reads in a block, we track the state of registers and VEX temps when
	// propagating taint in a block for easy rollback if we need to abort due to read from/write to
	// a symbolic address
	RegisterSet block_symbolic_registers, block_concrete_registers;
	TempSet block_symbolic_temps;

	// the latter part of the pair is a pointer to the page data if the page is direct-mapped, otherwise NULL
	std::map<address_t, std::pair<taint_t *, uint8_t *>> active_pages;
	//std::map<uint64_t, taint_t *> active_pages;
	std::set<uint64_t> stop_points;

	address_t current_block_start_address, current_block_size;
	address_t taint_engine_next_instr_address;
	address_t prev_block_addr;

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
	vex_reg_offset_t stopping_register;
	address_t stopping_memory;

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
	RegisterMap vex_to_unicorn_map; // Mapping of VEX offsets to unicorn registers
	RegisterSet artificial_vex_registers; // Artificial VEX registers
	TempSet symbolic_temps;

	// Result of all memory reads executed. Instruction address -> memory read result
	std::unordered_map<address_t, mem_read_result_t> mem_reads_map;

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
		current_block_start_address = 0;

		auto it = global_cache.find(cache_key);
		if (it == global_cache.end()) {
			page_cache = new PageCache();
			block_cache = new BlockCache();
			global_cache[cache_key] = {page_cache, block_cache};
		} else {
			page_cache = it->second.page_cache;
			block_cache = it->second.block_cache;
		}
		arch = *((uc_arch*)uc); // unicorn hides all its internals...
		mode = *((uc_mode*)((uc_arch*)uc + 1));
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
		executed_pages.clear();

		// error if pc is 0
		// TODO: why is this check here and not elsewhere
		if (pc == 0) {
			stop_reason = STOP_ZEROPAGE;
			cur_steps = 0;
			return UC_ERR_MAP;
		}

		uc_err out = uc_emu_start(uc, pc, 0, 0, 0);
		if (out == UC_ERR_OK && stop_reason == STOP_NOSTART && get_instruction_pointer() == 0) {
		    // handle edge case where we stop because we reached our bogus stop address (0)
		    commit(true);
		    stop_reason = STOP_ZEROPAGE;
		}
		rollback(true);

		if (out == UC_ERR_INSN_INVALID) {
			stop_reason = STOP_NODECODE;
		}

		// if we errored out right away, fix the step count to 0
		if (cur_steps == -1) cur_steps = 0;

		return out;
	}

	void stop(stop_t reason) {
		stopped = true;
		const char *msg = NULL;
		switch (reason) {
			case STOP_NORMAL:
				msg = "reached maximum steps";
				break;
			case STOP_STOPPOINT:
				msg = "hit a stop point";
				break;
			case STOP_ERROR:
				msg = "something wrong";
				break;
			case STOP_SYSCALL:
				msg = "unable to handle syscall";
				commit(true);
				break;
			case STOP_ZEROPAGE:
				msg = "accessing zero page";
				break;
			case STOP_EXECNONE:
				msg = "fetching empty page";
				break;
			case STOP_NOSTART:
				msg = "failed to start";
				break;
			case STOP_SEGFAULT:
				msg = "permissions or mapping error";
				break;
			case STOP_ZERO_DIV:
				msg = "divide by zero";
				break;
			case STOP_NODECODE:
				msg = "instruction decoding error";
				break;
			case STOP_VEX_LIFT_FAILED:
				msg = "failed to lift block to VEX";
				break;
			case STOP_SYMBOLIC_CONDITION:
				msg = "symbolic condition for ITE or Exit";
				break;
			case STOP_SYMBOLIC_READ_ADDR:
				msg = "attempted to read from symbolic address";
				break;
			case STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED:
				msg = "attempted to read symbolic data from memory but symbolic tracking is disabled";
				break;
			case STOP_SYMBOLIC_WRITE_ADDR:
				msg = "attempted to write to symbolic address";
				break;
			default:
				msg = "unknown error";
		}
		stop_reason = reason;
		//LOG_D("stop: %s", msg);
		uc_emu_stop(uc);
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
	void commit(bool end_block) {
		// save registers
		uc_context_save(uc, saved_regs);

		// mark memory sync status
		// we might miss some dirty bits, this happens if hitting the memory
		// write before mapping
		/*  THIS SHOULDN'T BE REQUIRED, we have the same logic to do this in the page activation code
		for (auto it = mem_writes.begin(); it != mem_writes.end(); it++) {
			if (it->clean == -1) {
				taint_t *bitmap = page_lookup(it->address);
				memset(&bitmap[it->address & 0xFFFULL], TAINT_DIRTY, sizeof(taint_t) * it->size);
				it->clean = (1 << it->size) - 1;
				//LOG_D("commit: lazy initialize mem_write [%#lx, %#lx]", it->address, it->address + it->size);
			}
		}
		*/

		// clear memory rollback status
		mem_writes.clear();
		if (end_block) {
			// Commit done at end of block; increase step count
			cur_steps++;
		}

		// Sync all block level taint statuses reads with state's taint statuses and block level
		// symbolic instruction list with state's symbolic instruction list
		for (auto &reg_offset: block_symbolic_registers) {
			mark_register_symbolic(reg_offset, false);
		}
		for (auto &reg_offset: block_concrete_registers) {
			mark_register_concrete(reg_offset, false);
		}
		for (auto &temp_id: block_symbolic_temps) {
			mark_temp_symbolic(temp_id, false);
		}
		auto block_symb_instrs_entry = symbolic_instr_addrs.find(current_block_start_address);
		if (block_symb_instrs_entry == symbolic_instr_addrs.end()) {
			symbolic_instr_addrs.emplace(current_block_start_address, block_symbolic_instr_addrs);
		}
		else {
			block_symb_instrs_entry->second.insert(block_symbolic_instr_addrs.begin(), block_symbolic_instr_addrs.end());
		}
		// Clear all block level taint status trackers and symbolic instruction list
		block_symbolic_registers.clear();
		block_concrete_registers.clear();
		block_symbolic_temps.clear();
		block_symbolic_instr_addrs.clear();
		return;
	}

	/*
	 * undo recent memory actions.
	 * block_level denotes whether we want to rollback fully to start of the block
	 */
	void rollback(bool block_level) {
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

		if (track_bbls && block_level) bbl_addrs.pop_back();
		if (track_stack && block_level) stack_pointers.pop_back();
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

	// check if we can clobberedly handle this IRExpr
	inline bool check_expr(RegisterSet *clobbered, RegisterSet *danger, IRExpr *e)
	{
		int i, expr_size;
		if (e == NULL) return true;
		switch (e->tag)
		{
			case Iex_Binder:
				break;
			case Iex_VECRET:
				break;
			case Iex_GSPTR:
				break;
			case Iex_GetI:
				// we can't handle this for the same reasons as PutI (see below)
				return false;
				break;
			case Iex_RdTmp:
				break;
			case Iex_Get:
				if (e->Iex.Get.ty == Ity_I1)
				{
					//LOG_W("seeing a 1-bit get from a register");
					return false;
				}

				expr_size = sizeofIRType(e->Iex.Get.ty);
				this->check_register_read(clobbered, danger, e->Iex.Get.offset, expr_size);
				break;
			case Iex_Qop:
				if (!this->check_expr(clobbered, danger, e->Iex.Qop.details->arg1)) return false;
				if (!this->check_expr(clobbered, danger, e->Iex.Qop.details->arg2)) return false;
				if (!this->check_expr(clobbered, danger, e->Iex.Qop.details->arg3)) return false;
				if (!this->check_expr(clobbered, danger, e->Iex.Qop.details->arg4)) return false;
				break;
			case Iex_Triop:
				if (!this->check_expr(clobbered, danger, e->Iex.Triop.details->arg1)) return false;
				if (!this->check_expr(clobbered, danger, e->Iex.Triop.details->arg2)) return false;
				if (!this->check_expr(clobbered, danger, e->Iex.Triop.details->arg3)) return false;
				break;
			case Iex_Binop:
				if (!this->check_expr(clobbered, danger, e->Iex.Binop.arg1)) return false;
				if (!this->check_expr(clobbered, danger, e->Iex.Binop.arg2)) return false;
				break;
			case Iex_Unop:
				if (!this->check_expr(clobbered, danger, e->Iex.Unop.arg)) return false;
				break;
			case Iex_Load:
				if (!this->check_expr(clobbered, danger, e->Iex.Load.addr)) return false;
				break;
			case Iex_Const:
				break;
			case Iex_ITE:
				if (!this->check_expr(clobbered, danger, e->Iex.ITE.cond)) return false;
				if (!this->check_expr(clobbered, danger, e->Iex.ITE.iffalse)) return false;
				if (!this->check_expr(clobbered, danger, e->Iex.ITE.iftrue)) return false;
				break;
			case Iex_CCall:
				for (i = 0; e->Iex.CCall.args[i] != NULL; i++)
				{
					if (!this->check_expr(clobbered, danger, e->Iex.CCall.args[i])) return false;
				}
				break;
		}

		return true;
	}

	// mark the register as clobbered
	inline void mark_register_clobbered(RegisterSet *clobbered, vex_reg_offset_t offset, int size)
	{
		for (int i = 0; i < size; i++)
			clobbered->insert(offset + i);
	}

	// check register access
	inline void check_register_read(RegisterSet *clobbered, RegisterSet *danger, vex_reg_offset_t offset, int size)
	{
		for (int i = 0; i < size; i++)
		{
			if (clobbered->count(offset + i) == 0) {
				danger->insert(offset + i);
			}
		}
	}

	// check if we can clobberedly handle this IRStmt
	inline bool check_stmt(RegisterSet *clobbered, RegisterSet *danger, IRTypeEnv *tyenv, IRStmt *s)
	{
		switch (s->tag)
		{
			case Ist_Put: {
				if (!this->check_expr(clobbered, danger, s->Ist.Put.data)) return false;
				IRType expr_type = typeOfIRExpr(tyenv, s->Ist.Put.data);
				if (expr_type == Ity_I1)
				{
					//LOG_W("seeing a 1-bit write to a register");
					return false;
				}

				int expr_size = sizeofIRType(expr_type);
				this->mark_register_clobbered(clobbered, s->Ist.Put.offset, expr_size);
				break;
			}
			case Ist_PutI:
				// we cannot handle the PutI because:
				// 1. in the case of symbolic registers, we need to have a good
				//    handle on what registers need to be synced back to angr.
				// 2. this requires us to track all the writes
				// 3. a PutI represents an indirect write into the registerfile,
				//    and we can't figure out where it's writing to ahead of time
				// 4. unicorn provides no way to hook register writes (and that'd
				//    probably be prohibitively slow anyways)
				// 5. so we're screwed
				return false;
				break;
			case Ist_WrTmp:
				if (!this->check_expr(clobbered, danger, s->Ist.WrTmp.data)) return false;
				break;
			case Ist_Store:
				if (!this->check_expr(clobbered, danger, s->Ist.Store.addr)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.Store.data)) return false;
				break;
			case Ist_CAS:
				if (!this->check_expr(clobbered, danger, s->Ist.CAS.details->addr)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.CAS.details->dataLo)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.CAS.details->dataHi)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.CAS.details->expdLo)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.CAS.details->expdHi)) return false;
				break;
			case Ist_LLSC:
				if (!this->check_expr(clobbered, danger, s->Ist.LLSC.addr)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.LLSC.storedata)) return false;
				break;
			case Ist_Dirty: {
				if (!this->check_expr(clobbered, danger, s->Ist.Dirty.details->guard)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.Dirty.details->mAddr)) return false;
				for (int i = 0; s->Ist.Dirty.details->args[i] != NULL; i++)
				{
					if (!this->check_expr(clobbered, danger, s->Ist.Dirty.details->args[i])) return false;
				}
				break;
							}
			case Ist_Exit:
				if (!this->check_expr(clobbered, danger, s->Ist.Exit.guard)) return false;
				break;
			case Ist_LoadG:
				if (!this->check_expr(clobbered, danger, s->Ist.LoadG.details->addr)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.LoadG.details->alt)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.LoadG.details->guard)) return false;
				break;
			case Ist_StoreG:
				if (!this->check_expr(clobbered, danger, s->Ist.StoreG.details->addr)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.StoreG.details->data)) return false;
				if (!this->check_expr(clobbered, danger, s->Ist.StoreG.details->guard)) return false;
				break;
			case Ist_NoOp:
			case Ist_IMark:
			case Ist_AbiHint:
			case Ist_MBE:
				// no-ops for our purposes
				break;
			default:
				//LOG_W("Encountered unknown VEX statement -- can't determine clobberedty.")
				return false;
		}

		return true;
	}

	// check if the block is feasible
	bool check_block(address_t address, int32_t size)
	{
		// assume we're good if we're not checking symbolic registers
		if (this->vex_guest == VexArch_INVALID) {
			return true;
		}

		// if there are no symbolic registers we're ok
		if (this->symbolic_registers.size() == 0) {
			return true;
		}

		// check if it's in the cache already
		RegisterSet *clobbered_registers;
		RegisterSet *used_registers;
		auto search = this->block_cache->find(address);
		if (search != this->block_cache->end()) {
			if (!search->second.try_unicorn) {
				return false;
			}
			clobbered_registers = &search->second.clobbered_registers;
			used_registers = &search->second.used_registers;
		} else {
			// wtf i hate c++...
			VexRegisterUpdates pxControl = VexRegUpdUnwindregsAtMemAccess;
			auto& entry = this->block_cache->emplace(std::make_pair(address, block_entry_t())).first->second;
			entry.try_unicorn = true;
			clobbered_registers = &entry.clobbered_registers;
			used_registers = &entry.used_registers;

			std::unique_ptr<uint8_t[]> instructions(new uint8_t[size]);
			uc_mem_read(this->uc, address, instructions.get(), size);
			VEXLiftResult *lift_ret = vex_lift(
					this->vex_guest, this->vex_archinfo, instructions.get(), address, 99, size, 1, 0, 0, 1, 0,
					pxControl
					);


			if (lift_ret == NULL) {
				// TODO: how to handle?
				return false;
			}

			IRSB *the_block = lift_ret->irsb;

			for (int i = 0; i < the_block->stmts_used; i++) {
				if (!this->check_stmt(clobbered_registers, used_registers, the_block->tyenv, the_block->stmts[i])) {
					entry.try_unicorn = false;
					return false;
				}
			}

			if (!this->check_expr(clobbered_registers, used_registers, the_block->next)) {
				entry.try_unicorn = false;
				return false;
			}
		}

		for (vex_reg_offset_t off : this->symbolic_registers) {
			if (used_registers->count(off) > 0) {
				stopping_register = off;
				return false;
			}
		}

		for (vex_reg_offset_t off : *clobbered_registers) {
			this->symbolic_registers.erase(off);
		}

		return true;
	}

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

	void handle_write(address_t address, int size) {
	    // If the write spans a page, chop it up
	    if ((address & 0xfff) + size > 0x1000) {
	        int chopsize = 0x1000 - (address & 0xfff);
	        handle_write(address, chopsize);
	        handle_write(address + chopsize, size - chopsize);
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
		bool is_dst_symbolic;

		if (!bitmap) {
		    // We should never have a missing bitmap because we explicitly called the callback!
		    printf("This should never happen, right? %#" PRIx64 "\n", address);
		    abort();
		}

        clean = 0;
		is_dst_symbolic = mem_writes_taint_map.at(get_instruction_pointer());
		if (is_dst_symbolic) {
			save_dependencies(get_instruction_pointer());
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
			if ((taint_source.entity_type == TAINT_ENTITY_REG) && !is_artificial_register(taint_source.reg_offset)) {
				reg_dependency_list.emplace(taint_source);
			}
			else if (taint_source.entity_type == TAINT_ENTITY_MEM) {
				has_memory_read = true;
			}
		}
		return std::make_pair(reg_dependency_list, has_memory_read);
	}

	block_taint_entry_t compute_taint_sink_source_relation_of_block(IRSB *vex_block, address_t address) {
		block_taint_entry_t block_taint_entry;
		instruction_taint_entry_t instruction_taint_entry;

		instruction_taint_entry.reset();
		for (int i = 0; i < vex_block->stmts_used; i++) {
			address_t curr_instr_addr;
			auto stmt = vex_block->stmts[i];
			switch (stmt->tag) {
				case Ist_Put:
				{
					taint_entity_t sink;
					std::unordered_set<taint_entity_t> srcs, ite_cond_entity_list;

					sink.entity_type = TAINT_ENTITY_REG;
					sink.instr_addr = curr_instr_addr;
					sink.reg_offset = stmt->Ist.Put.offset;
					auto result = get_taint_sources_and_ite_cond(stmt->Ist.Put.data, false);
					srcs = result.first;
					ite_cond_entity_list = result.second;
					if (srcs.size() > 0) {
						instruction_taint_entry.taint_sink_src_map.emplace_back(sink, srcs);
						// TODO: Should we not compute dependencies to save if sink is an artificial register?
						auto dependencies_to_save = compute_dependencies_to_save(srcs);
						instruction_taint_entry.has_memory_read = dependencies_to_save.second;
						instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					}
					if (ite_cond_entity_list.size() > 0) {
						instruction_taint_entry.ite_cond_entity_list.insert(ite_cond_entity_list.begin(), ite_cond_entity_list.end());
						auto dependencies_to_save = compute_dependencies_to_save(ite_cond_entity_list);
						instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
						instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					}
					break;
				}
				case Ist_WrTmp:
				{
					taint_entity_t sink;
					std::unordered_set<taint_entity_t> srcs, ite_cond_entity_list;

					sink.entity_type = TAINT_ENTITY_TMP;
					sink.instr_addr = curr_instr_addr;
					sink.tmp_id = stmt->Ist.WrTmp.tmp;
					auto result = get_taint_sources_and_ite_cond(stmt->Ist.WrTmp.data, false);
					srcs = result.first;
					ite_cond_entity_list = result.second;
					if (srcs.size() > 0) {
						instruction_taint_entry.taint_sink_src_map.emplace_back(sink, srcs);
						auto dependencies_to_save = compute_dependencies_to_save(srcs);
						instruction_taint_entry.has_memory_read = dependencies_to_save.second;
						instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					}
					if (ite_cond_entity_list.size() > 0) {
						instruction_taint_entry.ite_cond_entity_list.insert(ite_cond_entity_list.begin(), ite_cond_entity_list.end());
						auto dependencies_to_save = compute_dependencies_to_save(ite_cond_entity_list);
						instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
						instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					}
					break;
				}
				case Ist_Store:
				{
					taint_entity_t sink;
					std::unordered_set<taint_entity_t> srcs, ite_cond_entity_list;

					sink.entity_type = TAINT_ENTITY_MEM;
					sink.instr_addr = curr_instr_addr;
					auto result = get_taint_sources_and_ite_cond(stmt->Ist.Store.addr, false);
					// TODO: What if memory addresses have ITE expressions in them?
					sink.mem_ref_entity_list.assign(result.first.begin(), result.first.end());
					result = get_taint_sources_and_ite_cond(stmt->Ist.Store.data, false);
					srcs = result.first;
					ite_cond_entity_list = result.second;
					instruction_taint_entry.has_memory_write = true;
					if (srcs.size() > 0) {
						instruction_taint_entry.taint_sink_src_map.emplace_back(sink, srcs);
						auto dependencies_to_save = compute_dependencies_to_save(srcs);
						instruction_taint_entry.has_memory_read = dependencies_to_save.second;
						instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					}
					if (ite_cond_entity_list.size() > 0) {
						instruction_taint_entry.ite_cond_entity_list.insert(ite_cond_entity_list.begin(), ite_cond_entity_list.end());
						auto dependencies_to_save = compute_dependencies_to_save(ite_cond_entity_list);
						instruction_taint_entry.has_memory_read |= dependencies_to_save.second;
						instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					}
					break;
				}
				case Ist_Exit:
				{
					auto result = get_taint_sources_and_ite_cond(stmt->Ist.Exit.guard, true);
					block_taint_entry.exit_stmt_guard_expr_deps = result.first;
					if (block_taint_entry.exit_stmt_guard_expr_deps.size() > 0) {
						auto dependencies_to_save = compute_dependencies_to_save(block_taint_entry.exit_stmt_guard_expr_deps);
						instruction_taint_entry.has_memory_read = dependencies_to_save.second;
						taint_entity_t dummy_sink;
						dummy_sink.entity_type = TAINT_ENTITY_NONE;
						dummy_sink.instr_addr = curr_instr_addr;
						instruction_taint_entry.dependencies_to_save.insert(dependencies_to_save.first.begin(), dependencies_to_save.first.end());
					}
					break;
				}
				case Ist_IMark:
				{
					// Save dependencies of previous instruction, if any, and clear it
					if (instruction_taint_entry.taint_sink_src_map.size() > 0) {
						block_taint_entry.block_instrs_taint_data_map.emplace(curr_instr_addr, instruction_taint_entry);
					}
					instruction_taint_entry.reset();
					curr_instr_addr = stmt->Ist.IMark.addr;
					break;
				}
				case Ist_PutI:
				{
					assert(false && "[sim_unicorn] PutI statements not yet supported!");
				}
				case Ist_StoreG:
				{
					assert(false && "[sim_unicorn] StoreG statements not yet supported!");
				}
				case Ist_LoadG:
				{
					assert(false && "[sim_unicorn] LoadG statements not yet supported!");
				}
				case Ist_CAS:
				{
					assert(false && "[sim_unicorn] CAS statements not yet supported!");
				}
				case Ist_LLSC:
				{
					assert(false && "[sim_unicorn] LLSC statements not yet supported!");
				}
				case Ist_Dirty:
				{
					assert(false && "[sim_unicorn] Dirty statements not yet supported!");
				}
				case Ist_MBE:
				case Ist_NoOp:
				case Ist_AbiHint:
					break;
				default:
				{
					fprintf(stderr, "[sim_unicorn] Unsupported statement type encountered: ");
					fprintf(stderr, "Block: 0x%zx, statement index: %d, statement type: %u\n", address, i, stmt->tag);
					assert(false && "[sim_unicorn] Unsupported statement type encountered! See output for more info.");
				}
			}
		}
		return block_taint_entry;
	}

	inline uint64_t get_register_value(uint64_t vex_reg_offset) const {
		uint64_t reg_value;
		try {
			uc_reg_read(uc, vex_to_unicorn_map.at(vex_reg_offset), &reg_value);
			return reg_value;
		}
		catch (std::out_of_range) {
			fprintf(stderr, "Cannot retrieve value of unrecognized register %lu", vex_reg_offset);
			assert(false && "[sim_unicorn] Unrecognized register in get_register_value.");
		}
	}

	// Returns a pair (taint sources, list of taint entities in ITE condition expression)
	std::pair<std::unordered_set<taint_entity_t>, std::unordered_set<taint_entity_t>> get_taint_sources_and_ite_cond(
	  IRExpr *expr, bool is_exit_stmt) {
		std::unordered_set<taint_entity_t> sources, ite_cond_entities;
		switch (expr->tag) {
			case Iex_RdTmp:
			{
				taint_entity_t taint_entity;
				taint_entity.entity_type = TAINT_ENTITY_TMP;
				taint_entity.tmp_id = expr->Iex.RdTmp.tmp;
				sources.emplace(taint_entity);
				break;
			}
			case Iex_Get:
			{
				taint_entity_t taint_entity;
				taint_entity.entity_type = TAINT_ENTITY_REG;
				taint_entity.reg_offset = expr->Iex.Get.offset;
				sources.emplace(taint_entity);
				break;
			}
			case Iex_Unop:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Unop.arg, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				break;
			}
			case Iex_Binop:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Binop.arg1, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				temp = get_taint_sources_and_ite_cond(expr->Iex.Binop.arg2, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				break;
			}
			case Iex_Triop:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Triop.details->arg1, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				temp = get_taint_sources_and_ite_cond(expr->Iex.Triop.details->arg2, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				temp = get_taint_sources_and_ite_cond(expr->Iex.Triop.details->arg3, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				break;
			}
			case Iex_Qop:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Qop.details->arg1, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				temp = get_taint_sources_and_ite_cond(expr->Iex.Qop.details->arg2, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				temp = get_taint_sources_and_ite_cond(expr->Iex.Qop.details->arg3, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				temp = get_taint_sources_and_ite_cond(expr->Iex.Qop.details->arg4, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				break;
			}
			case Iex_ITE:
			{
				// We store the taint entities in the condition for ITE separately in order to check
				// if condition is symbolic and stop concrete execution if it is. However for VEX
				// exit statement, we don't need to store it separately since we process only the
				// guard condition for Exit statements
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.ITE.cond, false);
				if (is_exit_stmt) {
					sources.insert(temp.first.begin(), temp.first.end());
					sources.insert(temp.second.begin(), temp.second.end());
				}
				else {
					ite_cond_entities.insert(temp.first.begin(), temp.first.end());
					ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				}
				temp = get_taint_sources_and_ite_cond(expr->Iex.ITE.iffalse, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				temp = get_taint_sources_and_ite_cond(expr->Iex.ITE.iftrue, false);
				sources.insert(temp.first.begin(), temp.first.end());
				ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				break;
			}
			case Iex_CCall:
			{
				IRExpr **ccall_args = expr->Iex.CCall.args;
				for (uint64_t i = 0; ccall_args[i]; i++) {
					auto temp = get_taint_sources_and_ite_cond(ccall_args[i], false);
					sources.insert(temp.first.begin(), temp.first.end());
					ite_cond_entities.insert(temp.second.begin(), temp.second.end());
				}
				break;
			}
			case Iex_Load:
			{
				auto temp = get_taint_sources_and_ite_cond(expr->Iex.Load.addr, false);
				// TODO: What if memory addresses have ITE expressions in them?
				taint_entity_t source;
				source.entity_type = TAINT_ENTITY_MEM;
				source.mem_ref_entity_list.assign(temp.first.begin(), temp.first.end());
				sources.emplace(source);
				break;
			}
			case Iex_GetI:
			{
				// TODO
				assert(false && "[sim_unicorn] GetI expression not yet supported!");
			}
			case Iex_Const:
			case Iex_VECRET:
			case Iex_GSPTR:
			case Iex_Binder:
				break;
			default:
			{
				fprintf(stderr, "[sim_unicorn] Unsupported expression type encountered: %u\n", expr->tag);
				assert(false && "[sim_unicorn] Unsupported expression type encountered! See output for more info.");
			}
		}
		return std::make_pair(sources, ite_cond_entities);
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
		if (do_block_level) {
			// Mark register as symbolic in current block
			block_symbolic_registers.emplace(reg_offset);
		}
		else {
			// Mark register as symbolic in the state
			symbolic_registers.emplace(reg_offset);
		}
		return;
	}

	inline void mark_temp_symbolic(vex_tmp_id_t temp_id, bool do_block_level) {
		if (do_block_level) {
			// Mark VEX temp as symbolic in current block
			block_symbolic_temps.emplace(temp_id);
		}
		else {
			// Mark VEX temp as symbolic in the state
			symbolic_temps.emplace(temp_id);
		}
	}

	void mark_register_temp_symbolic(const taint_entity_t &entity, bool do_block_level) {
		if (entity.entity_type == TAINT_ENTITY_REG) {
			mark_register_symbolic(entity.reg_offset, do_block_level);
		}
		else if (entity.entity_type == TAINT_ENTITY_TMP) {
			mark_temp_symbolic(entity.tmp_id, do_block_level);
		}
		return;
	}

	inline void mark_register_concrete(vex_reg_offset_t reg_offset, bool do_block_level) {
		if (do_block_level) {
			// Mark this register as concrete in the current block
			block_concrete_registers.emplace(reg_offset);
		}
		else {
			symbolic_registers.erase(reg_offset);
		}
		return;
	}

	inline bool is_artificial_register(vex_reg_offset_t reg_offset) const {
		return artificial_vex_registers.count(reg_offset) > 0;
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
		// Check both the state's symbolic temp set and block's symbolic temp set
		return ((symbolic_temps.count(temp_id) > 0) || (block_symbolic_temps.count(temp_id) > 0));
	}

	inline bool is_symbolic_register_or_temp(const taint_entity_t &entity) const {
		if (entity.entity_type == TAINT_ENTITY_REG) {
			return is_symbolic_register(entity.reg_offset);
		}
		return is_symbolic_temp(entity.tmp_id);
	}

	void propagate_taints() {
		block_taint_entry_t block_taint_entry = this->block_taint_cache.at(current_block_start_address);
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
				taint_engine_next_instr_address = std::next(instr_taint_data_entries_it)->first;
				return;
			}
			if (is_symbolic_tracking_disabled()) {
				// We're not checking symbolic registers so no need to propagate taints
				continue;
			}
			if ((symbolic_registers.size() == 0) && (block_symbolic_registers.size() == 0)) {
				// There are no symbolic registers so no taint to propagate.
				continue;
			}
			propagate_taint_of_one_instr(curr_instr_taint_entry);
		}
		if (instr_taint_data_entries_it != instr_taint_data_stop_it) {
			// We reached here because we hit some stop state. Set next instruction address as
			// current instruction. VEX land will likely need this info.
			taint_engine_next_instr_address = instr_taint_data_entries_it->first;
		}
		return;
	}

	void propagate_taint_of_one_instr(const address_t instr_addr) {
		auto block_taint_entry = block_taint_cache.at(current_block_start_address);
		auto instr_taint_data_entry = block_taint_entry.block_instrs_taint_data_map.at(instr_addr);
		propagate_taint_of_one_instr(instr_taint_data_entry);
		return;
	}

	void propagate_taint_of_one_instr(const instruction_taint_entry_t &curr_instr_taint_entry) {
		for (auto &taint_data_entry: curr_instr_taint_entry.taint_sink_src_map) {
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
				else if (mem_writes_taint_map.find(taint_sink.instr_addr) != mem_writes_taint_map.end()) {
					assert(false && "[sim_unicorn] Multiple memory writes in same instruction not supported.");
				}
				else if (sink_taint_status == TAINT_STATUS_SYMBOLIC) {
					// Save the memory location written to be marked as symbolic in write hook
					mem_writes_taint_map.emplace(taint_sink.instr_addr, true);
					// Add instruction to list of instructions to be executed symbolically
					block_symbolic_instr_addrs.emplace(taint_sink.instr_addr);

					// Compute dependencies to save
					std::unordered_set<taint_entity_t> deps_to_save;
					for (auto &dependency: curr_instr_taint_entry.dependencies_to_save) {
						if ((dependency.entity_type == TAINT_ENTITY_REG) && (!is_symbolic_register(dependency.reg_offset))) {
							deps_to_save.emplace(dependency);
						}
					}
					auto instr_dep_save_entry = symbolic_instrs_dep_save_map.find(taint_sink.instr_addr);
					if (instr_dep_save_entry == symbolic_instrs_dep_save_map.end()) {
						symbolic_instrs_dep_save_map.emplace(taint_sink.instr_addr, deps_to_save);
					}
					else {
						instr_dep_save_entry->second.insert(deps_to_save.begin(), deps_to_save.end());
					}
				}
				else {
					// Save the memory location written to be marked as concrete in the write hook
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
					if ((taint_sink.entity_type == TAINT_ENTITY_REG) && (taint_sink.reg_offset == arch_pc_reg())) {
						stop(STOP_SYMBOLIC_PC);
						return;
					}
					mark_register_temp_symbolic(taint_sink, true);
					// Add instruction to list of instructions to be executed symbolically
					block_symbolic_instr_addrs.emplace(taint_sink.instr_addr);

					// Compute dependencies to save
					std::unordered_set<taint_entity_t> deps_to_save;
					for (auto &dependency: curr_instr_taint_entry.dependencies_to_save) {
						if ((dependency.entity_type == TAINT_ENTITY_REG) && (!is_symbolic_register(dependency.reg_offset))) {
							deps_to_save.emplace(dependency);
						}
					}
					auto instr_dep_save_entry = symbolic_instrs_dep_save_map.find(taint_sink.instr_addr);
					if (instr_dep_save_entry == symbolic_instrs_dep_save_map.end()) {
						symbolic_instrs_dep_save_map.emplace(taint_sink.instr_addr, deps_to_save);
						// If there is no memory read/write, add a hook to save dependencies
						if (!curr_instr_taint_entry.has_memory_read && !curr_instr_taint_entry.has_memory_write) {
							uc_hook hook;
							uc_hook_add(uc, &hook, UC_HOOK_CODE, (void *)hook_save_dependencies, (void *)this, taint_sink.instr_addr, taint_sink.instr_addr);
							symbolic_instrs_dep_saving_hooks.emplace(hook);
						}
					}
					else {
						instr_dep_save_entry->second.insert(deps_to_save.begin(), deps_to_save.end());
					}
				}
				else if (taint_sink.entity_type == TAINT_ENTITY_REG) {
					// Mark register as not symbolic since none of it's dependencies are symbolic
					mark_register_concrete(taint_sink.reg_offset, true);
				}
			}
			auto ite_cond_taint_status = get_final_taint_status(curr_instr_taint_entry.ite_cond_entity_list);
			if (ite_cond_taint_status != TAINT_STATUS_CONCRETE) {
				stop(STOP_SYMBOLIC_CONDITION);
				return;
			}
		}
		return;
	}

	inline void read_memory_value(address_t address, uint64_t size, uint8_t *result, size_t result_size) const {
		memset(result, 0, result_size);
		uc_mem_read(uc, address, result, size);
		return;
	}

	void start_propagating_taint(address_t block_address, int32_t block_size) {
		if (this->block_taint_cache.find(block_address) == this->block_taint_cache.end()) {
			// Compute and cache taint sink-source relations for this block
			VexRegisterUpdates pxControl = VexRegUpdUnwindregsAtMemAccess;
			std::unique_ptr<uint8_t[]> instructions(new uint8_t[block_size]);
			uc_mem_read(this->uc, block_address, instructions.get(), block_size);
			VEXLiftResult *lift_ret = vex_lift(
				this->vex_guest, this->vex_archinfo, instructions.get(), block_address, 99, block_size, 1, 0, 1,
				1, 0, pxControl
			);

			if (lift_ret == NULL) {
				// Failed to lift block to VEX. Stop concrete execution
				stop(STOP_VEX_LIFT_FAILED);
				return;
			}
			auto block_taint_entry = compute_taint_sink_source_relation_of_block(lift_ret->irsb, block_address);
			// Add entry to taint relations cache
			block_taint_cache.emplace(block_address, block_taint_entry);
		}
		current_block_start_address = block_address;
		current_block_size = block_size;
		taint_engine_next_instr_address = block_address;
		propagate_taints();
		return;
	}

	void continue_propagating_taint() {
		propagate_taints();
		return;
	}

	void save_dependencies(address_t instr_addr) {
		auto list_of_dependencies_to_save = symbolic_instrs_dep_save_map.find(instr_addr);
		if (list_of_dependencies_to_save != symbolic_instrs_dep_save_map.end()) {
			for (auto &dependency_to_save: list_of_dependencies_to_save->second) {
				saved_concrete_dependency_t reg_dep;
				reg_dep.dependency_type = TAINT_ENTITY_REG;
				reg_dep.reg_offset = dependency_to_save.reg_offset;
				reg_dep.reg_value = get_register_value(dependency_to_save.reg_offset);
				auto saved_dep_entry = saved_dependencies_map.find(instr_addr);
				if (saved_dep_entry == saved_dependencies_map.end()) {
					std::vector<saved_concrete_dependency_t> temp;
					temp.emplace_back(reg_dep);
					saved_dependencies_map.emplace(instr_addr, temp);
				}
				else {
					saved_dep_entry->second.emplace_back(reg_dep);
				}
			}
		}
		auto mem_read_result = mem_reads_map.find(instr_addr);
		if (mem_read_result != mem_reads_map.end()) {
			if (!mem_read_result->second.is_value_symbolic) {
				saved_concrete_dependency_t mem_dep;
				mem_dep.dependency_type = TAINT_ENTITY_MEM;
				mem_dep.mem_address = mem_read_result->second.address;
				mem_dep.mem_value_size = mem_read_result->second.size;
				for (int i = 0; i < MAX_MEM_ACCESS_SIZE; i++) {
					mem_dep.mem_value[i] = mem_read_result->second.value[i];
				}
				auto saved_dep_entry = saved_dependencies_map.find(instr_addr);
				if (saved_dep_entry == saved_dependencies_map.end()) {
					std::vector<saved_concrete_dependency_t> temp;
					temp.emplace_back(mem_dep);
					saved_dependencies_map.emplace(instr_addr, temp);
				}
				else {
					saved_dep_entry->second.emplace_back(mem_dep);
				}
			}
		}
		return;
	}

	void clear_dependency_saving_hooks() {
		for (auto &hook: symbolic_instrs_dep_saving_hooks) {
			uc_hook_del(uc, hook);
		}
		symbolic_instrs_dep_saving_hooks.clear();
		return;
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

	bool is_symbolic_exit_guard_previous_block() {
		// Technically we have started next block but we haven't updated the address of block being
		// executed and so current_block_start_address still works
		if (current_block_start_address == 0) {
			// We haven't started concrete execution yet
			return false;
		}
		block_taint_entry_t prev_block_taint_entry = block_taint_cache.at(current_block_start_address);
		auto prev_block_exit_guard_taint_status = get_final_taint_status(prev_block_taint_entry.exit_stmt_guard_expr_deps);
		// Since this checks the exit condition of the previous block, that means the previous block
		// was executed correctly: there was no memory read from a symbolic address. Hence, it is
		// sufficient to check if the guard status is symbolic.
		// (This is also why commit can be invoked before this: we need to check regs and temps)
		if (prev_block_exit_guard_taint_status == TAINT_STATUS_SYMBOLIC) {
			return true;
		}
		return false;
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

	void set_instruction_pointer(address_t val) {
		unsigned int reg = arch_pc_reg();
		if (reg != -1) {
			uc_reg_write(uc, reg, &val);
		}
	}

	void set_stack_pointer(address_t val) {
		unsigned int reg = arch_sp_reg();
		if (reg != -1) {
			uc_reg_write(uc, reg, &val);
		}
	}

	uint64_t get_count_of_blocks_with_symbolic_instrs() const {
		return symbolic_instr_addrs.size();
	}

	uint64_t get_count_of_symbolic_instrs_in_block(address_t block_address) const {
		return symbolic_instr_addrs.at(block_address).size();
	}

	std::unordered_set<address_t> get_blocks_with_symbolic_instrs() const {
		std::unordered_set<address_t> block_list;
		for (auto &block: symbolic_instr_addrs) {
			block_list.emplace(block.first);
		}
		return block_list;
	}

	std::unordered_set<address_t> get_symbolic_instrs_in_block(address_t block_address) const {
		std::unordered_set<address_t> instr_list;
		for (auto &instr: symbolic_instr_addrs.at(block_address)) {
			instr_list.emplace(instr);
		}
		return instr_list;
	}

	uint64_t get_count_of_dependencies_of_instr(address_t instr_addr) const {
		return saved_dependencies_map.at(instr_addr).size();
	}

	std::vector<saved_concrete_dependency_t> get_dependencies_of_instr(address_t instr_addr) const {
		return saved_dependencies_map.at(instr_addr);
	}
};

static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	// uc_mem_read(uc, address, &value, size);
	// //LOG_D("mem_read [%#lx, %#lx] = %#lx", address, address + size);
	//LOG_D("mem_read [%#lx, %#lx]", address, address + size);
	State *state = (State *)user_data;
	mem_read_result_t mem_read_result;

	// Commit the current execution state and create save point
	state->commit(false);
	mem_read_result.address = address;
	mem_read_result.size = size;
	auto tainted = state->find_tainted(address, size);
	if (tainted != -1)
	{
		mem_read_result.is_value_symbolic = true;
		if (!state->is_symbolic_tracking_disabled()) {
			// Symbolic register tracking is disabled but memory location has symbolic data.
			// We switch to VEX engine then.
			stop(STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED);
		}
	}
	else
	{
		mem_read_result.is_value_symbolic = false;
		state->read_memory_value(address, size, mem_read_result.value, MAX_MEM_ACCESS_SIZE);
	}
	if (!state->stopped) {
		state->mem_reads_map.emplace(state->get_instruction_pointer(), mem_read_result);
		state->propagate_taint_of_one_instr(state->get_instruction_pointer());
		state->save_dependencies(state->get_instruction_pointer());
	}
	if (!state->stopped) {
		state->continue_propagating_taint();
	}
	if (state->stopped) {
		// Since we've already executed part of the block, we rollback to the nearest save point.
		state->rollback(false);
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

	state->handle_write(address, size);
}

static void hook_block(uc_engine *uc, uint64_t address, int32_t size, void *user_data) {
	//LOG_I("block [%#lx, %#lx]", address, address + size);

	State *state = (State *)user_data;
	if (state->ignore_next_block) {
		state->ignore_next_block = false;
		state->ignore_next_selfmod = true;
		return;
	}
	state->commit(true);
	// This call below also handles case when the first block is executed and there is no previous
	// block
	if (state->is_symbolic_exit_guard_previous_block()) {
		// TODO: Save exit statement instruction address as to be executed symbolically
		stop(STOP_SYMBOLIC_CONDITION);
		return;
	}
	state->clear_dependency_saving_hooks();
	state->step(address, size);

	if (!state->stopped) {
		state->start_propagating_taint(address, size);
	}
	if (state->stopped) {
		// Since we're only starting the block, we rollback to state at start of the block
		state->rollback(true);
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
				state->commit(true);
				if (state->stopped)
				{
					//printf("... stopped after step()\n");
					free(dup_buf);
					return;
				}

				uc_err err = uc_mem_write(uc, tx_bytes, &count, 4);
				if (tx_bytes != 0) state->handle_write(tx_bytes, 4);
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

static void hook_save_dependencies(uc_engine *uc, address_t address, uint32_t size, void *user_data) {
	State *state = (State *)user_data;
	state->save_dependencies(address);
	return;
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
uint64_t simunicorn_stopping_register(State *state) {
	return state->stopping_register;
}

extern "C"
uint64_t simunicorn_stopping_memory(State *state) {
	return state->stopping_memory;
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

// VEX register offsets to unicorn register ID mappings
extern "C"
void simunicorn_set_vex_to_unicorn_reg_mappings(State *state, uint64_t *vex_offsets, uint64_t *unicorn_ids, uint64_t count) {
	state->vex_to_unicorn_map.clear();
	for (int i = 0; i < count; i++) {
		state->vex_to_unicorn_map.emplace(vex_offsets[i], unicorn_ids[i]);
	}
	return;
}

// VEX re-execution data

extern "C"
uint64_t simunicorn_get_count_of_blocks_with_symbolic_instrs(State *state) {
	return state->get_count_of_blocks_with_symbolic_instrs();
}

extern "C"
void simunicorn_get_blocks_with_symbolic_instrs(State *state, uint64_t *block_addrs) {
	auto block_addrs_list = state->get_blocks_with_symbolic_instrs();
	std::copy(block_addrs_list.begin(), block_addrs_list.end(), block_addrs);
	return;
}

extern "C"
uint64_t simunicorn_get_count_of_symbolic_instrs_in_block(State *state, uint64_t block_address) {
	return state->get_count_of_symbolic_instrs_in_block(block_address);
}

extern "C"
void simunicorn_get_symbolic_instrs_in_block(State *state, uint64_t block_address, uint64_t *instr_addrs) {
	auto instrs_list = state->get_symbolic_instrs_in_block(block_address);
	std::copy(instrs_list.begin(), instrs_list.end(), instr_addrs);
	return;
}

extern "C"
uint64_t simunicorn_get_count_of_dependencies_of_instr(State *state, uint64_t instr_addr) {
	return state->get_count_of_dependencies_of_instr(instr_addr);
}

extern "C"
void simunicorn_get_dependencies_of_instr(State *state, uint64_t instr_addr, saved_concrete_dependency_t *deps) {
	auto deps_list = state->get_dependencies_of_instr(instr_addr);
	std::copy(deps_list.begin(), deps_list.end(), deps);
	return;
}
