#include <unicorn/unicorn.h>

#include <cstring>
#include <cstdint>
#include <cinttypes>

#include <memory>
#include <map>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <set>

extern "C" {
#include <libvex.h>
#include <pyvex.h>
}

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12

#define MAX_REG_SIZE 0x2000 // hope it's big enough

// Maximum size of a qemu/unicorn basic block
// See State::step for why this is necessary
static const uint32_t MAX_BB_SIZE = 800;

extern "C" void x86_reg_update(uc_engine *uc, uint8_t *buf, int save);
extern "C" void mips_reg_update(uc_engine *uc, uint8_t *buf, int save);

typedef enum taint: uint8_t {
	TAINT_NONE = 0,
	TAINT_DIRTY = 1,
	TAINT_SYMBOLIC = 2,
} taint_t;

typedef enum stop {
	STOP_NORMAL=0,
	STOP_STOPPOINT,
	STOP_SYMBOLIC_MEM,
	STOP_SYMBOLIC_REG,
	STOP_ERROR,
	STOP_SYSCALL,
	STOP_EXECNONE,
	STOP_ZEROPAGE,
	STOP_NOSTART,
	STOP_SEGFAULT,
	STOP_ZERO_DIV,
	STOP_NODECODE,
} stop_t;

typedef struct block_entry {
  bool try_unicorn;
  std::unordered_set<uint64_t> used_registers;
  std::unordered_set<uint64_t> clobbered_registers;
} block_entry_t;

typedef struct CachedPage {
	size_t size;
	uint8_t *bytes;
	uint64_t perms;
} CachedPage;

typedef taint_t PageBitmap[PAGE_SIZE];
typedef std::map<uint64_t, CachedPage> PageCache;
typedef std::unordered_map<uint64_t, block_entry_t> BlockCache;
typedef struct caches {
  PageCache *page_cache;
  BlockCache *block_cache;
} caches_t;
std::map<uint64_t, caches_t> global_cache;

typedef std::unordered_set<uint64_t> RegisterSet;

typedef struct mem_access {
	uint64_t address;
	uint8_t value[8]; // assume size of any memory write is no more than 8
	int size;
	int clean; // save current page bitmap
} mem_access_t; // actually it should be `mem_write_t` :)

typedef struct mem_update {
	uint64_t address, length;
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
	BlockCache *block_cache;
	bool hooked;

	uc_context *saved_regs;

	std::vector<mem_access_t> mem_writes;
	std::map<uint64_t, taint_t *> active_pages;
	std::set<uint64_t> stop_points;

public:
	std::vector<uint64_t> bbl_addrs;
	std::vector<uint64_t> stack_pointers;
	std::unordered_set<uint64_t> executed_pages;
	std::unordered_set<uint64_t>::iterator *executed_pages_iterator;
	uint64_t syscall_count;
	std::vector<transmit_record_t> transmit_records;
	uint64_t cur_steps, max_steps;
	uc_hook h_read, h_write, h_block, h_prot, h_unmap, h_intr;
	bool stopped;
	stop_t stop_reason;
	uint64_t stopping_register;
	uint64_t stopping_memory;

	bool ignore_next_block;
	bool ignore_next_selfmod;
	uint64_t cur_address;
	int32_t cur_size;

	uc_arch arch;
	uc_mode mode;
	bool interrupt_handled;
	uint32_t transmit_sysno;
	uint32_t transmit_bbl_addr;

	VexArch vex_guest;
	VexArchInfo vex_archinfo;
	RegisterSet symbolic_registers; // tracking of symbolic registers

	bool track_bbls;
	bool track_stack;

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
			// only poor guys consider about memory leak :(
			//LOG_D("delete active page %#lx", it->first);
			// delete should use the bracket operator since PageBitmap is an array typedef
			delete[] it->second;
		}
		active_pages.clear();
		uc_free(saved_regs);
	}

	uc_err start(uint64_t pc, uint64_t step = 1) {
		stopped = false;
		stop_reason = STOP_NOSTART;
		max_steps = step;
		cur_steps = -1;
		executed_pages.clear();

		// error if pc is 0
		if (pc == 0) {
		  stop_reason = STOP_ZEROPAGE;
		  return UC_ERR_MAP;
		}

		uc_err out = uc_emu_start(uc, pc, 0, 0, 0);
		rollback();

		if (out == UC_ERR_INSN_INVALID) {
			stop_reason = STOP_NODECODE;
		}
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
			case STOP_SYMBOLIC_MEM:
				msg = "read symbolic data";
				break;
			case STOP_SYMBOLIC_REG:
				msg = "going to try to read symbolic reg";
				break;
			case STOP_ERROR:
				msg = "something wrong";
				break;
			case STOP_SYSCALL:
				msg = "unable to handle syscall";
				commit();
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
			default:
				msg = "unknown error";
		}
		stop_reason = reason;
		//LOG_D("stop: %s", msg);
		uc_emu_stop(uc);

		// if we errored out right away, fix the step count to 0
		if (cur_steps == -1) cur_steps = 0;
	}

	void step(uint64_t current_address, int32_t size, bool check_stop_points=true) {
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
	 * record current memory write
	 */
	bool log_write(uint64_t address, int size, int clean) {
		mem_access_t record;

		record.address = address;
		record.size = size;
		record.clean = clean;
		if (clean == -1) {
			// all bytes are clean before this write, so the value
			// is not important
			memset(record.value, 0, sizeof(record.value));
		} else {
			uc_err err = uc_mem_read(uc, address, record.value, size);
			if (err) {
				//LOG_E("log_write: %s", uc_strerror(err));
				stop(STOP_ERROR);
				return false;
			}
		}

		mem_writes.push_back(record);
		return true;
	}

	/*
	 * commit all memory actions.
	 */
	void commit() {
		// save registers
		uc_context_save(uc, saved_regs);

		// mark memory sync status
		// we might miss some dirty bits, this happens if hitting the memory
		// write before mapping
		for (auto it = mem_writes.begin(); it != mem_writes.end(); it++) {
			if (it->clean == -1) {
				taint_t *bitmap = page_lookup(it->address);
				memset(&bitmap[it->address & 0xFFFULL], TAINT_DIRTY, sizeof(taint_t) * it->size);
				it->clean = (1 << it->size) - 1;
				//LOG_D("commit: lazy initialize mem_write [%#lx, %#lx]", it->address, it->address + it->size);
			}
		}

		// clear memory rollback status
		mem_writes.clear();
		cur_steps++;
	}

	/*
	 * undo recent memory actions.
	 */
	void rollback() {
		// roll back memory changes
		for (auto rit = mem_writes.rbegin(); rit != mem_writes.rend(); rit++) {
			if (rit->clean == -1) {
				// all bytes were clean before this write
				taint_t *bitmap = page_lookup(rit->address);
				if (bitmap)
					memset(bitmap, TAINT_NONE, sizeof(taint_t) * rit->size);
			} else {
				uc_err err = uc_mem_write(uc, rit->address, rit->value, rit->size);
				if (err) {
					//LOG_I("rollback: %s", uc_strerror(err));
					break ;
				}
				if (rit->clean) {
					// should untaint some bits
					taint_t *bitmap = page_lookup(rit->address);
					uint64_t start = rit->address & 0xFFF;
					int size = rit->size;
					int clean = rit->clean;
					for (int i = 0; i < size; i++)
						if ((clean >> i) & 1) {
							// this byte is untouched before this memory action
							// in the rollback, we already failed to execute, so
							// we don't care about symoblic address, just mark
							// it's clean.
							bitmap[start + i] = TAINT_NONE;
						}
				}
			}
		}
		mem_writes.clear();

		// restore registers
		uc_context_restore(uc, saved_regs);
		bbl_addrs.pop_back();
	}

	/*
	 * return the PageBitmap only if the page is remapped for writing,
	 * or initialized with symbolic variable, otherwise return NULL.
	 */
	taint_t *page_lookup(uint64_t address) const {
		address &= ~0xFFFULL;
		auto it = active_pages.find(address);
		if (it == active_pages.end()) {
			return NULL;
		}
		return it->second;
	}

	/*
	 * allocate a new PageBitmap and put into active_pages.
	 */
	void page_activate(uint64_t address, uint8_t *taint = NULL, uint64_t taint_offset = 0) {
		address &= ~0xFFFULL;
		taint_t *bitmap = NULL;
		auto it = active_pages.find(address);
		if (it == active_pages.end()) {
			bitmap = new PageBitmap;
			//LOG_D("inserting %lx %p", address, bitmap);
			// active_pages[address] = bitmap;
			active_pages.insert(std::pair<uint64_t, taint_t*>(address, bitmap));
			if (taint != NULL) {
				// taint is not NULL iff current page contains symbolic data
				// check previous write acctions.
				memcpy(bitmap, &taint[taint_offset], sizeof(PageBitmap));
			} else {
				memset(bitmap, TAINT_NONE, sizeof(PageBitmap));
			}
		} else {
			if (address == 0x1000) {
				printf("[sim_unicorn] You've mapped something at 0x1000! "
					"Please don't do that, I put my GDT there!\n");
			} else {
				printf("[sim_unicorn] Something very bad is happening; please investigate. "
					"Trying to activate the page at %#llx but it's already activated.\n", address);
				// to the person who sees this error:
				// you're gonna need to spend some time looking into it.
				// I'm not 100% sure that this is necessarily a bug condition.
			}
			bitmap = it->second;
		}

		for (auto a = mem_writes.begin(); a != mem_writes.end(); a++)
			if (a->clean == -1 && (a->address & ~0xFFFULL) == address) {
				// initialize this memory access immediately so that the
				// following memory read is valid.
				//LOG_D("page_activate: lazy initialize mem_write [%#lx, %#lx]", a->address, a->address + a->size);
				memset(&bitmap[a->address & 0xFFFULL], TAINT_DIRTY, sizeof(taint_t) * a->size);
				a->clean = (1ULL << a->size) - 1;
			}
	}

	/*
	 * record consecutive dirty bit rage, return a linked list of ranges
	 */
	mem_update_t *sync() {
		mem_update *head = NULL;

		for (auto it = active_pages.begin(); it != active_pages.end(); it++) {
			taint_t *start = it->second;
			taint_t *end = &it->second[0x1000];
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

	void set_stops(uint64_t count, uint64_t *stops)
	{
		stop_points.clear();
		for (int i = 0; i < count; i++)
			stop_points.insert(stops[i]);
	}

	std::pair<uint64_t, size_t> cache_page(uint64_t address, size_t size, char* bytes, uint64_t permissions)
	{
		//printf("caching page %#lx - %#lx.\n", address, address + size);
		// Make sure this page is not overlapping with any existing cached page
		auto after = page_cache->lower_bound(address);
		auto before = page_cache->lower_bound(address);

		if (after != page_cache->end()) {
			if (address + size >= after->first) {
				if (address >= after->first) {
					printf("[%#" PRIx64 ", %#" PRIx64 "](%#zx) overlaps with [%#" PRIx64 ", %#" PRIx64 "](%#zx).\n", address, address + size, size, after->first, after->first + after->second.size, after->second.size);
					// A complete overlap
					return std::make_pair(address, size);
				}
				size = after->first - address;
			}
		}
		if (before != page_cache->begin()) {
			before--;
			if (address < before->first + before->second.size) {
				if (address + size <= before->first + before->second.size) {
					// A complete overlap
					printf("[%#" PRIx64 ", %#" PRIx64 "](%#zx) overlaps with [%#" PRIx64 ", %#" PRIx64 "](%#zx).\n", address, address + size, size, after->first, after->first + after->second.size, after->second.size);
					return std::make_pair(address, size);
				}
				size = address + size - (before->first + before->second.size);
				address = before->first + before->second.size;
			}
		}

		for (uint64_t offset = 0; offset < size; offset += 0x1000) {
			uint8_t *copy = (uint8_t *)malloc(0x1000);
			CachedPage cached_page = {
				0x1000,
				copy,
				permissions
			};
			// address should be aligned to 0x1000
			memcpy(copy, &bytes[offset], 0x1000);
			page_cache->insert(std::pair<uint64_t, CachedPage>(address+offset, cached_page));
		}
		return std::make_pair(address, size);
	}

	void uncache_page(uint64_t address) {
		if ((address & 0xfff) != 0) {
			printf("Warning: Address #%" PRIx64 " passed to uncache_page is not aligned\n", address);
			return;
		}

		auto page = page_cache->find(address);
		if (page != page_cache->end()) {
			//printf("Internal: unmapping %#llx size %#x, result %#x", page->first, page->second.size, uc_mem_unmap(uc, page->first, page->second.size));
			uc_mem_unmap(uc, page->first, page->second.size);
			//free(page->second.bytes); // other forks might need this I guess :( how the HELL do you make memory management sane?
			page_cache->erase(page);
		} else {
			//printf("Uh oh! Couldn't find page at %#llx\n", address);
		}
	}

	bool map_cache(uint64_t address, size_t size) {
		auto it = page_cache->lower_bound(address);

		if (it == page_cache->end() && it != page_cache->begin()) {
			// Maybe the previous one works?
			it--;
		}

		if (it != page_cache->end()) {
			uint64_t cached_page_addr = it->first;
			if (cached_page_addr > address && it != page_cache->begin()) {
				it--;
				cached_page_addr = it->first;
			}
			auto itt = it->second;
			size_t page_size = itt.size;
			uint8_t *bytes = itt.bytes;
			uint64_t permissions = itt.perms;

			if (address >= cached_page_addr && address < cached_page_addr + page_size) {
				while (cached_page_addr < address + size) {
					//LOG_D("hit cache [%#lx, %#lx]", address, address + size);
					uc_err err = uc_mem_map_ptr(uc, cached_page_addr, page_size, permissions, bytes);
					if (err) {
						//LOG_E("map_cache [%#lx, %#lx]: %s", address, address + size, uc_strerror(err));
						return false;
					}

					it++;
					if (it != page_cache->end()) {
						cached_page_addr = it->first;
						page_size = it->second.size;
						bytes = it->second.bytes;
						permissions = it->second.perms;
					} else {
						break;
					}
				}
				return true;
			}
		}
		//LOG_D("cache miss.");
		return false;
	}

	bool in_cache(uint64_t address) {
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
	inline void mark_register_clobbered(RegisterSet *clobbered, uint64_t offset, int size)
	{
		for (int i = 0; i < size; i++)
			clobbered->insert(offset + i);
	}

	// check register access
	inline void check_register_read(RegisterSet *clobbered, RegisterSet *danger, uint64_t offset, int size)
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
	bool check_block(uint64_t address, int32_t size)
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
			auto& entry = this->block_cache->emplace(std::make_pair(address, block_entry_t())).first->second;
			entry.try_unicorn = true;
			clobbered_registers = &entry.clobbered_registers;
			used_registers = &entry.used_registers;

			std::unique_ptr<uint8_t[]> instructions(new uint8_t[size]);
			uc_mem_read(this->uc, address, instructions.get(), size);
			VEXLiftResult *lift_ret = vex_lift(
			    this->vex_guest, this->vex_archinfo, instructions.get(), address, 99, size, 1, 0, 0, 1
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

		for (uint64_t off : this->symbolic_registers) {
			if (used_registers->count(off) > 0) {
				stopping_register = off;
				return false;
			}
		}

		for (uint64_t off : *clobbered_registers) {
			this->symbolic_registers.erase(off);
		}

		return true;
	}

	// Finds tainted data in the provided range and returns the address.
	// Returns -1 if no tainted data is present.
	uint64_t find_tainted(uint64_t address, int size)
	{
		taint_t *bitmap = page_lookup(address);

		int start = address & 0xFFF;
		int end = (address + size - 1) & 0xFFF;

		if (end >= start) {
			if (bitmap) {
				for (int i = start; i <= end; i++)  {
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

			bitmap = page_lookup(address + size - 1);
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

	void handle_write(uint64_t address, int size)
	{
		taint_t *bitmap = page_lookup(address);
		int start = address & 0xFFF;
		int end = (address + size - 1) & 0xFFF;
		int clean;

		if (end >= start)  {
			if (bitmap) {
				clean = 0;
				for (int i = start; i <= end; i++) {
					if (bitmap[i] != TAINT_DIRTY) {
						clean |= (1 << i); // this bit should not be marked as taint if we undo this action
						bitmap[i] = TAINT_DIRTY; // this will automatically remove TAINT_SYMBOLIC flag
					}
				}
			} else {
				clean = -1;
			}
			log_write(address, size, clean);
		} else {
			if (bitmap) {
				clean = 0;
				for (int i = start; i <= 0xFFF; i++) {
					if (bitmap[i] == TAINT_DIRTY) {
						clean |= (1 << i);
						bitmap[i] = TAINT_DIRTY;
					}
				}
			} else {
				clean = -1;
			}
			if (!log_write(address, 0x1000 - start, clean))
				// uc is already stopped if any error happens
				return ;

			bitmap = page_lookup(address + size - 1);
			if (bitmap) {
				clean = 0;
				for (int i = 0; i <=  end; i++)  {
					if (bitmap[i] == TAINT_DIRTY) {
						clean |= (1 << i);
						bitmap[i] = TAINT_DIRTY;
					}
				}
			} else {
				clean = -1;
			}
			log_write(address - start + 0x1000, end + 1, clean);
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

	uint64_t get_instruction_pointer() {
		uint64_t out = 0;
		unsigned int reg = arch_pc_reg();
		if (reg == -1) {
			out = 0;
		} else {
			uc_reg_read(uc, reg, &out);
		}

		return out;
	}

	uint64_t get_stack_pointer() {
		uint64_t out = 0;
		unsigned int reg = arch_sp_reg();
		if (reg == -1) {
			out = 0;
		} else {
			uc_reg_read(uc, reg, &out);
		}

		return out;
	}

	void set_instruction_pointer(uint64_t val) {
		unsigned int reg = arch_pc_reg();
		if (reg != -1) {
			uc_reg_write(uc, reg, &val);
		}
	}

	void set_stack_pointer(uint64_t val) {
		unsigned int reg = arch_sp_reg();
		if (reg != -1) {
			uc_reg_write(uc, reg, &val);
		}
	}
};

static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	// uc_mem_read(uc, address, &value, size);
	// //LOG_D("mem_read [%#lx, %#lx] = %#lx", address, address + size);
	//LOG_D("mem_read [%#lx, %#lx]", address, address + size);
	State *state = (State *)user_data;

	auto tainted = state->find_tainted(address, size);
	if (tainted != -1)
	{
		state->stopping_memory = tainted;
		state->stop(STOP_SYMBOLIC_MEM);
	}
}

/*
 * the goal of hooking memory write is to determine the exact
 * positions of dirty bytes to writing chaneges  back to angr
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
	state->commit();
	state->step(address, size);

	if (!state->stopped && !state->check_block(address, size)) {
		state->stop(STOP_SYMBOLIC_REG);
		//LOG_I("finishing early at address %#lx", address);
	}
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
				state->commit();
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
void simunicorn_activate(State *state, uint64_t address, uint64_t length, uint8_t *taint) {
	// //LOG_D("activate [%#lx, %#lx]", address, address + length);
	for (uint64_t offset = 0; offset < length; offset += 0x1000)
		state->page_activate(address + offset, taint, offset);
}

extern "C"
uint64_t simunicorn_executed_pages(State *state) { // this is HORRIBLE
    if (state->executed_pages_iterator == NULL) {
        state->executed_pages_iterator = new std::unordered_set<uint64_t>::iterator;
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
void simunicorn_uncache_page(State *state, uint64_t address) {
	state->uncache_page(address);
}

// Tracking settings
extern "C"
void simunicorn_set_tracking(State *state, bool track_bbls, bool track_stack) {
	state->track_bbls = track_bbls;
	state->track_stack = track_stack;
}
