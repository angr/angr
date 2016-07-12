#include "unicorn.h"
#include "log.h"

#include <cstring>

#include <memory>
#include <map>
#include <vector>
#include <unordered_set>

extern "C" {
#include <libvex.h>
#include <pyvex_static.h>
}

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12

#define MAX_REG_SIZE 0x2000 // hope it's big enough

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
} stop_t;

typedef taint_t PageBitmap[PAGE_SIZE];
typedef std::map<uint64_t, std::pair<char *, uint64_t>> PageCache;
std::map<uint64_t, PageCache*> global_cache;

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

static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static bool hook_mem_unmapped(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static bool hook_mem_prot(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void hook_block(uc_engine *uc, uint64_t address, int32_t size, void *user_data);

class State {
private:
	uc_engine *uc;
	PageCache *page_cache;
	bool hooked;

	void (*uc_reg_update)(uc_engine *uc, void *buf, int save);
	uint8_t tmp_reg[MAX_REG_SIZE];

	std::vector<mem_access_t> mem_writes;
	std::map<uint64_t, taint_t *> active_pages;
	std::unordered_set<uint64_t> stop_points;

public:
	std::vector<uint64_t> bbl_addrs;
	uint64_t cur_steps, max_steps;
	uc_hook h_read, h_write, h_block, h_prot, h_unmap;
	stop_t stop_reason;

	bool ignore_next_block;
	bool ignore_next_selfmod;
	uint64_t cur_address;
	int32_t cur_size;

  VexArch vex_guest;
  VexArchInfo vex_archinfo;
	RegisterSet symbolic_registers; // tracking of symbolic registers

	State(uc_engine *_uc, uint64_t cache_key):uc(_uc)
	{
		hooked = false;
		h_read = h_write = h_block = h_prot = 0;
		max_steps = cur_steps = 0;
		stop_reason = STOP_NOSTART;
		ignore_next_block = false;
		ignore_next_selfmod = false;
    vex_guest = VexArch_INVALID;

		auto it = global_cache.find(cache_key);
		if (it == global_cache.end()) {
				page_cache = new PageCache();
				global_cache[cache_key] = page_cache;
		} else {
				page_cache = it->second;
		}

		switch (*(uc_arch *)uc) { // tricky:)
				case UC_ARCH_X86:
						*(void **)&uc_reg_update = (void *)x86_reg_update;
						break;
				case UC_ARCH_MIPS:
						*(void **)&uc_reg_update = (void *)mips_reg_update;
						break;
				default:
						*(void **)&uc_reg_update = (void *)0xdeadbeef;
						LOG_E("unsupported arch");
		};
	}
	
	/*
	 * HOOK_MEM_WRITE is called before checking if the address is valid. so we might
	 * see uninitialized pages. Using HOOK_MEM_PROT is too late for tracking taint.
	 * so we don't have to use HOOK_MEM_PROT to track dirty pages.
	 *
	 * syscall is not hooked here, because we always stop in  any syscall, and we
	 * prefer to deal with different archs in python.
	 */
	void hook() {
		if (hooked) {
			LOG_D("already hooked");
			return ;
		}
		uc_err err;
		err = uc_hook_add(uc, &h_read, UC_HOOK_MEM_READ, (void *)hook_mem_read, this, 1, 0);

		err = uc_hook_add(uc, &h_write, UC_HOOK_MEM_WRITE, (void *)hook_mem_write, this, 1, 0);

		err = uc_hook_add(uc, &h_block, UC_HOOK_BLOCK, (void *)hook_block, this, 1, 0);

		err = uc_hook_add(uc, &h_prot, UC_HOOK_MEM_PROT, (void *)hook_mem_prot, this, 1, 0);

		err = uc_hook_add(uc, &h_unmap, UC_HOOK_MEM_UNMAPPED, (void *)hook_mem_unmapped, this, 1, 0);

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

		hooked = false;
		h_read = h_write = h_block = h_prot = h_unmap = 0;
	}

	~State() {
		for (auto it = active_pages.begin(); it != active_pages.end(); it++) {
			// only poor guys consider about memory leak :(
			LOG_D("delete active page %#lx", it->first);
			// delete should use the bracket operator since PageBitmap is an array typedef
			delete[] it->second;
		}
		active_pages.clear();
	}

	uc_err start(uint64_t pc, uint64_t step = 1) {
		stop_reason = STOP_NOSTART;
		max_steps = step;
		cur_steps = -1;

		// error if pc is 0
		if (pc == 0) {
		  stop_reason == STOP_ZEROPAGE;
		  return UC_ERR_MAP;
		}

		return uc_emu_start(uc, pc, 0, 0, 0);
	}

	void stop(stop_t reason) {
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
				uc_reg_update(uc, tmp_reg, 1);
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
			default:
				msg = "unknown error";
		}
		stop_reason = reason;
		LOG_D("stop: %s", msg);
		rollback();
		uc_emu_stop(uc);

		// if we errored out right away, fix the step count to 0
		if (cur_steps == -1) cur_steps = 0;
	}

	void step(uint64_t current_address, int32_t size) {
		uc_reg_update(uc, tmp_reg, 1); // save current registers
		bbl_addrs.push_back(current_address);
		cur_address = current_address;
		cur_size = size;

		if (cur_steps >= max_steps) {
			stop(STOP_NORMAL);
		} else if (stop_points.count(current_address) == 1) {
			stop(STOP_STOPPOINT);
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
				LOG_E("log_write: %s", uc_strerror(err));
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
		// we might miss some dirty bits, this happens if hitting the memory
		// write before mapping
		for (auto it = mem_writes.begin(); it != mem_writes.end(); it++) {
			if (it->clean == -1) {
				taint_t *bitmap = page_lookup(it->address);
				memset(&bitmap[it->address & 0xFFFUL], TAINT_DIRTY, sizeof(taint_t) * it->size);
				it->clean = (1 << it->size) - 1;
				LOG_D("commit: lazy initialize mem_write [%#lx, %#lx]", it->address, it->address + it->size);
			}
    }
		mem_writes.clear();
		cur_steps++;
	}

	/*
	 * undo recent memory actions.
	 * TODO reload registers
	 */
	void rollback() {
		for (auto rit = mem_writes.rbegin(); rit != mem_writes.rend(); rit++) {
			if (rit->clean == -1) {
				// all bytes were clean before this write
				taint_t *bitmap = page_lookup(rit->address);
				if (bitmap)
					memset(bitmap, TAINT_NONE, sizeof(taint_t) * rit->size);
			} else {
				uc_err err = uc_mem_write(uc, rit->address, rit->value, rit->size);
				if (err) {
					LOG_I("rollback: %s", uc_strerror(err));
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

		uc_reg_update(uc, tmp_reg, 0);
		bbl_addrs.pop_back();
	}

	/*
	 * return the PageBitmap only if the page is remapped for writing,
	 * or initialized with symbolic variable, otherwise return NULL.
	 */
	taint_t *page_lookup(uint64_t address) const {
		address &= ~0xFFFUL;
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
		address &= ~0xFFFUL;
		taint_t *bitmap = NULL;
		auto it = active_pages.find(address);
		if (it == active_pages.end()) {
			bitmap = new PageBitmap;
			LOG_D("inserting %lx %p", address, bitmap);
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
			bitmap = it->second;
		}

		for (auto a = mem_writes.begin(); a != mem_writes.end(); a++)
			if (a->clean == -1 && (a->address & ~0xFFFUL) == address) {
				// initialize this memory access immediately so that the
				// following memory read is valid.
				LOG_D("page_activate: lazy initialize mem_write [%#lx, %#lx]", a->address, a->address + a->size);
				memset(&bitmap[a->address & 0xFFFUL], TAINT_DIRTY, sizeof(taint_t) * a->size);
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
			LOG_D("found active page %#lx (%p)", it->first, start);
			for (taint_t *i = start; i < end; i++)
				if ((*i) == TAINT_DIRTY) {
					taint_t *j = i;
					while (j < end && (*j) == TAINT_DIRTY) j++;

					char buf[0x1000];
					uc_mem_read(uc, it->first + (i - start), buf, j - i);
					LOG_D("sync [%#lx, %#lx] = %#lx", it->first + (i - start), it->first + (j - start), *(uint64_t *)buf);

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

	void cache_page(uint64_t address, char* bytes, uint64_t permissions) {
		// address should be aligned to 0x1000
		char *copy = (char *)malloc(0x1000);
		memcpy(copy, bytes, 0x1000);
		page_cache->insert(std::pair<uint64_t, std::pair<char *, uint64_t>>(address, std::pair<char *, uint64_t>(copy, permissions)));
	}

	bool map_cache(uint64_t address) {
		auto it = page_cache->find(address);

		if (it != page_cache->end()) {
			auto itt = it->second;
			char *bytes = itt.first;
			uint64_t permissions = itt.second;
			LOG_D("hit cache [%#lx, %#lx]", address, address + 0x1000);
			uc_err err = uc_mem_map_ptr(uc, address, 0x1000, permissions, bytes);
			if (err) {
				LOG_E("map_cache: %s", uc_strerror(err));
				return false;
			}
			return true;
		} else {
			return false;
		}
	}

	bool in_cache(uint64_t address) {
		return page_cache->find(address) != page_cache->end();
	}

	//
	// Feasibility checks for unicorn
	//

	// check if we can safely handle this IRExpr
	inline bool check_expr(IRExpr *e)
	{
    int i, expr_size;
		if (e == NULL) return true;
		switch (e->tag)
		{
			case Iex_Binder:
				break;
			case Iex_VECRET:
				break;
			case Iex_BBPTR:
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
					LOG_W("seeing a 1-bit get from a register");
					return false;
				}

				expr_size = sizeofIRType(e->Iex.Get.ty);
				if (!this->check_register_read(e->Iex.Get.offset, expr_size)) return false;
				break;
			case Iex_Qop:
				if (!this->check_expr(e->Iex.Qop.details->arg1)) return false;
				if (!this->check_expr(e->Iex.Qop.details->arg2)) return false;
				if (!this->check_expr(e->Iex.Qop.details->arg3)) return false;
				if (!this->check_expr(e->Iex.Qop.details->arg4)) return false;
				break;
			case Iex_Triop:
				if (!this->check_expr(e->Iex.Triop.details->arg1)) return false;
				if (!this->check_expr(e->Iex.Triop.details->arg2)) return false;
				if (!this->check_expr(e->Iex.Triop.details->arg3)) return false;
				break;
			case Iex_Binop:
				if (!this->check_expr(e->Iex.Binop.arg1)) return false;
				if (!this->check_expr(e->Iex.Binop.arg2)) return false;
				break;
			case Iex_Unop:
				if (!this->check_expr(e->Iex.Unop.arg)) return false;
				break;
			case Iex_Load:
				if (!this->check_expr(e->Iex.Load.addr)) return false;
				break;
			case Iex_Const:
				break;
			case Iex_ITE:
				if (!this->check_expr(e->Iex.ITE.cond)) return false;
				if (!this->check_expr(e->Iex.ITE.iffalse)) return false;
				if (!this->check_expr(e->Iex.ITE.iftrue)) return false;
				break;
			case Iex_CCall:
				for (i = 0; i < 20; i++)
				{
					if (!this->check_expr(e->Iex.CCall.args[i])) return false;
				}
				break;
		}

		return true;
	}

	// mark the register as safe
	inline void mark_register_safe(uint64_t offset, int size)
	{
		for (int i = 0; i < size; i++)
			this->symbolic_registers.erase(offset+i);
	}

	// check register access
	inline bool check_register_read(uint64_t offset, int size)
	{
		for (int i = 0; i < size; i++)
		{
			if (this->symbolic_registers.find(offset + i) != this->symbolic_registers.end())
				return false;
		}
	}

	// check if we can safely handle this IRStmt
	inline bool check_stmt(IRTypeEnv *tyenv, IRStmt *s)
	{
		switch (s->tag)
		{
      case Ist_Put: {
				if (!this->check_expr(s->Ist.Put.data)) return false;
				IRType expr_type = typeOfIRExpr(tyenv, s->Ist.Put.data);
				if (expr_type == Ity_I1)
				{
					LOG_W("seeing a 1-bit write to a register");
					return false;
				}

				int expr_size = sizeofIRType(expr_type);
				this->mark_register_safe(s->Ist.Put.offset, expr_size);
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
				if (!this->check_expr(s->Ist.WrTmp.data)) return false;
				break;
			case Ist_Store:
				if (!this->check_expr(s->Ist.Store.addr)) return false;
				if (!this->check_expr(s->Ist.Store.data)) return false;
				break;
			case Ist_CAS:
				if (!this->check_expr(s->Ist.CAS.details->addr)) return false;
				if (!this->check_expr(s->Ist.CAS.details->dataLo)) return false;
				if (!this->check_expr(s->Ist.CAS.details->dataHi)) return false;
				if (!this->check_expr(s->Ist.CAS.details->expdLo)) return false;
				if (!this->check_expr(s->Ist.CAS.details->expdHi)) return false;
				break;
			case Ist_LLSC:
				if (!this->check_expr(s->Ist.LLSC.addr)) return false;
				if (!this->check_expr(s->Ist.LLSC.storedata)) return false;
				break;
      case Ist_Dirty: {
				if (!this->check_expr(s->Ist.Dirty.details->guard)) return false;
				if (!this->check_expr(s->Ist.Dirty.details->mAddr)) return false;
				for (int i = 0; i < 20; i++)
				{
					if (!this->check_expr(s->Ist.Dirty.details->args[i])) return false;
				}
				break;
      }
			case Ist_Exit:
				if (!this->check_expr(s->Ist.Exit.guard)) return false;
				break;
			case Ist_LoadG:
				if (!this->check_expr(s->Ist.LoadG.details->addr)) return false;
				if (!this->check_expr(s->Ist.LoadG.details->alt)) return false;
				if (!this->check_expr(s->Ist.LoadG.details->guard)) return false;
				break;
			case Ist_StoreG:
				if (!this->check_expr(s->Ist.StoreG.details->addr)) return false;
				if (!this->check_expr(s->Ist.StoreG.details->data)) return false;
				if (!this->check_expr(s->Ist.StoreG.details->guard)) return false;
				break;
			case Ist_NoOp:
			case Ist_IMark:
			case Ist_AbiHint:
			case Ist_MBE:
				// no-ops for our purposes
				break;
			default:
				LOG_W("Encountered unknown VEX statement -- can't determine safety.")
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

    std::unique_ptr<uint8_t[]> instructions(new uint8_t[size]);
		uc_mem_read(this->uc, address, instructions.get(), size);
		IRSB *the_block = vex_block_bytes(this->vex_guest, this->vex_archinfo, instructions.get(), address, size, 0);

    if (the_block == NULL) {
      // TODO: how to handle?
      return false;
    }

		for (int i = 0; i < the_block->stmts_used; i++) {
			if (!this->check_stmt(the_block->tyenv, the_block->stmts[i])) {
        return false;
      }
		}

		if (!this->check_expr(the_block->next)) {
      return false;
    }

		return true;
	}

};

static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	// uc_mem_read(uc, address, &value, size);
	// LOG_D("mem_read [%#lx, %#lx] = %#lx", address, address + size);
	LOG_D("mem_read [%#lx, %#lx]", address, address + size);
	State *state = (State *)user_data;
	taint_t *bitmap = state->page_lookup(address);

	int start = address & 0xFFF;
	int end = (address + size - 1) & 0xFFF;

	if (end >= start) {
		if (bitmap) {
			for (int i = start; i <= end; i++)  {
				if (bitmap[i] & TAINT_SYMBOLIC) {
					state->stop(STOP_SYMBOLIC_MEM);
					return ;
				}
			}
		}
	} else {
		// cross page boundary
		if (bitmap) {
			for (int i = start; i <= 0xFFF; i++) {
				if (bitmap[i] & TAINT_SYMBOLIC) {
					state->stop(STOP_SYMBOLIC_MEM);
					return ;
				}
			}
		}

		bitmap = state->page_lookup(address + size - 1);
		if (bitmap) {
			for (int i = 0; i <= end; i++) {
				if (bitmap[i] & TAINT_SYMBOLIC) {
					state->stop(STOP_SYMBOLIC_MEM);
					return ;
				}
			}
		}
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
	LOG_D("mem_write [%#lx, %#lx]", address, address + size);
	State *state = (State *)user_data;
	taint_t *bitmap = state->page_lookup(address);

	if (state->ignore_next_selfmod) {
		// ...the self-modification gets repeated for internal qemu reasons
		state->ignore_next_selfmod = false;
	} else if ((address >= state->cur_address && address < state->cur_address + state->cur_size) ||
		// CODE IS SELF-MODIFYING: qemu will restart this basic block at this address.
		// discard the next block hook
		(state->cur_address >= address && state->cur_address < address + size)) {
		state->ignore_next_block = true;
	}

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
		state->log_write(address, size, clean);
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
		if (!state->log_write(address, 0x1000 - start, clean))
			// uc is already stopped if any error happens
			return ;

		bitmap = state->page_lookup(address + size - 1);
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
		state->log_write(address - start + 0x1000, end + 1, clean);
	}
}

static void hook_block(uc_engine *uc, uint64_t address, int32_t size, void *user_data) {
	LOG_I("block [%#lx, %#lx]", address, address + size);

	if (state->ignore_next_block) {
		state->ignore_next_block = false;
		state->ignore_next_selfmod = true;
		return;
	}
	State *state = (State *)user_data;
  // TODO: is this right?
	state->commit();

	if (!state->check_block(address, size)) {
    state->stop(STOP_SYMBOLIC_REG);
    return;
  }

	state->step(address);
}

static bool hook_mem_unmapped(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	State *state = (State *)user_data;
	uint64_t start = address & ~0xFFFUL;
	uint64_t end = (address + size - 1) & ~0xFFFUL;

	// only hook nonwritable pages
	if (type != UC_MEM_WRITE_UNMAPPED && state->map_cache(start) && (start == end || state->map_cache(end))) {
		LOG_D("handle unmapped page natively");
		return true;
	}

	return false;
}

static bool hook_mem_prot(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	State *state = (State *)user_data;
	state->stop(STOP_SEGFAULT);
	return true;
}

/*
 * C style bindings makes it simple and dirty
 */

extern "C"
State *alloc(uc_engine *uc, uint64_t cache_key) {
	State *state = new State(uc, cache_key);
	return state;
}

extern "C"
void dealloc(State *state) {
	delete state;
}

extern "C"
uint64_t *bbl_addrs(State *state) {
	return &(state->bbl_addrs[0]);
}

extern "C"
uint64_t bbl_addr_count(State *state) {
	return state->bbl_addrs.size();
}

extern "C"
void hook(State *state) {
	state->hook();
}

extern "C"
void unhook(State *state) {
	state->unhook();
}

extern "C"
uc_err start(State *state, uint64_t pc, uint64_t step) {
	return state->start(pc, step);
}

extern "C"
void stop(State *state, stop_t reason) {
	state->stop(reason);
}

extern "C"
mem_update_t *sync(State *state) {
	return state->sync();
}

extern "C"
void destroy(mem_update_t * head) {
	mem_update_t *next;
	for (mem_update_t *cur = head; cur; cur = next) {
		next = cur->next;
		delete cur;
	}
}

extern "C"
uint64_t step(State *state) {
	return state->cur_steps;
}

extern "C"
stop_t stop_reason(State *state) {
	return state->stop_reason;
}

extern "C"
void set_stops(State *state, uint64_t count, uint64_t *stops)
{
	state->set_stops(count, stops);
}

extern "C"
void activate(State *state, uint64_t address, uint64_t length, uint8_t *taint) {
	// LOG_D("activate [%#lx, %#lx]", address, address + length);
	for (uint64_t offset = 0; offset < length; offset += 0x1000)
		state->page_activate(address + offset, taint, offset);
}

extern "C"
void symbolic_register_data(State *state, uint64_t count, uint64_t *offsets)
{
  state->symbolic_registers.clear();
	for (int i = 0; i < count; i++)
	{
		state->symbolic_registers.insert(offsets[i]);
	}
}

extern "C"
void enable_symbolic_reg_tracking(State *state, VexArch guest, VexArchInfo archinfo) {
  state->vex_guest = guest;
  state->vex_archinfo = archinfo;
}

extern "C"
void disable_symbolic_reg_tracking(State *state) {
  state->vex_guest = VexArch_INVALID;
}

/*
 * Page cache
 */

extern "C"
bool cache_page(State *state, uint64_t address, uint64_t length, char *bytes, uint64_t permissions) {
	LOG_I("caching [%#lx, %#lx]", address, address + length);
	for (uint64_t offset = 0; offset < length; offset += 0x1000) {
		state->cache_page(address + offset, &bytes[offset], permissions);
		if (!state->map_cache(address + offset))
				return false;
	}
	return true;
}
