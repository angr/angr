#include <unicorn.h>

#include <cstring>

#include <map>
#include <vector>

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12

typedef enum taint: uint8_t {
	TAINT_NONE = 0,
	TAINT_DIRTY = 1,
	TAINT_SYMBOLIC = 2,
} taint_t;

typedef enum stop {
	STOP_NORMAL=0,
	STOP_SYMBOLIC,
	STOP_ERROR,
	STOP_SYSCALL,
	STOP_EXECNONE,
	STOP_ZEROPAGE,
} stop_t;

typedef taint_t PageBitmap[PAGE_SIZE];

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
static bool hook_mem_prot(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void hook_block(uc_engine *uc, uint64_t address, uint64_t size, void *user_data);

class State {
private:
	uc_engine *uc;
	bool hooked;

	std::vector<mem_access_t> mem_writes;
	std::map<uint64_t, taint_t *> active_pages;

public:
	uint64_t cur_steps, max_steps;
	uc_hook h_read, h_write, h_block, h_prot;

	State(uc_engine *_uc):uc(_uc) {
		hooked = false;
		h_read = h_write = h_block = h_prot = 0;
		max_steps = cur_steps = 0;
	}
	
	/*
	 * HOOK_MEM_WRITE is called before checking if the address is valid. so we might
	 * see uninitialized pages, so using HOOK_MEM_PROT is too late for tracking taint.
	 * so we don't have to use HOOK_MEM_PROT to track dirty pages.
	 *
	 * syscall is not hooked here, because we always stop in  any syscall, and we
	 * prefer to deal with different archs in python.
	 */
	void hook() {
		if (hooked)
			return ;
		uc_err err;
		err = uc_hook_add(uc, &h_read, UC_HOOK_MEM_READ, (void *)hook_mem_read, this);
		err = uc_hook_add(uc, &h_write, UC_HOOK_MEM_WRITE, (void *)hook_mem_write, this);
		err = uc_hook_add(uc, &h_block, UC_HOOK_BLOCK, (void *)hook_block, this);
		// err = uc_hook_add(uc, &h_prot, UC_HOOK_MEM_PROT, (void *)hook_mem_prot, this);
		hooked = true;
	}

	void unhook() {
		if (!hooked)
			return ;

		uc_err err;
		err = uc_hook_del(uc, h_read);
		err = uc_hook_del(uc, h_write);
		err = uc_hook_del(uc, h_block);
		// err = uc_hook_del(uc, h_prot);

		hooked = false;
		h_read = h_write = h_block = h_prot = 0;
	}

	~State() {
		for (auto it = active_pages.begin(); it != active_pages.end(); it++) {
			delete it->second;
		}
		active_pages.clear();
	}

	void start(uint64_t pc, uint64_t step = 1) {
		max_steps = step;
		cur_steps = 0;
		uc_emu_start(uc, pc, 0, 0, 0);
	}

	void stop(stop_t reason) {
		const char *msg = NULL;
		switch (reason) {
			case STOP_NORMAL:
				msg = "reaches maximal steps";
				break;
			case STOP_SYMBOLIC:
				msg = "read symbolic data";
				break;
			case STOP_ERROR:
				msg = "something wrong";
				break;
			case STOP_SYSCALL:
				msg = "unable to handle syscall";
				break;
			case STOP_ZEROPAGE:
				msg = "accessing zero page";
				break;
			case STOP_EXECNONE:
				msg = "fetching empty page";
				break;
			default:
				msg = "unknown error";
		}
		fprintf(stderr, "stop: %s\n", msg);
		if (mem_writes.size() > 0)
			rollback();
		uc_emu_stop(uc);
	}

	void step() {
		if (cur_steps >= max_steps)
			stop(STOP_NORMAL);
		else
			cur_steps++;
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
				fprintf(stderr, "log_write: %s\n", uc_strerror(err));
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
		for (auto it = mem_writes.begin(); it != mem_writes.end(); it++)
			if (it->clean == -1) {
				taint_t *bitmap = page_lookup(it->address);
				memset(&bitmap[it->address & 0xFFFUL], TAINT_DIRTY, sizeof(taint_t) * it->size);
				it->clean = (1 << it->size) - 1;
				fprintf(stderr, "commit: lazy initialize mem_write [%#lx, %#lx]\n", it->address, it->address + it->size);
			}
		mem_writes.clear();
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
				memset(bitmap, TAINT_NONE, sizeof(taint_t) * rit->size);
			} else {
				uc_err err = uc_mem_write(uc, rit->address, rit->value, rit->size);
				if (err) {
					fprintf(stderr, "rollback: %s\n", uc_strerror(err));
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
	}

	/*
	 * return the PageBitmap only if the page is remapped for writing,
	 * or initialized with symbolic variable, otherwise return NULL.
	 */
	taint_t *page_lookup(uint64_t address) const {
		address &= ~0xFFFUL;
		auto it = active_pages.find(address);
		if (it == active_pages.end())
			return NULL;
		return it->second;
	}

	/*
	 * allocate a new PageBitmap and put into active_pages.
	 */
	void page_activate(uint64_t address, uint8_t *taint = NULL) {
		address &= ~0xFFFUL;
		taint_t *bitmap = NULL;
		auto it = active_pages.find(address);
		if (it == active_pages.end()) {
			bitmap = new PageBitmap;
			fprintf(stderr, "inserting %lx %p\n", address, bitmap);
			// active_pages[address] = bitmap;
			active_pages.insert(std::pair<uint64_t, taint_t*>(address, bitmap));
		} else {
			bitmap = it->second;
		}

		if (taint != NULL) {
			// taint is not NULL iff current page contains symbolic data
			// check previous write acctions.
			memcpy(bitmap, taint, sizeof(PageBitmap));
		} else {
			memset(bitmap, TAINT_NONE, sizeof(PageBitmap));
		}

		for (auto a = mem_writes.begin(); a != mem_writes.end(); a++)
			if (a->clean == -1 && (a->address & ~0xFFFUL) == address) {
				// initialize this memory access immediately so that the
				// following memory read is valid.
				fprintf(stderr, "page_activate: lazy initialize mem_write [%#lx, %#lx]\n", a->address, a->address + a->size);
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
			fprintf(stderr, "found active page %#lx (%p)\n", it->first, start);
			for (taint_t *i = start; i != end; i++)
				if ((*i) == TAINT_DIRTY) {
					taint_t *j = i;
					while (j != end && (*j) == TAINT_DIRTY) j++;

					fprintf(stderr, "sync [%#lx, %#lx]\n", it->first + (i - start), it->first + (j - start));

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
};

static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	fprintf(stderr, "mem_read [%#lx, %#lx]\n", address, address + size);
	State *state = (State *)user_data;
	taint_t *bitmap = state->page_lookup(address);

	int start = address & 0xFFF;
	int end = (address + size - 1) & 0xFFF;

	if (end >= start) {
		if (bitmap) {
			for (int i = start; i <= end; i++)  {
				if (bitmap[i] & TAINT_SYMBOLIC) {
					state->stop(STOP_SYMBOLIC);
					return ;
				}
			}
		}
	} else {
		// cross page boundary
		if (bitmap) {
			for (int i = start; i <= 0xFFF; i++) {
				if (bitmap[i] & TAINT_SYMBOLIC) {
					state->stop(STOP_SYMBOLIC);
					return ;
				}
			}
		}

		bitmap = state->page_lookup(address + size - 1);
		if (bitmap) {
			for (int i = 0; i <= end; i++) {
				if (bitmap[i] & TAINT_SYMBOLIC) {
					state->stop(STOP_SYMBOLIC);
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
	fprintf(stderr, "mem_write [%#lx, %#lx]\n", address, address + size);
	State *state = (State *)user_data;
	taint_t *bitmap = state->page_lookup(address);

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

static void hook_block(uc_engine *uc, uint64_t address, uint64_t size, void *user_data) {
	fprintf(stderr, "block [%#lx, %#lx]\n", address, address + size);
	State *state = (State *)user_data;
	state->commit();
	state->step();
}

static bool hook_mem_prot(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	if (type == UC_MEM_WRITE_PROT) {
		// we only handle writing to readonly page
		fprintf(stderr, "writing to readonly page [%#lx, %#lx]\n", address, address + size);
		uint64_t start = address & ~0xFFFUL;
		uint64_t length = ((address + size + 0xFFFUL) & ~0xFFFUL) - start;

		uc_err err = uc_mem_protect(uc, start, length, UC_PROT_ALL);
		if (err) {
			fprintf(stderr, "hook_mem_prot: %s\n", uc_strerror(err));
			return false;
		}
		State *state = (State *)user_data;
		for (uint64_t offset = 0; offset < length; offset += 0x1000)
			state->page_activate(start + offset);
		return true;
	} else {
		// any other exception should terminate to program
		return false;
	}
}

/*
 * C style bindings makes it simple and dirty
 */

extern "C"
State *alloc(uc_engine *uc) {
	State *state = new State(uc);
	return state;
}

extern "C"
void dealloc(State *state) {
	delete state;
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
void start(State *state, uint64_t pc, uint64_t step) {
	state->start(pc, step);
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
void activate(State *state, uint64_t address, uint64_t length, uint8_t *taint) {
	// fprintf(stderr, "activate [%#lx, %#lx]\n", address, address + length);
	for (uint64_t offset = 0; offset < length; offset += 0x1000)
		state->page_activate(address + offset, &taint[offset]);
}
