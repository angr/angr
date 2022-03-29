#define __STDC_FORMAT_MACROS 1
#define NOMINMAX

#include <algorithm>
#include <cassert>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <queue>
#include <memory>
#include <map>
#include <set>
#include <stdexcept>
#include <unordered_set>
#include <unordered_map>
#include <vector>

extern "C" {
#include <libvex.h>
#include <pyvex.h>
}

#include <unicorn/unicorn.h>

#include "sim_unicorn.hpp"
//#include "log.h"

State::State(uc_engine *_uc, uint64_t cache_key, simos_t curr_os, bool symb_addrs, bool symb_cond):
  uc(_uc), simos(curr_os), handle_symbolic_addrs(symb_addrs), handle_symbolic_conditions(symb_cond) {
	hooked = false;
	h_read = h_write = h_block = h_prot = 0;
	max_steps = cur_steps = 0;
	stopped = true;
	stop_details.stop_reason = STOP_NOSTART;
	ignore_next_block = false;
	ignore_next_selfmod = false;
	interrupt_handled = false;
	cgc_random_sysno = -1;
	cgc_receive_sysno = -1;
	cgc_transmit_sysno = -1;
	vex_guest = VexArch_INVALID;
	syscall_count = 0;
	uc_context_alloc(uc, &saved_regs);
	executed_pages_iterator = NULL;
	mem_updates_head = NULL;

	auto it = global_cache.find(cache_key);
	if (it == global_cache.end()) {
		page_cache = new PageCache();
		global_cache[cache_key] = {page_cache};
	} else {
		page_cache = it->second.page_cache;
	}
	arch = *((uc_arch*)uc); // unicorn hides all its internals...
	unicorn_mode = *((uc_mode*)((uc_arch*)uc + 1));
	curr_block_details.reset();
	symbolic_read_in_progress = false;
	trace_last_block_addr = 0;
	trace_last_block_tot_count = -1;
	trace_last_block_curr_count = -1;
	executed_blocks_count = -1;
}

/*
 * HOOK_MEM_WRITE is called before checking if the address is valid. so we might
 * see uninitialized pages. Using HOOK_MEM_PROT is too late for tracking taint.
 * so we don't have to use HOOK_MEM_PROT to track dirty pages.
 */
void State::hook() {
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

void State::unhook() {
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

uc_err State::start(address_t pc, uint64_t step) {
	stopped = false;
	stop_details.stop_reason = STOP_NOSTART;
	max_steps = step;
	cur_steps = -1;
	unicorn_next_instr_addr = pc;
	executed_pages.clear();

	// error if pc is 0
	// TODO: why is this check here and not elsewhere
	if (pc == 0) {
		stop_details.stop_reason = STOP_ZEROPAGE;
		cur_steps = 0;
		return UC_ERR_MAP;
	}

	uc_err out = uc_emu_start(uc, unicorn_next_instr_addr, 0, 0, 0);
	if (out == UC_ERR_OK && stop_details.stop_reason == STOP_NOSTART && get_instruction_pointer() == 0) {
		// handle edge case where we stop because we reached our bogus stop address (0)
		commit();
		stop_details.stop_reason = STOP_ZEROPAGE;
	}
	rollback();

	if (out == UC_ERR_INSN_INVALID) {
		stop_details.stop_reason = STOP_NODECODE;
	}

	// if we errored out right away, fix the step count to 0
	if (cur_steps == -1) cur_steps = 0;

	return out;
}

void State::stop(stop_t reason, bool do_commit) {
	if (stopped) {
		// Do not stop if already stopped. Sometimes, python lands initiates a stop even though native interface has
		// already stopped leading to multiple issues.
		return;
	}
	stopped = true;
	stop_details.stop_reason = reason;
	stop_details.block_addr = curr_block_details.block_addr;
	stop_details.block_size = curr_block_details.block_size;
	if ((reason == STOP_SYSCALL) || do_commit) {
		commit();
	}
	else if ((reason != STOP_NORMAL) && (reason != STOP_STOPPOINT)) {
		// Stop reason is not NORMAL, STOPPOINT or SYSCALL. Rollback.
		// EXECNONE, ZEROPAGE, NOSTART, ZERO_DIV, NODECODE and HLT are never passed to this function.
		rollback();
	}
	uc_emu_stop(uc);
	// Prepare details of blocks with symbolic instructions to re-execute for returning to state plugin
	for (auto &block: blocks_with_symbolic_instrs) {
		sym_block_details_t sym_block;
		sym_block.reset();
		sym_block.block_addr = block.block_addr;
		sym_block.block_size = block.block_size;
		sym_block.block_trace_ind = block.block_trace_ind;
		sym_block.has_symbolic_exit = block.has_symbolic_exit;
		std::set<instr_details_t> sym_instrs;
		std::unordered_set<register_value_t> reg_values;
		for (auto &sym_instr: block.symbolic_instrs) {
			auto sym_instr_list = get_list_of_dep_instrs(sym_instr);
			sym_instrs.insert(sym_instr_list.begin(), sym_instr_list.end());
			sym_instrs.insert(sym_instr);
			reg_values.insert(sym_instr.reg_deps.begin(), sym_instr.reg_deps.end());
		}
		sym_block.register_values.insert(sym_block.register_values.end(), reg_values.begin(), reg_values.end());
		for (auto &instr: sym_instrs) {
			sym_instr_details_t sym_instr;
			sym_instr.instr_addr = instr.instr_addr;
			sym_instr.memory_values = instr.memory_values;
			sym_instr.memory_values_count = instr.memory_values_count;
			sym_instr.has_memory_dep = instr.has_concrete_memory_dep || (instr.has_symbolic_memory_dep && !instr.has_read_from_symbolic_addr);
			sym_block.symbolic_instrs.emplace_back(sym_instr);
		}
		block_details_to_return.emplace_back(sym_block);
	}
}

void State::step(address_t current_address, int32_t size, bool check_stop_points) {
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
		else if ((trace_last_block_tot_count > 0) && (trace_last_block_addr >= current_address) &&
		  (trace_last_block_addr < current_address + real_size) && (trace_last_block_curr_count == trace_last_block_tot_count - 1)) {
			// Executing last block in trace. Stop.
			stop(STOP_STOPPOINT);
		}
	}
	if (!stopped) {
		executed_blocks_count++;
	}
}

void State::commit() {
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
		symbolic_registers.emplace(reg_offset);
	}
	for (auto &reg_offset: block_concrete_registers) {
		symbolic_registers.erase(reg_offset);
	}
	// Remove instructions whose effects are overwritten by subsequent instructions from the re-execute list
	std::vector<std::vector<block_details_t>::iterator> blocks_to_erase_it;
	for (auto &instrs_to_erase_entry: symbolic_instrs_to_erase) {
		std::vector<std::vector<instr_details_t>::iterator> instrs_to_erase_it;
		auto block_it = blocks_with_symbolic_instrs.begin() + instrs_to_erase_entry.first;
		auto first_instr_it = block_it->symbolic_instrs.begin();
		for (auto &instr_offset: instrs_to_erase_entry.second) {
			instrs_to_erase_it.push_back(first_instr_it + instr_offset);
		}
		for (auto &instr_to_erase_it: instrs_to_erase_it) {
			block_it->symbolic_instrs.erase(instr_to_erase_it);
		}
		if (block_it->symbolic_instrs.size() == 0) {
			// There are no more instructions to re-execute in this block and thus it can be removed from list of blocks
			// with instructions that need to be re-executed
			blocks_to_erase_it.push_back(block_it);
		}
	}
	for (auto &block_to_erase_it: blocks_to_erase_it) {
		blocks_with_symbolic_instrs.erase(block_to_erase_it);
	}
	// Save details of symbolic instructions in current block
	if (curr_block_details.symbolic_instrs.size() > 0) {
		for (auto &symbolic_instr: curr_block_details.symbolic_instrs) {
			compute_slice_of_instr(symbolic_instr);
			// Save all concrete memory dependencies of the block
			save_concrete_memory_deps(symbolic_instr);
		}
		blocks_with_symbolic_instrs.emplace_back(curr_block_details);
	}
	if (curr_block_details.block_addr == trace_last_block_addr) {
		trace_last_block_curr_count += 1;
	}
	// Clear all block level taint status trackers and symbolic instruction list
	block_symbolic_registers.clear();
	block_concrete_registers.clear();
	block_instr_concrete_regs.clear();
	curr_block_details.reset();
	block_mem_reads_data.clear();
	block_mem_reads_map.clear();
	block_mem_writes_taint_data.clear();
	symbolic_instrs_to_erase.clear();
	taint_engine_next_instr_address = 0;
	taint_engine_stop_mem_read_instruction = 0;
	taint_engine_stop_mem_read_size = 0;
	return;
}

void State::rollback() {
	// roll back memory changes
	for (auto rit = mem_writes.rbegin(); rit != mem_writes.rend(); rit++) {
		uc_err err = uc_mem_write(uc, rit->address, rit->value.data(), rit->size);
		if (err) {
			//LOG_I("rollback: %s", uc_strerror(err));
			break;
		}
		auto page = page_lookup(rit->address);
		taint_t *bitmap = page.first;

		uint64_t start = rit->address & 0xFFF;
		int size = rit->size;
		for (auto i = 0; i < size; i++) {
			bitmap[start + i] = rit->previous_taint[i];
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
std::pair<taint_t *, uint8_t *> State::page_lookup(address_t address) const {
	address &= ~0xFFFULL;
	auto it = active_pages.find(address);
	if (it == active_pages.end()) {
		return std::pair<taint_t *, uint8_t *>(NULL, NULL);
	}
	return it->second;
}

void State::page_activate(address_t address, uint8_t *taint, uint8_t *data) {
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

mem_update_t *State::sync() {
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
				range->next = mem_updates_head;
				mem_updates_head = range;

				i = j;
			}
	}

	return mem_updates_head;
}

void State::set_last_block_details(address_t block_addr, int64_t curr_count, int64_t tot_count) {
	trace_last_block_addr = block_addr;
	trace_last_block_curr_count = curr_count;
	trace_last_block_tot_count = tot_count;
	return;
}

void State::set_stops(uint64_t count, address_t *stops) {
	stop_points.clear();
	for (auto i = 0; i < count; i++) {
		stop_points.insert(stops[i]);
	}
}

std::pair<address_t, size_t> State::cache_page(address_t address, size_t size, char* bytes, uint64_t permissions) {
	assert(address % 0x1000 == 0);
	assert(size % 0x1000 == 0);

	for (auto offset = 0; offset < size; offset += 0x1000) {
		auto page = page_cache->find(address+offset);
		if (page != page_cache->end()) {
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

void State::wipe_page_from_cache(address_t address) {
	auto page = page_cache->find(address);
	if (page != page_cache->end()) {
		//printf("Internal: unmapping %#llx size %#x, result %#x", page->first, page->second.size, uc_mem_unmap(uc, page->first, page->second.size));
		uc_err err = uc_mem_unmap(uc, page->first, page->second.size);
		//if (err) {
		//	fprintf(stderr, "wipe_page_from_cache [%#lx, %#lx]: %s\n", page->first, page->first + page->second.size, uc_strerror(err));
		//}
		free(page->second.bytes); // might explode
		page_cache->erase(page);
	}
	else {
		//printf("Uh oh! Couldn't find page at %#llx\n", address);
	}
}

void State::uncache_pages_touching_region(address_t address, uint64_t length) {
	address &= ~(0x1000-1);
	for (auto offset = 0; offset < length; offset += 0x1000) {
				wipe_page_from_cache(address + offset);
	}

}

void State::clear_page_cache() {
	while (!page_cache->empty()) {
		wipe_page_from_cache(page_cache->begin()->first);
	}
}

bool State::map_cache(address_t address, size_t size) {
	assert(address % 0x1000 == 0);
	assert(size % 0x1000 == 0);

	bool success = true;

	for (auto offset = 0; offset < size; offset += 0x1000) {
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

bool State::in_cache(address_t address) const {
	return page_cache->find(address) != page_cache->end();
}

// Finds tainted data in the provided range and returns the address.
// Returns -1 if no tainted data is present.
int64_t State::find_tainted(address_t address, int size) {
	taint_t *bitmap = page_lookup(address).first;

	int start = address & 0xFFF;
	int end = (address + size - 1) & 0xFFF;

	if (end >= start) {
		if (bitmap) {
			for (auto i = start; i <= end; i++) {
				if (bitmap[i] & TAINT_SYMBOLIC) {
					return (address & ~0xFFF) + i;
				}
			}
		}
	}
	else {
		// cross page boundary
		if (bitmap) {
			for (auto i = start; i <= 0xFFF; i++) {
				if (bitmap[i] & TAINT_SYMBOLIC) {
					return (address & ~0xFFF) + i;
				}
			}
		}

		bitmap = page_lookup(address + size - 1).first;
		if (bitmap) {
			for (auto i = 0; i <= end; i++) {
				if (bitmap[i] & TAINT_SYMBOLIC) {
					return ((address + size - 1) & ~0xFFF) + i;
				}
			}
		}
	}
	return -1;
}

void State::handle_write(address_t address, int size, bool is_interrupt = false, bool interrupt_value_symbolic = false) {
	// If the write spans a page, chop it up
	if ((address & 0xfff) + size > 0x1000) {
		int chopsize = 0x1000 - (address & 0xfff);
		handle_write(address, chopsize, is_interrupt, interrupt_value_symbolic);
		if (stopped) {
			return;
		}
		handle_write(address + chopsize, size - chopsize, is_interrupt, interrupt_value_symbolic);
		return;
	}

	// From here, we are definitely only dealing with one page

	uint64_t skip_next_map_request;
	mem_write_t record;
	record.address = address;
	record.size = size;
	record.value.resize(size);
	uc_err err = uc_mem_read(uc, address, record.value.data(), size);
	if (err == UC_ERR_READ_UNMAPPED) {
		if (is_interrupt) {
			skip_next_map_request = 0;
		}
		else {
			skip_next_map_request = 1;
		}
		if (py_mem_callback(uc, UC_MEM_WRITE_UNMAPPED, address, size, 0, (void*)skip_next_map_request)) {
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
	address_t curr_instr_addr = 0;
	bool is_dst_symbolic;

	if (!bitmap) {
		// We should never have a missing bitmap because we explicitly called the callback!
		printf("This should never happen, right? %#" PRIx64 "\n", address);
		abort();
	}

	clean = 0;
	if (is_interrupt) {
		is_dst_symbolic = interrupt_value_symbolic;
	}
	else if (is_symbolic_tracking_disabled() || curr_block_details.vex_lift_failed) {
		// If symbolic tracking is disabled, all writes are concrete
		// is_interrupt flag is a workaround for CGC transmit syscall, which never passes symbolic data
		// If VEX lift failed, then write is definitely concrete since execution continues only
		// if no symbolic data is present
		is_dst_symbolic = false;
	}
	else if (size == 0) {
		// unicorn was unable to determine size of the memory write. Treat as failure since we cannot determine final
		// taint status
		stop(STOP_UNKNOWN_MEMORY_WRITE_SIZE);
		return;
	}
	else if ((block_mem_writes_taint_data.size() == 0) && (symbolic_registers.size() == 0) &&
	  (block_symbolic_registers.size() == 0) && (block_symbolic_temps.size() == 0)) {
		// No write taint info saved and there are no symbolic registers/VEX temps => write is concrete
		is_dst_symbolic = false;
	}
	else {
		// Determine destination's taint using block's memory writes taint info
		is_dst_symbolic = false;
		uint32_t size_of_writes_processed = 0;
		while (size_of_writes_processed != size) {
			if (block_mem_writes_taint_data.size() == 0) {
				// All writes have been processed but there should be more. Likely a bug.
				printf("All memory writes have been processed but more expected. This should not happen!\n");
				abort();
			}
			auto &next_mem_write = block_mem_writes_taint_data.front();
			is_dst_symbolic |= next_mem_write.is_symbolic;
			if (curr_instr_addr == 0) {
				curr_instr_addr = next_mem_write.instr_addr;
			}
			else if (curr_instr_addr != next_mem_write.instr_addr) {
				printf("Memory writes from two instructions being processed as part of one instruction. This should not happen!\n");
				abort();
			}
			if (size_of_writes_processed + next_mem_write.size > size) {
				// Including current write entry exceeds size of current write reported by unicorn. Update size of write
				// entry instead of erasing it completely
				block_mem_writes_taint_data[0].size = size_of_writes_processed + next_mem_write.size - size;
				break;
			}
			else {
				// Size of all writes so far does not exceed current write. Erase current write entry.
				size_of_writes_processed += next_mem_write.size;
				block_mem_writes_taint_data.erase(block_mem_writes_taint_data.begin());
			}
		}
	}
	if (is_dst_symbolic && !is_interrupt) {
		// Save the details of memory location written to in the instruction details
		for (auto &symbolic_instr: curr_block_details.symbolic_instrs) {
			if (symbolic_instr.instr_addr == curr_instr_addr) {
				symbolic_instr.mem_write_addr = address;
				symbolic_instr.mem_write_size = size;
				break;
			}
		}
	}
	if ((find_tainted(address, size) != -1) & (!is_dst_symbolic)) {
		// We are writing to a memory location that is currently symbolic. If the destination if a memory dependency
		// of some instruction to be re-executed, we need to re-execute that instruction before continuing.
		auto write_start_addr = address;
		auto write_end_addr = address + size;
		for (auto &symbolic_mem_dep: symbolic_mem_deps) {
			auto symbolic_start_addr = symbolic_mem_dep.first;
			auto symbolic_end_addr = symbolic_mem_dep.first + symbolic_mem_dep.second;
			if (!((symbolic_end_addr < write_start_addr) || (write_end_addr < symbolic_start_addr))) {
				// No overlap condition test failed => there is some overlap. Thus, some symbolic memory dependency
				// will be lost. Stop execution.
				stop(STOP_SYMBOLIC_MEM_DEP_NOT_LIVE);
				return;
			}
		}
		// The destination is not a memory dependency of some instruction to be re-executed. We now check if any
		// instructions to be re-executed write to this same location. If there is one, they need not be re-executed
		// since this concrete write nullifies their effects.
		auto curr_write_start_addr = address;
		auto curr_write_end_addr = address + size;
		auto first_block_it = blocks_with_symbolic_instrs.begin();
		for (auto block_it = first_block_it; block_it != blocks_with_symbolic_instrs.end(); block_it++) {
			std::unordered_set<uint32_t> instrs_to_erase;
			auto first_instr_it = block_it->symbolic_instrs.begin();
			for (auto sym_instr_it = first_instr_it; sym_instr_it != block_it->symbolic_instrs.end(); sym_instr_it++) {
				int64_t symbolic_write_start_addr = sym_instr_it->mem_write_addr;
				if (symbolic_write_start_addr == -1) {
					// Instruction does not write a symbolic write to memory. No need to check this.
					continue;
				}
				int64_t symbolic_write_end_addr = sym_instr_it->mem_write_addr + sym_instr_it->mem_write_size;
				if ((curr_write_start_addr <= symbolic_write_start_addr) && (symbolic_write_end_addr <= curr_write_end_addr)) {
					// Currrent write fully overwrites the previous written symbolic value and so the symbolic write
					// instruction need not be re-executed
					// TODO: How to handle partial overwrite?
					instrs_to_erase.emplace(sym_instr_it - first_instr_it);
				}
			}
			if (instrs_to_erase.size() > 0) {
				symbolic_instrs_to_erase.emplace(block_it - first_block_it, instrs_to_erase);
			}
		}
	}
	if (data == NULL) {
		for (auto i = start; i <= end; i++) {
			record.previous_taint.push_back(bitmap[i]);
			if (is_dst_symbolic) {
				// Don't mark as TAINT_DIRTY since we don't want to sync it back to angr
				// Also, no need to set clean: rollback will set it to TAINT_NONE which
				// is fine for symbolic bytes and rollback is called when exiting unicorn
				// due to an error encountered
				bitmap[i] = TAINT_SYMBOLIC;
			}
			else if (bitmap[i] != TAINT_DIRTY) {
				bitmap[i] = TAINT_DIRTY;
			}
		}
	}
	else {
		for (auto i = start; i <= end; i++) {
			record.previous_taint.push_back(bitmap[i]);
			if (is_dst_symbolic) {
				// Don't mark as TAINT_DIRTY since we don't want to sync it back to angr
				// Also, no need to set clean: rollback will set it to TAINT_NONE which
				// is fine for symbolic bytes and rollback is called when exiting unicorn
				// due to an error encountered
				bitmap[i] = TAINT_SYMBOLIC;
			}
			else if (bitmap[i] != TAINT_NONE) {
				bitmap[i] = TAINT_NONE;
			}
		}
	}
	mem_writes.push_back(record);
}

void State::compute_slice_of_instr(instr_details_t &instr) {
	// Compute block slice of instruction needed to setup concrete registers needed by it and also save values of
	// registers not changed from start of the block
	std::unordered_set<address_t> instrs_to_process;
	bool all_dep_regs_concrete = false;
	auto &block_taint_entry = block_taint_cache.at(curr_block_details.block_addr);
	auto &instr_taint_entry = block_taint_entry.block_instrs_taint_data_map.at(instr.instr_addr);

	// Save values of registers not modified from start of block till instruction
	auto instr_concrete_regs_it = block_instr_concrete_regs.find(instr.instr_addr);
	if (instr_concrete_regs_it == block_instr_concrete_regs.end()) {
		// No entry for current instruction in list of concrete regs => all registers were concrete
		// An entry was not added because no symbolic taint was present to propagate
		all_dep_regs_concrete = true;
	}
	for (auto &dependency: instr_taint_entry.unmodified_dep_regs) {
		if (!is_valid_dependency_register(dependency.first) ||
		    (!all_dep_regs_concrete && instr_concrete_regs_it->second.count(dependency.first) == 0)) {
			// Register is not a valid dependency or was not concrete before instruction was executed. Do not save value.
			continue;
		}
		register_value_t dep_reg_val;
		dep_reg_val.offset = dependency.first;
		dep_reg_val.size = dependency.second;
		auto saved_reg_val = block_start_reg_values.lower_bound(dep_reg_val.offset);
		if (dep_reg_val.offset == saved_reg_val->first) {
			// Dependency register contains byte 0 of the register. Save entire value: correct-sized value will
			// be computed when re-executing instruction
			memcpy(dep_reg_val.value, saved_reg_val->second.value, MAX_REGISTER_BYTE_SIZE);
			instr.reg_deps.insert(dep_reg_val);
			continue;
		}
		// Check if dependency register is a sub-register
		// lower_bound returns the first entry greater than or equal to given register offset but we have to check with
		// the register whose byte 0 has VEX offset less than the dependency register.
		saved_reg_val--;
		if (dep_reg_val.offset + dep_reg_val.size <= saved_reg_val->first + saved_reg_val->second.size) {
			// Dependency is a sub-register that starts in middle of larger register.
			// Save value of dependency register starting at offset 0 so that value is computed correctly when
			// re-executing
			uint32_t val_offset = dep_reg_val.offset - saved_reg_val->first;
			memcpy(dep_reg_val.value, saved_reg_val->second.value + val_offset, MAX_REGISTER_BYTE_SIZE - val_offset);
			instr.reg_deps.insert(dep_reg_val);
		}
		else {
			assert(false && "[sim_unicorn] Dependency register not saved at block start. Please create a bug with repro instructions.");
		}
	}

	// List of instructions modifying a register dependency. Their slice needs to be computed.
	for (auto &reg_dep: instr_taint_entry.dependencies.at(TAINT_ENTITY_REG)) {
		auto reg_modifier_entry = instr_taint_entry.dep_reg_modifier_addr.find(reg_dep.reg_offset);
		if (reg_modifier_entry == instr_taint_entry.dep_reg_modifier_addr.end()) {
			continue;
		}
		if (!all_dep_regs_concrete && instr_concrete_regs_it->second.count(reg_dep.reg_offset) == 0) {
			// Register was not concrete before instruction was executed. Do not compute slice.
			continue;
		}
		if (!reg_dep.used_in_mem_addr || instr.has_read_from_symbolic_addr) {
			instrs_to_process.emplace(instr_taint_entry.dep_reg_modifier_addr.at(reg_dep.reg_offset));
		}
	}

	// List of instructions modifying a VEX temp dependency. Their slice needs to be computed.
	for (auto &dependency: instr_taint_entry.dependencies.at(TAINT_ENTITY_TMP)) {
		auto vex_temp_deps_entry = block_taint_entry.vex_temp_deps.find(dependency);
		if (vex_temp_deps_entry == block_taint_entry.vex_temp_deps.end()) {
			// No dependency entries for this VEX temp
			continue;
		}
		address_t vex_setter_instr = vex_temp_deps_entry->second.first;
		if ((vex_setter_instr != instr.instr_addr) && !is_symbolic_temp(dependency.tmp_id)) {
			instrs_to_process.emplace(vex_setter_instr);
		}
	}
	for (auto &instr_to_process_addr: instrs_to_process) {
		auto &instr_to_process_taint_entry = block_taint_entry.block_instrs_taint_data_map.at(instr_to_process_addr);
		instr_details_t instr_details = compute_instr_details(instr_to_process_addr, instr_to_process_taint_entry);
		compute_slice_of_instr(instr_details);
		instr.reg_deps.insert(instr_details.reg_deps.begin(), instr_details.reg_deps.end());
		instr.instr_deps.insert(instr_details.instr_deps.begin(), instr_details.instr_deps.end());
		instr_details.reg_deps.clear();
		instr_details.instr_deps.clear();
		instr.instr_deps.insert(instr_details);
	}
	return;
}

void State::set_deps_mem_addr_status(const taint_entity_t &entity, instruction_taint_entry_t &instr_taint_entry) {
	std::queue<taint_entity_t> entities_to_process;
	entities_to_process.emplace(entity);
	while (!entities_to_process.empty()) {
		auto curr_entity = entities_to_process.front();
		entities_to_process.pop();
		for (auto &dep_list: instr_taint_entry.dependencies) {
			for (auto &dep: dep_list.second) {
				if (dep == curr_entity) {
					dep.used_in_mem_addr = true;
					auto taint_sink_entry_it = std::find_if(instr_taint_entry.taint_sink_src_map.begin(), instr_taint_entry.taint_sink_src_map.end(),
										[&dep](taint_vector_t::const_reference element) { return element.first == dep; });
					while (taint_sink_entry_it != instr_taint_entry.taint_sink_src_map.end()) {
						for (auto &elem: taint_sink_entry_it->second) {
							entities_to_process.push(elem);
					    }
						taint_sink_entry_it++;
						taint_sink_entry_it = std::find_if(taint_sink_entry_it, instr_taint_entry.taint_sink_src_map.end(),
										[&dep](taint_vector_t::const_reference element) { return element.first == dep; });
					}
				}
			}
		}
	}
}

void State::update_deps_mem_addr_status(const taint_entity_t &entity, instruction_taint_entry_t &instr_taint_entry) {
	for (auto &mem_entity: entity.mem_ref_entity_list) {
		set_deps_mem_addr_status(mem_entity, instr_taint_entry);
	}
	return;
}

void State::process_vex_block(IRSB *vex_block, address_t address) {
	block_taint_entry_t block_taint_entry;
	instruction_taint_entry_t instruction_taint_entry;
	bool started_processing_instructions;
	address_t curr_instr_addr;
	std::unordered_map<vex_reg_offset_t, address_t> last_reg_modifier_instr;
	std::unordered_set<vex_reg_offset_t> modified_regs;

	started_processing_instructions = false;
	block_taint_entry.has_unsupported_stmt_or_expr_type = false;
	for (auto i = 0; i < vex_block->stmts_used; i++) {
		auto stmt = vex_block->stmts[i];
		switch (stmt->tag) {
			case Ist_Put:
			{
				taint_entity_t sink;
				std::unordered_set<taint_entity_t> srcs;

				sink.entity_type = TAINT_ENTITY_REG;
				sink.instr_addr = curr_instr_addr;
				sink.reg_offset = stmt->Ist.Put.offset;
				auto result = process_vex_expr(stmt->Ist.Put.data, vex_block->tyenv, curr_instr_addr, false);
				if (result.has_unsupported_expr) {
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
					break;
				}
				sink.value_size = result.value_size;
				// Flatten list of taint sources and also save them as dependencies of instruction
				// TODO: Should we not save dependencies if sink is an artificial register?
				for (auto &entry: result.taint_sources) {
					srcs.insert(entry.second.begin(), entry.second.end());
					instruction_taint_entry.dependencies.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				instruction_taint_entry.taint_sink_src_map.emplace_back(sink, srcs);
				// Store ITE condition entities. Also, store them as dependencies of instruction.
				for (auto &entry: result.ite_cond_entities) {
					instruction_taint_entry.ite_cond_entity_list.insert(entry.second.begin(), entry.second.end());
					instruction_taint_entry.dependencies.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				if (result.mem_read_size != 0) {
					for (auto &mem_addr_dep: result.taint_sources.at(TAINT_ENTITY_MEM)) {
						update_deps_mem_addr_status(mem_addr_dep, instruction_taint_entry);
					}
					instruction_taint_entry.mem_read_size += result.mem_read_size;
					instruction_taint_entry.has_memory_read = true;
				}
				// Mark this register as modified by this instruction for updating register setter later
				modified_regs.emplace(sink.reg_offset);
				break;
			}
			case Ist_WrTmp:
			{
				taint_entity_t sink;
				std::unordered_set<taint_entity_t> srcs;

				sink.entity_type = TAINT_ENTITY_TMP;
				sink.instr_addr = curr_instr_addr;
				sink.tmp_id = stmt->Ist.WrTmp.tmp;
				auto sink_type = vex_block->tyenv->types[sink.tmp_id];
				if (sink_type == Ity_I1) {
					sink.value_size = 0;
				}
				else {
					sink.value_size = sizeofIRType(sink_type);
				}
				auto result = process_vex_expr(stmt->Ist.WrTmp.data, vex_block->tyenv, curr_instr_addr, false);
				if (result.has_unsupported_expr) {
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
					break;
				}
				// Store VEX temp dependencies details
				auto vex_temp_dep_data = std::make_pair(curr_instr_addr, result.taint_sources.at(TAINT_ENTITY_TMP));
				auto &vex_temp_ite_deps = result.ite_cond_entities.at(TAINT_ENTITY_TMP);
				vex_temp_dep_data.second.insert(vex_temp_ite_deps.begin(), vex_temp_ite_deps.end());
				for (auto &mem_taint_source: result.taint_sources.at(TAINT_ENTITY_MEM)) {
					for (auto &mem_ref_entity: mem_taint_source.mem_ref_entity_list) {
						instruction_taint_entry.dependencies.at(mem_ref_entity.entity_type).emplace(mem_ref_entity);
						if (mem_ref_entity.entity_type ==TAINT_ENTITY_TMP) {
							vex_temp_dep_data.second.emplace(mem_ref_entity);
						}
					}
				}
				block_taint_entry.vex_temp_deps.emplace(sink, vex_temp_dep_data);
				// Flatten list of taint sources and also save them as dependencies of instruction
				for (auto &entry: result.taint_sources) {
					srcs.insert(entry.second.begin(), entry.second.end());
					instruction_taint_entry.dependencies.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				instruction_taint_entry.taint_sink_src_map.emplace_back(sink, srcs);
				if (result.mem_read_size != 0) {
					for (auto &mem_addr_dep: result.taint_sources.at(TAINT_ENTITY_MEM)) {
						update_deps_mem_addr_status(mem_addr_dep, instruction_taint_entry);
					}
					instruction_taint_entry.mem_read_size += result.mem_read_size;
					instruction_taint_entry.has_memory_read = true;
				}
				// Store ITE condition entities. Also, store them as dependencies of instruction.
				for (auto &entry: result.ite_cond_entities) {
					instruction_taint_entry.ite_cond_entity_list.insert(entry.second.begin(), entry.second.end());
					instruction_taint_entry.dependencies.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				break;
			}
			case Ist_Store:
			{
				taint_entity_t sink;
				std::unordered_set<taint_entity_t> srcs;

				sink.entity_type = TAINT_ENTITY_MEM;
				sink.instr_addr = curr_instr_addr;
				auto result = process_vex_expr(stmt->Ist.Store.addr, vex_block->tyenv, curr_instr_addr, false);
				if (result.has_unsupported_expr) {
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
					break;
				}
				// TODO: What if memory addresses have ITE expressions in them?
				for (auto &entry: result.taint_sources) {
					sink.mem_ref_entity_list.insert(sink.mem_ref_entity_list.end(), entry.second.begin(), entry.second.end());
					instruction_taint_entry.dependencies.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				instruction_taint_entry.mem_read_size += result.mem_read_size;
				instruction_taint_entry.has_memory_read |= (result.mem_read_size != 0);

				result = process_vex_expr(stmt->Ist.Store.data, vex_block->tyenv, curr_instr_addr, false);
				if (result.has_unsupported_expr) {
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
					break;
				}
				sink.value_size = result.value_size;
				instruction_taint_entry.mem_write_size += result.value_size;
				// Flatten list of taint sources and also save them as dependencies of instruction
				for (auto &entry: result.taint_sources) {
					srcs.insert(entry.second.begin(), entry.second.end());
					instruction_taint_entry.dependencies.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				instruction_taint_entry.taint_sink_src_map.emplace_back(sink, srcs);
				if (result.mem_read_size != 0) {
					for (auto &mem_addr_dep: result.taint_sources.at(TAINT_ENTITY_MEM)) {
						update_deps_mem_addr_status(mem_addr_dep, instruction_taint_entry);
					}
					instruction_taint_entry.mem_read_size += result.mem_read_size;
					instruction_taint_entry.has_memory_read = true;
				}

				// Store ITE condition entities. Also, store them as dependencies of instruction.
				for (auto &entry: result.ite_cond_entities) {
					instruction_taint_entry.ite_cond_entity_list.insert(entry.second.begin(), entry.second.end());
					instruction_taint_entry.dependencies.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				break;
			}
			case Ist_Exit:
			{
				auto result = process_vex_expr(stmt->Ist.Exit.guard, vex_block->tyenv, curr_instr_addr, true);
				if (result.has_unsupported_expr) {
					block_taint_entry.has_unsupported_stmt_or_expr_type = true;
					block_taint_entry.unsupported_stmt_stop_reason = result.unsupported_expr_stop_reason;
					break;
				}
				for (auto &entry: result.taint_sources) {
					block_taint_entry.exit_stmt_guard_expr_deps.insert(entry.second.begin(), entry.second.end());
				}
				block_taint_entry.exit_stmt_instr_addr = curr_instr_addr;
				if (result.mem_read_size != 0) {
					for (auto &mem_addr_dep: result.taint_sources.at(TAINT_ENTITY_MEM)) {
						update_deps_mem_addr_status(mem_addr_dep, instruction_taint_entry);
					}
					instruction_taint_entry.mem_read_size += result.mem_read_size;
					instruction_taint_entry.has_memory_read = true;
				}
				break;
			}
			case Ist_IMark:
			{
				// Save dependencies of previous instruction and clear it
				if (started_processing_instructions) {
					for (auto &dep: instruction_taint_entry.dependencies.at(TAINT_ENTITY_REG)) {
						auto entry = last_reg_modifier_instr.find(dep.reg_offset);
						if (entry != last_reg_modifier_instr.end()) {
							instruction_taint_entry.dep_reg_modifier_addr.emplace(dep.reg_offset, entry->second);
						}
						else {
							instruction_taint_entry.unmodified_dep_regs.emplace(dep.reg_offset, dep.value_size);
						}
					}
					// Update last modified instruction address for registers modified by this instruction
					for (auto &modified_reg: modified_regs) {
						auto last_modifier_entry = last_reg_modifier_instr.find(modified_reg);
						if (last_modifier_entry == last_reg_modifier_instr.end()) {
							last_reg_modifier_instr.emplace(modified_reg, curr_instr_addr);
						}
						else {
							last_modifier_entry->second = curr_instr_addr;
						}
					}
					modified_regs.clear();
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
				if (strstr(stmt->Ist.Dirty.details->cee->name, "CPUID")) {
					block_taint_entry.has_cpuid_instr = true;
				}
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
	// Process block default exit target
	auto block_next_taint_sources = process_vex_expr(vex_block->next, vex_block->tyenv, curr_instr_addr, false);
	if (block_next_taint_sources.has_unsupported_expr) {
		block_taint_entry.has_unsupported_stmt_or_expr_type = true;
		block_taint_entry.unsupported_stmt_stop_reason = block_next_taint_sources.unsupported_expr_stop_reason;
	}
	else {
		for (auto &entry: block_next_taint_sources.taint_sources) {
			block_taint_entry.block_next_entities.insert(entry.second.begin(), entry.second.end());
			instruction_taint_entry.dependencies.at(entry.first).insert(entry.second.begin(), entry.second.end());
		}
		if (block_next_taint_sources.mem_read_size != 0) {
			for (auto &mem_addr_dep: block_next_taint_sources.taint_sources.at(TAINT_ENTITY_MEM)) {
				update_deps_mem_addr_status(mem_addr_dep, instruction_taint_entry);
			}
			instruction_taint_entry.mem_read_size += block_next_taint_sources.mem_read_size;
			instruction_taint_entry.has_memory_read = true;
		}
	}
	// Save register dependencies' info
	for (auto &dep: instruction_taint_entry.dependencies.at(TAINT_ENTITY_REG)) {
		auto entry = last_reg_modifier_instr.find(dep.reg_offset);
		if (entry != last_reg_modifier_instr.end()) {
			instruction_taint_entry.dep_reg_modifier_addr.emplace(dep.reg_offset, entry->second);
		}
		else {
			instruction_taint_entry.unmodified_dep_regs.emplace(dep.reg_offset, dep.value_size);
		}
	}
	// Save last instruction's entry
	block_taint_entry.block_instrs_taint_data_map.emplace(curr_instr_addr, instruction_taint_entry);
	block_taint_cache.emplace(address, block_taint_entry);
	return;
}

std::set<instr_details_t> State::get_list_of_dep_instrs(const instr_details_t &instr) const {
	std::set<instr_details_t> instrs;
	for (auto &dep_instr: instr.instr_deps) {
		auto result = get_list_of_dep_instrs(dep_instr);
		instrs.insert(result.begin(), result.end());
		instrs.insert(dep_instr);
	}
	return instrs;
}

void State::get_register_value(uint64_t vex_reg_offset, uint8_t *out_reg_value) const {
	// Check if VEX register is actually a CPU flag
	auto cpu_flags_entry = cpu_flags.find(vex_reg_offset);
	if (cpu_flags_entry != cpu_flags.end()) {
		uint64_t reg_value;
		uc_reg_read(uc, cpu_flags_entry->second.first, &reg_value);
		reg_value &= cpu_flags_entry->second.second;
		if (reg_value == 0) {
			memset(out_reg_value, 0, MAX_REGISTER_BYTE_SIZE);
		}
		else {
			// The flag is not 0 so we shift right until first non-zero bit is in LSB so that value of flag register
			// will be set correctly when re-executing
			for (int i = 1; i < MAX_REGISTER_BYTE_SIZE && (reg_value & 1 == 0); i++) {
				reg_value >>= i;
			}
			memcpy(out_reg_value, (uint8_t *)&reg_value, MAX_REGISTER_BYTE_SIZE);
		}
	}
	else {
		uc_reg_read(uc, vex_to_unicorn_map.at(vex_reg_offset).first, out_reg_value);
	}
	return;
}

// Returns a pair (taint sources, list of taint entities in ITE condition expression)
processed_vex_expr_t State::process_vex_expr(IRExpr *expr, IRTypeEnv *vex_block_tyenv, address_t instr_addr, bool is_exit_stmt) {
	processed_vex_expr_t result;
	result.reset();
	switch (expr->tag) {
		case Iex_RdTmp:
		{
			taint_entity_t taint_entity;
			taint_entity.entity_type = TAINT_ENTITY_TMP;
			taint_entity.tmp_id = expr->Iex.RdTmp.tmp;
			taint_entity.instr_addr = instr_addr;
			taint_entity.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);
			result.taint_sources.at(TAINT_ENTITY_TMP).emplace(taint_entity);
			result.value_size = taint_entity.value_size;
			break;
		}
		case Iex_Get:
		{
			taint_entity_t taint_entity;
			taint_entity.entity_type = TAINT_ENTITY_REG;
			taint_entity.reg_offset = expr->Iex.Get.offset;
			taint_entity.instr_addr = instr_addr;
			taint_entity.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);
			result.taint_sources.at(TAINT_ENTITY_REG).emplace(taint_entity);
			result.value_size = taint_entity.value_size;
			break;
		}
		case Iex_Unop:
		{
			auto temp = process_vex_expr(expr->Iex.Unop.arg, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;
			result.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);;
			break;
		}
		case Iex_Binop:
		{
			auto temp = process_vex_expr(expr->Iex.Binop.arg1, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;

			temp = process_vex_expr(expr->Iex.Binop.arg2, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;
			result.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);;
			break;
		}
		case Iex_Triop:
		{
			auto temp = process_vex_expr(expr->Iex.Triop.details->arg1, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;

			temp = process_vex_expr(expr->Iex.Triop.details->arg2, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;

			temp = process_vex_expr(expr->Iex.Triop.details->arg3, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;
			result.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);
			break;
		}
		case Iex_Qop:
		{
			auto temp = process_vex_expr(expr->Iex.Qop.details->arg1, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;

			temp = process_vex_expr(expr->Iex.Qop.details->arg2, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;

			temp = process_vex_expr(expr->Iex.Qop.details->arg3, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;

			temp = process_vex_expr(expr->Iex.Qop.details->arg4, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;
			result.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);
			break;
		}
		case Iex_ITE:
		{
			// We store the taint entities in the condition for ITE separately in order to check
			// if condition is symbolic and stop concrete execution if it is. However for VEX
			// exit statement, we don't need to store it separately since we process only the
			// guard condition for Exit statements
			auto temp = process_vex_expr(expr->Iex.ITE.cond, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			if (is_exit_stmt) {
				for (auto &entry: temp.taint_sources) {
					result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				for (auto &entry: temp.ite_cond_entities) {
					result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
			}
			else {
				for (auto &entry: temp.taint_sources) {
					result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				for (auto &entry: temp.ite_cond_entities) {
					result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
			}
			result.mem_read_size += temp.mem_read_size;

			temp = process_vex_expr(expr->Iex.ITE.iffalse, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;

			temp = process_vex_expr(expr->Iex.ITE.iftrue, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			for (auto &entry: temp.taint_sources) {
				result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			for (auto &entry: temp.ite_cond_entities) {
				result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
			}
			result.mem_read_size += temp.mem_read_size;
			result.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);
			break;
		}
		case Iex_CCall:
		{
			IRExpr **ccall_args = expr->Iex.CCall.args;
			for (auto i = 0; ccall_args[i]; i++) {
				auto temp = process_vex_expr(ccall_args[i], vex_block_tyenv, instr_addr, false);
				if (temp.has_unsupported_expr) {
					result.has_unsupported_expr = true;
					result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
					break;
				}
				for (auto &entry: temp.taint_sources) {
					result.taint_sources.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				for (auto &entry: temp.ite_cond_entities) {
					result.ite_cond_entities.at(entry.first).insert(entry.second.begin(), entry.second.end());
				}
				result.mem_read_size += temp.mem_read_size;
			}
			result.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);
			break;
		}
		case Iex_Load:
		{
			auto temp = process_vex_expr(expr->Iex.Load.addr, vex_block_tyenv, instr_addr, false);
			if (temp.has_unsupported_expr) {
				result.has_unsupported_expr = true;
				result.unsupported_expr_stop_reason = temp.unsupported_expr_stop_reason;
				break;
			}
			// TODO: What if memory addresses have ITE expressions in them?
			taint_entity_t source;
			source.entity_type = TAINT_ENTITY_MEM;
			for (auto &entry: temp.taint_sources) {
				source.mem_ref_entity_list.insert(source.mem_ref_entity_list.end(), entry.second.begin(), entry.second.end());
			}
			source.instr_addr = instr_addr;
			result.taint_sources.at(TAINT_ENTITY_MEM).emplace(source);
			// Calculate number of bytes read. unicorn sometimes triggers read hook multiple times for the same read
			result.mem_read_size += temp.mem_read_size;
			// TODO: Will there be a 1 bit read from memory?
			auto load_size = sizeofIRType(expr->Iex.Load.ty);
			result.mem_read_size += load_size;
			result.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);
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
		{
			result.value_size = get_vex_expr_result_size(expr, vex_block_tyenv);
			break;
		}
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
taint_status_result_t State::get_final_taint_status(const std::unordered_set<taint_entity_t> &taint_sources) const {
	bool is_symbolic = false;
	for (auto &taint_source: taint_sources) {
		if (taint_source.entity_type == TAINT_ENTITY_NONE) {
			continue;
		}
		else if ((taint_source.entity_type == TAINT_ENTITY_REG) &&
		  (is_symbolic_register(taint_source.reg_offset, taint_source.value_size))) {
			  // Register is symbolic. Continue checking for read from symbolic address
			  is_symbolic = true;
		}
		else if ((taint_source.entity_type == TAINT_ENTITY_TMP) && (is_symbolic_temp(taint_source.tmp_id))) {
			// Temp is symbolic. Continue checking for read from a symbolic address
			is_symbolic = true;
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
					mem_read_result = block_mem_reads_map.at(taint_source.instr_addr);
				}
				catch (std::out_of_range const&) {
					assert(false && "[sim_unicorn] Taint sink depends on a read not executed yet! This should not happen!");
				}
				is_symbolic = mem_read_result.is_mem_read_symbolic;
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
taint_status_result_t State::get_final_taint_status(const std::vector<taint_entity_t> &taint_sources) const {
	std::unordered_set<taint_entity_t> taint_sources_set(taint_sources.begin(), taint_sources.end());
	return get_final_taint_status(taint_sources_set);
}

int32_t State::get_vex_expr_result_size(IRExpr *expr, IRTypeEnv* tyenv) const {
	auto expr_type = typeOfIRExpr(tyenv, expr);
	if (expr_type == Ity_I1) {
		return 0;
	}
	return sizeofIRType(expr_type);
}

bool State::is_cpuid_in_block(address_t block_address, int32_t block_size) {
	bool found_cpuid_bytes = false;
	bool has_cpuid_instr = false;
	int32_t real_size;
	int32_t i;
	const uint8_t cpuid_bytes[] = {0xf, 0xa2};

	auto block_entry = block_taint_cache.find(block_address);
	if (block_entry != block_taint_cache.end()) {
		// VEX statements of block have been processed already.
		return block_entry->second.has_cpuid_instr;
	}

	// Assume block size is MAX_BB_SIZE if block size is report as 0.
	// See State::step
	real_size = block_size == 0 ? MAX_BB_SIZE : block_size;
	std::unique_ptr<uint8_t[]> instructions(new uint8_t[real_size]);
	uc_mem_read(this->uc, block_address, instructions.get(), real_size);
	// Test 1: Look for bytes corresponding to the cpuid instruction(0fa2) in the block. Naive linear search for two
	// byte pattern
	i = 0;
	while (i < real_size) {
		if (instructions[i] == cpuid_bytes[0]) {
			if (instructions[i + 1] == cpuid_bytes[1]) {
				found_cpuid_bytes = true;
				break;
			}
			i ++;
		}
		i++;
	}
	if (!found_cpuid_bytes) {
		return false;
	}
	// Test 2: Verify using VEX statements of the block. If we reached here, then block is certainly not already lifted
	// to VEX. Let's process them.
	auto vex_lift_result = lift_block(block_address, real_size);
	if ((vex_lift_result == NULL) || (vex_lift_result->size == 0)) {
		// Since VEX lift failed, we cannot verify if cpuid is present. Assume it could exit and stop emulation.
		stop(STOP_VEX_LIFT_FAILED);
		return true;
	}
	process_vex_block(vex_lift_result->irsb, block_address);
	block_entry = block_taint_cache.find(block_address);
	has_cpuid_instr = block_entry->second.has_cpuid_instr;
	if (block_size == 0) {
		// Remove block from block taint cache since size reported by unicorn is 0
		block_taint_cache.erase(block_entry);
	}
	return has_cpuid_instr;
}

VEXLiftResult* State::lift_block(address_t block_address, int32_t block_size) {
	// Using the optimized VEX block causes write-write conflicts: an older value becomes current value because the
	// corresponding instruction is executed as dependency of a symbolic instruction to set some VEX temps. Thus, we use
	// the unoptimized VEX block.
	VexRegisterUpdates pxControl = VexRegUpdLdAllregsAtEachInsn;
	std::unique_ptr<uint8_t[]> instructions(new uint8_t[block_size]);
	address_t lift_address;

	if ((arch == UC_ARCH_ARM) && is_thumb_mode()) {
		lift_address = block_address | 1;
	}
	else {
		lift_address = block_address;
	}
	uc_mem_read(this->uc, lift_address, instructions.get(), block_size);
	return vex_lift(vex_guest, vex_archinfo, instructions.get(), lift_address, 99, block_size, 1, 0, 1, 1, 0,
	    pxControl, 0);
}

void State::mark_register_symbolic(vex_reg_offset_t reg_offset, int64_t reg_size) {
	// Mark register as symbolic in the state in current block
	if (is_blacklisted_register(reg_offset)) {
		return;
	}
	else if (cpu_flags.find(reg_offset) != cpu_flags.end()) {
		block_symbolic_registers.emplace(reg_offset);
		block_concrete_registers.erase(reg_offset);
	}
	else {
		for (auto i = 0; i < reg_size; i++) {
			block_symbolic_registers.emplace(reg_offset + i);
			block_concrete_registers.erase(reg_offset + i);
		}
	}
	return;
}

void State::mark_temp_symbolic(vex_tmp_id_t temp_id) {
	// Mark VEX temp as symbolic in current block
	block_symbolic_temps.emplace(temp_id);
	return;
}

void State::mark_register_concrete(vex_reg_offset_t reg_offset, int64_t reg_size) {
	// Mark register as concrete in the current block
	if (is_blacklisted_register(reg_offset)) {
		return;
	}
	else if (cpu_flags.find(reg_offset) != cpu_flags.end()) {
		block_symbolic_registers.erase(reg_offset);
		block_concrete_registers.emplace(reg_offset);
	}
	else {
		for (auto i = 0; i < reg_size; i++) {
			block_symbolic_registers.erase(reg_offset + i);
			block_concrete_registers.emplace(reg_offset + i);
		}
	}
	return;
}

bool State::is_symbolic_register(vex_reg_offset_t reg_offset, int64_t reg_size) const {
	// We check if this register is symbolic or concrete in the block level taint statuses since
	// those are more recent. If not found in either, check the state's symbolic register list.
	// TODO: Is checking only first byte of artificial and blacklisted registers to determine if they are symbolic fine
	// or should all be checked?
	if ((cpu_flags.find(reg_offset) != cpu_flags.end()) || (artificial_vex_registers.count(reg_offset) > 0)
	    || (blacklisted_registers.count(reg_offset) > 0)) {
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
	// The register is not a CPU flag and so we check every byte of the register
	for (auto i = 0; i < reg_size; i++) {
		// If any of the register's bytes are symbolic, we deem the register to be symbolic
		if (block_symbolic_registers.count(reg_offset + i) > 0) {
			return true;
		}
	}
	bool is_concrete = true;
	for (auto i = 0; i < reg_size; i++) {
		if (block_concrete_registers.count(reg_offset) == 0) {
			is_concrete = false;
			break;
		}
	}
	if (is_concrete) {
		// All bytes of register are concrete and so the register is concrete
		return false;
	}
	// If we reach here, it means that the register is not marked symbolic or concrete in the block
	// level taint status tracker. We check the state's symbolic register list.
	for (auto i = 0; i < reg_size; i++) {
		if (symbolic_registers.count(reg_offset + i) > 0) {
			return true;
		}
	}
	return false;
}

bool State::is_symbolic_temp(vex_tmp_id_t temp_id) const {
	return (block_symbolic_temps.count(temp_id) > 0);
}

void State::propagate_taints() {
	if (is_symbolic_tracking_disabled()) {
		// We're not checking symbolic registers so no need to propagate taints
		return;
	}
	auto& block_taint_entry = this->block_taint_cache.at(curr_block_details.block_addr);
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
		auto& curr_instr_taint_entry = instr_taint_data_entries_it->second;
		std::unordered_map<vex_reg_offset_t, int64_t> concrete_reg_deps;

		// Save list of register dependencies of current instruction which are concrete for slice computation later
		for (auto &reg_dep: curr_instr_taint_entry.dependencies.at(TAINT_ENTITY_REG)) {
			if (!is_symbolic_register(reg_dep.reg_offset, reg_dep.value_size)) {
				concrete_reg_deps.emplace(std::make_pair(reg_dep.reg_offset, reg_dep.value_size));
			}
		}
		block_instr_concrete_regs.emplace(curr_instr_addr, concrete_reg_deps);
		if (curr_instr_taint_entry.has_memory_read) {
			// Pause taint propagation to process the memory read and continue from instruction
			// after the memory read.
			taint_engine_stop_mem_read_instruction = curr_instr_addr;
			taint_engine_stop_mem_read_size = instr_taint_data_entries_it->second.mem_read_size;
			taint_engine_next_instr_address = std::next(instr_taint_data_entries_it)->first;
			return;
		}
		if ((symbolic_registers.size() == 0) && (block_symbolic_registers.size() == 0) && (block_symbolic_temps.size() == 0)) {
			// There are no symbolic registers so no taint to propagate. Mark any memory writes
			// as concrete and update slice of registers.
			if (curr_instr_taint_entry.mem_write_size != 0) {
				block_mem_writes_taint_data.emplace_back(curr_instr_addr, false, curr_instr_taint_entry.mem_write_size);
			}
			continue;
		}
		propagate_taint_of_one_instr(curr_instr_addr, curr_instr_taint_entry);
	}
	// If we reached here, execution has reached the end of the block
	if (!stopped) {
		if (curr_block_details.vex_lift_failed && ((symbolic_registers.size() > 0) || (block_symbolic_registers.size() > 0))) {
			// There are symbolic registers but VEX lift failed so we can't determine
			// status of guard condition
			stop(STOP_VEX_LIFT_FAILED);
			return;
		}
		else if (is_block_exit_guard_symbolic()) {
			if (handle_symbolic_conditions) {
				curr_block_details.has_symbolic_exit = true;
			}
			else {
				stop(STOP_SYMBOLIC_BLOCK_EXIT_CONDITION);
			}
		}
		else if (!handle_symbolic_conditions && is_block_next_target_symbolic()) {
			stop(STOP_SYMBOLIC_BLOCK_EXIT_TARGET);
		}
	}
	return;
}

void State::propagate_taint_of_mem_read_instr_and_continue(address_t read_address, int read_size) {
	memory_value_t memory_read_value;
	address_t curr_instr_addr;

	auto tainted = find_tainted(read_address, read_size);
	if (is_symbolic_tracking_disabled()) {
		if (tainted != -1) {
			// Symbolic register tracking is disabled but memory location has symbolic data.
			// We switch to VEX engine then.
			stop(STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED);
			return;
		}
		// We're not checking symbolic registers so no need to propagate taints
		return;
	}

	// Save info about the memory read
	memory_read_value.reset();
	memory_read_value.address = read_address;
	memory_read_value.size = read_size;
	if (tainted != -1) {
		memory_read_value.is_value_symbolic = true;
	}
	else {
		memory_read_value.is_value_symbolic = false;
		read_memory_value(read_address, read_size, memory_read_value.value, MAX_MEM_ACCESS_SIZE);
	}

	if (!memory_read_value.is_value_symbolic && !symbolic_read_in_progress && (symbolic_registers.size() == 0) &&
	    (block_symbolic_registers.size() == 0) && (block_symbolic_temps.size() == 0)) {
		// The value read from memory is concrete and there are no symbolic registers or VEX temps. No need to propagate
		// taint. Since we cannot rely on the unicorn engine to find out current instruction correctly, we simply save
		// the memory read value in a list for now and rebuild the map later if needed using instruction info from VEX
		// block
		block_mem_reads_data.emplace_back(memory_read_value);
		return;
	}

	if (block_taint_cache.find(curr_block_details.block_addr) == block_taint_cache.end()) {
		// The VEX statements of current block has not been processed yet. This means symbolic taint is being introduced
		// by this memory read. Let's process the block, rebuild its memory reads map and find the current instruction
		// address
		curr_block_details.vex_lift_result = lift_block(curr_block_details.block_addr, curr_block_details.block_size);
		if ((curr_block_details.vex_lift_result == NULL) || (curr_block_details.vex_lift_result->size == 0)) {
			// Failed to lift block to VEX.
			if (memory_read_value.is_value_symbolic) {
				// Since we are processing VEX block for the first time, there are no symbolic registers/VEX temps.
				// Thus, it is sufficient to check if the value read from memory is symbolic.
				stop(STOP_VEX_LIFT_FAILED);
			}
			else {
				// There are no symbolic registers so let's attempt to execute the block.
				curr_block_details.vex_lift_failed = true;
			}
			return;
		}
		process_vex_block(curr_block_details.vex_lift_result->irsb, curr_block_details.block_addr);
	}
	auto& block_taint_entry = block_taint_cache.at(curr_block_details.block_addr);
	if (taint_engine_stop_mem_read_instruction != 0) {
		// Taint has been propagated and so we can rely on information from taint engine to find current instruction
		// address and hence update the block's memory reads map
		curr_instr_addr = taint_engine_stop_mem_read_instruction;
	}
	else {
		// Symbolic taint is being introduced by this memory read so we cannot rely on taint engine to find current
		// instruction address
		std::map<address_t, instruction_taint_entry_t>::iterator instr_entry_it = block_taint_entry.block_instrs_taint_data_map.begin();
		if (block_mem_reads_data.size() > 0) {
			// There are previous reads that need to be insert into block's memory reads map
			while (instr_entry_it != block_taint_entry.block_instrs_taint_data_map.end()) {
				if (instr_entry_it->second.has_memory_read) {
					mem_read_result_t mem_read_result;
					while (block_mem_reads_data.size() != 0) {
						auto &next_mem_read = block_mem_reads_data.front();
						mem_read_result.memory_values.emplace_back(next_mem_read);
						mem_read_result.is_mem_read_symbolic |= next_mem_read.is_value_symbolic;
						mem_read_result.read_size += next_mem_read.size;
						block_mem_reads_data.erase(block_mem_reads_data.begin());
						if (mem_read_result.read_size == instr_entry_it->second.mem_read_size) {
							block_mem_reads_map.emplace(instr_entry_it->first, mem_read_result);
							break;
						}
						else if (block_mem_reads_data.size() == 0) {
							// This entry is of a partial memory read for the instruction being processed.
							block_mem_reads_map.emplace(instr_entry_it->first, mem_read_result);
							break;
						}
					}
					if (block_mem_reads_data.size() == 0) {
						// All pending reads have been processed and inserted into the map
						if (block_mem_reads_map.at(instr_entry_it->first).read_size == instr_entry_it->second.mem_read_size) {
							// Update iterator since all reads for current instruction have been processed. We should
							// start searching for next instruction with memory read from successor of this instruction.
							instr_entry_it++;
						}
						break;
					}
				}
				instr_entry_it++;
			}
			if ((block_mem_reads_data.size() != 0) && (instr_entry_it == block_taint_entry.block_instrs_taint_data_map.end())) {
				// There are still some pending reads but all instructions in the block have been processed. Something
				// is wrong.
				assert(false && "There are pending memory reads to process but full block has been processed. This should not happen!");
			}
		}
		// Find next instruction with memory read
		while (!instr_entry_it->second.has_memory_read) {
			instr_entry_it++;
			if (instr_entry_it == block_taint_entry.block_instrs_taint_data_map.end()) {
				// Current read does not belong to any possible instruction in current block. This should not happen!
				assert(false && "Unable to identify instruction for current memory read. This should not happen!");
			}
		}
		curr_instr_addr = instr_entry_it->first;
		taint_engine_stop_mem_read_instruction = curr_instr_addr;
		taint_engine_stop_mem_read_size = instr_entry_it->second.mem_read_size;
		taint_engine_next_instr_address = std::next(instr_entry_it)->first;
	}
	auto mem_reads_map_entry = block_mem_reads_map.find(curr_instr_addr);
	if (mem_reads_map_entry == block_mem_reads_map.end()) {
		mem_read_result_t mem_read_result;
		mem_read_result.memory_values.emplace_back(memory_read_value);
		mem_read_result.is_mem_read_symbolic = memory_read_value.is_value_symbolic;
		mem_read_result.read_size = read_size;
		block_mem_reads_map.emplace(curr_instr_addr, mem_read_result);
	}
	else {
		auto &mem_read_entry = block_mem_reads_map.at(curr_instr_addr);
		mem_read_entry.memory_values.emplace_back(memory_read_value);
		mem_read_entry.is_mem_read_symbolic |= memory_read_value.is_value_symbolic;
		mem_read_entry.read_size += read_size;
	}

	// At this point the block's memory reads map has been rebuilt and we can propagate taint as before
	auto &mem_read_result = block_mem_reads_map.at(curr_instr_addr);
	if (curr_block_details.vex_lift_failed) {
		if (mem_read_result.is_mem_read_symbolic || (symbolic_registers.size() > 0)
			|| (block_symbolic_registers.size() > 0) || (block_symbolic_temps.size() > 0)) {
			// Either the memory value is symbolic or there are symbolic registers: thus, taint
			// status of registers could change. But since VEX lift failed, the taint relations
			// are not known and so we can't propagate taint. Stop concrete execution.
			stop(STOP_VEX_LIFT_FAILED);
			return;
		}
		else {
			// We cannot propagate taint since VEX lift failed and so we stop here. But, since
			// there are no symbolic values, we do need need to propagate taint.
			return;
		}
	}
	if (mem_read_result.read_size < taint_engine_stop_mem_read_size) {
		// There are more bytes to be read by this instruction. We do not propagate taint until bytes are read
		// Sometimes reads are split across multiple reads hooks in unicorn.
		// Also, remember that a symbolic value has been partially read from memory so that even if the rest of the
		// bytes to be read are concrete, taint will be propagated.
		symbolic_read_in_progress = true;
		return;
	}
	else if (mem_read_result.read_size > taint_engine_stop_mem_read_size) {
		// Somehow the read result has read more bytes than read operation should according to the VEX statements.
		// Likely a bug.
		assert(false && "Memory read operation has read more bytes than expected. This should not happen!");
	}

	// Mark read as complete
	symbolic_read_in_progress = false;

	// There are no more pending reads at this instruction. Now we can propagate taint.
	// This allows us to also handle cases when only some of the memory reads are symbolic: we treat all as symbolic
	// and overtaint.
	auto& instr_taint_data_entry = block_taint_entry.block_instrs_taint_data_map.at(curr_instr_addr);
	if (mem_read_result.is_mem_read_symbolic || (symbolic_registers.size() > 0) || (block_symbolic_registers.size() > 0) ||
	  block_symbolic_temps.size() > 0) {
		if (block_taint_entry.has_unsupported_stmt_or_expr_type) {
			// There are symbolic registers and/or memory read was symbolic and there are VEX
			// statements in block for which taint propagation is not supported.
			stop(block_taint_entry.unsupported_stmt_stop_reason);
			return;
		}
		propagate_taint_of_one_instr(curr_instr_addr, instr_taint_data_entry);
	}
	if (!stopped) {
		continue_propagating_taint();
	}
	return;
}

void State::propagate_taint_of_one_instr(address_t instr_addr, const instruction_taint_entry_t &instr_taint_entry) {
	instr_details_t instr_details;
	bool is_instr_symbolic;

	is_instr_symbolic = false;
	instr_details = compute_instr_details(instr_addr, instr_taint_entry);
	if (instr_details.has_symbolic_memory_dep) {
		is_instr_symbolic = true;
	}
	for (auto &taint_data_entry: instr_taint_entry.taint_sink_src_map) {
		taint_entity_t taint_sink = taint_data_entry.first;
		std::unordered_set<taint_entity_t> taint_srcs = taint_data_entry.second;
		if (taint_sink.entity_type == TAINT_ENTITY_MEM) {
			auto addr_taint_status = get_final_taint_status(taint_sink.mem_ref_entity_list);
			// Check if address written to is symbolic or is read from memory
			if (addr_taint_status != TAINT_STATUS_CONCRETE) {
				if (handle_symbolic_addrs) {
					is_instr_symbolic = true;
				}
				else {
					stop(STOP_SYMBOLIC_WRITE_ADDR);
					return;
				}
			}
			auto sink_taint_status = get_final_taint_status(taint_srcs);
			if (sink_taint_status == TAINT_STATUS_DEPENDS_ON_READ_FROM_SYMBOLIC_ADDR) {
				if (handle_symbolic_addrs) {
					is_instr_symbolic = true;
					sink_taint_status = TAINT_STATUS_SYMBOLIC;
					instr_details.has_read_from_symbolic_addr = true;
				}
				else {
					stop(STOP_SYMBOLIC_READ_ADDR);
					return;
				}
			}
			if (sink_taint_status == TAINT_STATUS_SYMBOLIC) {
				// Save the memory location written to be marked as symbolic in write hook
				block_mem_writes_taint_data.emplace_back(taint_sink.instr_addr, true, taint_sink.value_size);
				// Mark instruction as needing symbolic execution
				is_instr_symbolic = true;
			}
			else {
				// Save the memory location(s) written to be marked as concrete in the write
				// hook only if it is not a previously seen write
				block_mem_writes_taint_data.emplace_back(taint_sink.instr_addr, false, taint_sink.value_size);
			}
		}
		else if (taint_sink.entity_type != TAINT_ENTITY_NONE) {
			taint_status_result_t final_taint_status = get_final_taint_status(taint_srcs);
			if ((final_taint_status == TAINT_STATUS_DEPENDS_ON_READ_FROM_SYMBOLIC_ADDR)) {
				if (handle_symbolic_addrs) {
					is_instr_symbolic = true;
					final_taint_status = TAINT_STATUS_SYMBOLIC;
					instr_details.has_read_from_symbolic_addr = true;
				}
				else {
					stop(STOP_SYMBOLIC_READ_ADDR);
					return;
				}
			}
			else if (final_taint_status != TAINT_STATUS_CONCRETE) {
				if ((taint_sink.entity_type == TAINT_ENTITY_REG) && (taint_sink.reg_offset == arch_pc_reg_vex_offset())) {
					stop(STOP_SYMBOLIC_PC);
					return;
				}

				// Mark instruction as needing symbolic execution
				is_instr_symbolic = true;

				// Mark sink as symbolic
				if (taint_sink.entity_type == TAINT_ENTITY_REG) {
					mark_register_symbolic(taint_sink.reg_offset, taint_sink.value_size);
				}
				else {
					mark_temp_symbolic(taint_sink.tmp_id);
				}
			}
			else if ((taint_sink.entity_type == TAINT_ENTITY_REG) && (taint_sink.reg_offset != arch_pc_reg_vex_offset())) {
				// Mark register as concrete since none of it's dependencies are symbolic.
				mark_register_concrete(taint_sink.reg_offset, taint_sink.value_size);
			}
		}
		auto ite_cond_taint_status = get_final_taint_status(instr_taint_entry.ite_cond_entity_list);
		if (ite_cond_taint_status != TAINT_STATUS_CONCRETE) {
			is_instr_symbolic = true;
		}
	}
	if (is_instr_symbolic) {
		if (instr_details.has_symbolic_memory_dep) {
			for (auto &mem_value: block_mem_reads_map.at(instr_addr).memory_values) {
				if (mem_value.is_value_symbolic) {
					auto elem = symbolic_mem_deps.find(mem_value.address);
					if (elem == symbolic_mem_deps.end()) {
						symbolic_mem_deps.emplace(mem_value.address, mem_value.size);
					}
					else if (elem->second < mem_value.size) {
						elem->second = mem_value.size;
					}
				}
			}
		}
		curr_block_details.symbolic_instrs.emplace_back(instr_details);
	}
	return;
}

instr_details_t State::compute_instr_details(address_t instr_addr, const instruction_taint_entry_t &instr_taint_entry) {
	instr_details_t instr_details;
	instr_details.instr_addr = instr_addr;
	if (instr_taint_entry.has_memory_read) {
		auto mem_read_result = block_mem_reads_map.at(instr_addr);
		if (!mem_read_result.is_mem_read_symbolic) {
			instr_details.has_concrete_memory_dep = true;
			instr_details.has_symbolic_memory_dep = false;
		}
		else {
			instr_details.has_concrete_memory_dep = false;
			instr_details.has_symbolic_memory_dep = true;
		}
	}
	else {
		instr_details.has_concrete_memory_dep = false;
		instr_details.has_symbolic_memory_dep = false;
	}
	return instr_details;
}

void State::read_memory_value(address_t address, uint64_t size, uint8_t *result, size_t result_size) const {
	memset(result, 0, result_size);
	uc_mem_read(uc, address, result, size);
	return;
}

void State::start_propagating_taint() {
	address_t block_address = curr_block_details.block_addr;
	int32_t block_size = curr_block_details.block_size;
	curr_block_details.block_trace_ind = executed_blocks_count;
	if (is_symbolic_tracking_disabled()) {
		// We're not checking symbolic registers so no need to propagate taints
		return;
	}
	if ((arch == UC_ARCH_ARM) && (block_taint_cache.find(block_address) == block_taint_cache.end())) {
		// Block was not lifted and processed before. So it could end in syscall
		curr_block_details.vex_lift_result = lift_block(block_address, block_size);
		if ((curr_block_details.vex_lift_result == NULL) || (curr_block_details.vex_lift_result->size == 0)) {
			// Failed to lift block to VEX. We don't execute the block because it could end in a syscall.
			stop(STOP_VEX_LIFT_FAILED);
			return;
		}
		if (curr_block_details.vex_lift_result->irsb->jumpkind == Ijk_Sys_syscall) {
			// This block invokes a syscall. For now, such blocks are handled by VEX engine.
			stop(STOP_SYSCALL_ARM);
			return;
		}
	}
	if ((arch == UC_ARCH_X86) && is_cpuid_in_block(block_address, block_size)) {
		// Check if emulation was stopped; could be if VEX lift failed
		if (!stopped) {
			stop(STOP_X86_CPUID);
		}
		return;
	}
	block_symbolic_temps.clear();
	block_start_reg_values.clear();
	// Save value of all registers in case some instruction touches symbolic data and needs to be re-executed
	for (auto &reg_offset: vex_to_unicorn_map) {
		register_value_t reg_value;
		reg_value.offset = reg_offset.first;
		reg_value.size = reg_offset.second.second;
		get_register_value(reg_value.offset, reg_value.value);
		block_start_reg_values.emplace(reg_value.offset, reg_value);
	}
	for (auto &cpu_flag: cpu_flags) {
		register_value_t flag_value;
		flag_value.offset = cpu_flag.first;
		get_register_value(cpu_flag.first, flag_value.value);
		block_start_reg_values.emplace(flag_value.offset, flag_value);
	}
	if (symbolic_registers.size() != 0) {
		if (block_taint_cache.find(block_address) == block_taint_cache.end()) {
			// Compute and cache taint sink-source relations for this block since there are symbolic registers.
			if (curr_block_details.vex_lift_result == NULL) {
				curr_block_details.vex_lift_result = lift_block(block_address, block_size);
				if ((curr_block_details.vex_lift_result == NULL) || (curr_block_details.vex_lift_result->size == 0)) {
					// Failed to lift block to VEX.
					if (symbolic_registers.size() > 0) {
						// There are symbolic registers but VEX lift failed so we can't propagate taint
						stop(STOP_VEX_LIFT_FAILED);
					}
					else {
						// There are no symbolic registers so let's attempt to execute the block.
						curr_block_details.vex_lift_failed = true;
					}
					return;
				}
			}
			process_vex_block(curr_block_details.vex_lift_result->irsb, block_address);
		}
		taint_engine_next_instr_address = block_address;
		propagate_taints();
	}
	return;
}

void State::continue_propagating_taint() {
	if (is_symbolic_tracking_disabled()) {
		// We're not checking symbolic registers so no need to propagate taints
		return;
	}
	if (curr_block_details.vex_lift_failed) {
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

void State::save_concrete_memory_deps(instr_details_t &instr) {
	if (instr.has_concrete_memory_dep || (instr.has_symbolic_memory_dep && !instr.has_read_from_symbolic_addr)) {
		archived_memory_values.emplace_back(block_mem_reads_map.at(instr.instr_addr).memory_values);
		instr.memory_values = &(archived_memory_values.back()[0]);
		instr.memory_values_count = archived_memory_values.back().size();
	}
	std::queue<std::set<instr_details_t>::iterator> instrs_to_process;
	for (auto it = instr.instr_deps.begin(); it != instr.instr_deps.end(); it++) {
		instrs_to_process.push(it);
	}
	while (!instrs_to_process.empty()) {
		auto &curr_instr = instrs_to_process.front();
		if (curr_instr->has_concrete_memory_dep) {
			archived_memory_values.emplace_back(block_mem_reads_map.at(curr_instr->instr_addr).memory_values);
			curr_instr->memory_values = &(archived_memory_values.back()[0]);
			curr_instr->memory_values_count = archived_memory_values.back().size();
		}
		instrs_to_process.pop();
		for (auto it = curr_instr->instr_deps.begin(); it != curr_instr->instr_deps.end(); *it++) {
			instrs_to_process.push(it);
		}
	}
	return;
}

bool State::is_block_exit_guard_symbolic() const {
	auto& block_taint_entry = block_taint_cache.at(curr_block_details.block_addr);
	auto block_exit_guard_taint_status = get_final_taint_status(block_taint_entry.exit_stmt_guard_expr_deps);
	return (block_exit_guard_taint_status != TAINT_STATUS_CONCRETE);
}

bool State::is_block_next_target_symbolic() const {
	auto& block_taint_entry = block_taint_cache.at(curr_block_details.block_addr);
	auto block_next_target_taint_status = get_final_taint_status(block_taint_entry.block_next_entities);
	return (block_next_target_taint_status != TAINT_STATUS_CONCRETE);
}

bool State::check_symbolic_stack_mem_dependencies_liveness() const {
	// Stop concrete execution if a stack frame was deallocated and if any symbolic memory dependencies were present
	// on that stack frame.
	address_t curr_stack_top_addr = get_stack_pointer();
	if (curr_stack_top_addr <= prev_stack_top_addr) {
		// No change in stack frame and so no need to perform a liveness check.
		// TODO: What is stack growth direction is different?
		return true;
	}
	for (auto &symbolic_mem_dep: symbolic_mem_deps) {
		if ((curr_stack_top_addr > symbolic_mem_dep.first) && (symbolic_mem_dep.first > prev_stack_top_addr)) {
			// A symbolic memory value that this symbolic instruction depends on is no longer on the stack
			// and could be overwritten by future code. We stop concrete execution here to avoid that.
			return false;
		}
	}
	return true;
}

void State::set_curr_block_details(address_t block_address, int32_t block_size) {
	curr_block_details.block_addr = block_address;
	curr_block_details.block_size = block_size;
	return;
}

address_t State::get_instruction_pointer() const {
	address_t out = 0;
	int reg = arch_pc_reg();
	if (reg == -1) {
		out = 0;
	} else {
		uc_reg_read(uc, reg, &out);
	}

	return out;
}

address_t State::get_stack_pointer() const {
	address_t out = 0;
	int reg = arch_sp_reg();
	if (reg == -1) {
		out = 0;
	} else {
		uc_reg_read(uc, reg, &out);
	}

	return out;
}

void State::fd_init_bytes(uint64_t fd, char *bytes, uint64_t len, uint64_t read_pos) {
	fd_details.emplace(fd, fd_data(bytes, len, read_pos));
	return;
}

uint64_t State::fd_read(uint64_t fd, char *buf, uint64_t count) {
	auto &fd_det = fd_details.at(fd);
	if (fd_det.curr_pos >= fd_det.len) {
		// No more bytes to read
		return 0;
	}
	// Truncate count of bytes to read if request exceeds number left in the "stream"
	auto actual_count = std::min(count, fd_det.len - fd_det.curr_pos);
	memcpy(buf, fd_det.bytes + fd_det.curr_pos, actual_count);
	fd_det.curr_pos += actual_count;
	return actual_count;
}

void State::init_random_bytes(uint64_t *values, uint64_t *sizes, uint64_t count) {
	for (auto i = 0; i < count; i++) {
		random_bytes.emplace_back(values[i], sizes[i]);
	}
	return;
}

// CGC syscall handlers

void State::perform_cgc_random() {
	uint32_t buf, count, rnd_bytes;
	uint64_t number_of_items_to_process, actual_count, next_write_offset;
	char *rand_bytes;

	uc_reg_read(uc, UC_X86_REG_EBX, &buf);
	uc_reg_read(uc, UC_X86_REG_ECX, &count);
	uc_reg_read(uc, UC_X86_REG_EDX, &rnd_bytes);

	if (count == 0) {
		if (rnd_bytes != 0) {
			handle_write(rnd_bytes, 4, true);
			if (stopped) {
				return;
			}
			uc_mem_write(uc, rnd_bytes, &count, 4);
		}
		uc_reg_write(uc, UC_X86_REG_EAX, &count);
		interrupt_handled = true;
		syscall_count++;
		return;
	}

	number_of_items_to_process = 0;
	actual_count = 0;
	for (auto &val: random_bytes) {
		if (actual_count == count) {
			break;
		}
		actual_count += val.second;
		number_of_items_to_process++;
	}
	assert((actual_count == count));
	rand_bytes = (char *)malloc(actual_count);
	next_write_offset = 0;
	for (auto i = 0; i < number_of_items_to_process; i++) {
		std::reverse_copy((char *)&(random_bytes[i].first), (char *)&(random_bytes[i].first) + random_bytes[i].second, rand_bytes + next_write_offset);
		next_write_offset += random_bytes[i].second;
	}
	for (auto i = 0; i < number_of_items_to_process; i++) {
		random_bytes.erase(random_bytes.begin());
	}
	handle_write(buf, actual_count, true, true);
	if (stopped) {
		free(rand_bytes);
		return;
	}
	uc_mem_write(uc, buf, rand_bytes, actual_count);
	free(rand_bytes);
	if (rnd_bytes != 0) {
		handle_write(rnd_bytes, 4, true);
		if (stopped) {
			return;
		}
		uc_mem_write(uc, rnd_bytes, &actual_count, 4);
	}
	next_write_offset = 0;
	uc_reg_write(uc, UC_X86_REG_EAX, &next_write_offset);
	step(cgc_random_bbl, 0, false);
	commit();
	if (actual_count > 0) {
		// Save a block with an instruction to track that the random syscall needs to be re-executed. The instruction
		// data is used only to work with existing mechanism to return data to python.
		// Save all non-symbolic register arguments needed for syscall.
		block_details_t block_for_random;
		block_for_random.block_addr = cgc_random_bbl;
		block_for_random.block_size = 0;
		block_for_random.block_trace_ind = executed_blocks_count;
		block_for_random.has_symbolic_exit = false;
		instr_details_t instr_for_random;
		// First argument: ebx
		register_value_t reg_val;
		if (!is_symbolic_register(20, 4)) {
			reg_val.offset = 20;
			reg_val.size = 4;
			get_register_value(reg_val.offset, reg_val.value);
			instr_for_random.reg_deps.emplace(reg_val);
		}
		// Second argument: ecx
		if (!is_symbolic_register(12, 4)) {
			reg_val.offset = 12;
			reg_val.size = 4;
			get_register_value(reg_val.offset, reg_val.value);
			instr_for_random.reg_deps.emplace(reg_val);
		}
		block_for_random.symbolic_instrs.emplace_back(instr_for_random);
		blocks_with_symbolic_instrs.emplace_back(block_for_random);
	}
	interrupt_handled = true;
	syscall_count++;
	return;
}

void State::perform_cgc_receive() {
	uint32_t fd, buf, count, rx_bytes;

	uc_reg_read(uc, UC_X86_REG_EBX, &fd);
	if (fd > 2) {
		// Ignore any fds > 2
		return;
	}

	if (fd_details.count(fd) == 0) {
		// fd stream has not been initialized in native interface. Can't perform receive.
		return;
	}

	uc_reg_read(uc, UC_X86_REG_ECX, &buf);
	uc_reg_read(uc, UC_X86_REG_EDX, &count);
	uc_reg_read(uc, UC_X86_REG_ESI, &rx_bytes);
	if (count == 0) {
		// Requested to read 0 bytes. Set *rx_bytes and syscall return value to 0
		if (rx_bytes != 0) {
			handle_write(rx_bytes, 4, true);
			if (stopped) {
				return;
			}
			uc_mem_write(uc, rx_bytes, &count, 4);
		}
		uc_reg_write(uc, UC_X86_REG_EAX, &count);
		interrupt_handled = true;
		syscall_count++;
		return;
	}

	// Perform read
	char *tmp_buf = (char *)malloc(count);
	auto actual_count = fd_read(fd, tmp_buf, count);
	if (stopped) {
		// Possibly stopped when writing bytes read to memory. Treat as syscall failure.
		free(tmp_buf);
		return;
	}
	if (actual_count > 0) {
		// Mark buf as symbolic
		handle_write(buf, actual_count, true, true);
		if (stopped) {
			free(tmp_buf);
			return;
		}
		uc_mem_write(uc, buf, tmp_buf, actual_count);
	}
	free(tmp_buf);
	if (rx_bytes != 0) {
		handle_write(rx_bytes, 4, true);
		if (stopped) {
			return;
		}
		uc_mem_write(uc, rx_bytes, &actual_count, 4);
	}
	count = 0;
	uc_reg_write(uc, UC_X86_REG_EAX, &count);
	step(cgc_receive_bbl, 0, false);
	commit();
	if (actual_count > 0) {
		// Save a block with an instruction to track that the receive syscall needs to be re-executed. The instruction
		// data is used only to work with existing mechanism to return data to python.
		// Save all non-symbolic register arguments needed for syscall.
		block_details_t block_for_receive;
		block_for_receive.block_addr = cgc_receive_bbl;
		block_for_receive.block_size = 0;
		block_for_receive.block_trace_ind = executed_blocks_count;
		block_for_receive.has_symbolic_exit = false;
		instr_details_t instr_for_receive;
		// First argument: ebx
		register_value_t reg_val;
		if (!is_symbolic_register(20, 4)) {
			reg_val.offset = 20;
			reg_val.size = 4;
			get_register_value(reg_val.offset, reg_val.value);
			instr_for_receive.reg_deps.emplace(reg_val);
		}
		// Second argument: ecx
		if (!is_symbolic_register(12, 4)) {
			reg_val.offset = 12;
			reg_val.size = 4;
			get_register_value(reg_val.offset, reg_val.value);
			instr_for_receive.reg_deps.emplace(reg_val);
		}
		// Third argument: edx
		if (!is_symbolic_register(16, 4)) {
			reg_val.offset = 16;
			reg_val.size = 4;
			get_register_value(reg_val.offset, reg_val.value);
			instr_for_receive.reg_deps.emplace(reg_val);
		}
		block_for_receive.symbolic_instrs.emplace_back(instr_for_receive);
		blocks_with_symbolic_instrs.emplace_back(block_for_receive);
	}
	interrupt_handled = true;
	syscall_count++;
	return;
}

void State::perform_cgc_transmit() {
	// basically an implementation of the cgc transmit syscall
	//printf(".. TRANSMIT!\n");
	uint32_t fd, buf, count, tx_bytes;

	uc_reg_read(uc, UC_X86_REG_EBX, &fd);
	if (fd == 2) {
		// we won't try to handle fd 2 prints here, they are uncommon.
		return;
	}
	else if (fd == 0 || fd == 1) {
		uc_reg_read(uc, UC_X86_REG_ECX, &buf);
		uc_reg_read(uc, UC_X86_REG_EDX, &count);
		uc_reg_read(uc, UC_X86_REG_ESI, &tx_bytes);

		// ensure that the memory we're sending is not tainted
		// TODO: Can transmit also work with symbolic bytes?
		void *dup_buf = malloc(count);
		uint32_t tmp_tx;
		if (uc_mem_read(uc, buf, dup_buf, count) != UC_ERR_OK) {
			//printf("... fault on buf\n");
			free(dup_buf);
			return;
		}

		if (tx_bytes != 0 && uc_mem_read(uc, tx_bytes, &tmp_tx, 4) != UC_ERR_OK) {
			//printf("... fault on tx\n");
			free(dup_buf);
			return;
		}

		if (find_tainted(buf, count) != -1) {
			//printf("... symbolic data\n");
			free(dup_buf);
			return;
		}

		step(cgc_transmit_bbl, 0, false);
		commit();
		if (stopped) {
			//printf("... stopped after step()\n");
			free(dup_buf);
			return;
		}

		if (tx_bytes != 0) {
			handle_write(tx_bytes, 4, true);
			if (stopped) {
				return;
			}
			uc_mem_write(uc, tx_bytes, &count, 4);
		}

		if (stopped) {
			return;
		}

		transmit_records.push_back({dup_buf, count});
		int result = 0;
		uc_reg_write(uc, UC_X86_REG_EAX, &result);
		symbolic_registers.erase(8);
		symbolic_registers.erase(9);
		symbolic_registers.erase(10);
		symbolic_registers.erase(11);
		interrupt_handled = true;
		syscall_count++;
		return;
	}
}

static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	// uc_mem_read(uc, address, &value, size);
	// //LOG_D("mem_read [%#lx, %#lx] = %#lx", address, address + size);
	//LOG_D("mem_read [%#lx, %#lx]", address, address + size);
	State *state = (State *)user_data;
	state->propagate_taint_of_mem_read_instr_and_continue(address, size);
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
	if (!state->check_symbolic_stack_mem_dependencies_liveness()) {
		state->stop(STOP_SYMBOLIC_MEM_DEP_NOT_LIVE, true);
		return;
	}
	state->commit();
	state->update_previous_stack_top();
	state->set_curr_block_details(address, size);
	state->step(address, size);

	if (!state->stopped) {
		state->start_propagating_taint();
	}
	return;
}

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data) {
	State *state = (State *)user_data;
	state->interrupt_handled = false;
	auto curr_simos = state->get_simos();

	if (curr_simos == SIMOS_CGC) {
		assert (state->arch == UC_ARCH_X86);
		assert (state->unicorn_mode == UC_MODE_32);

		if (intno == 0x80) {
			for (auto sr : state->symbolic_registers) {
				// eax,ecx,edx,ebx,esi
				if ((sr >= 8 && sr <= 23) || (sr >= 32 && sr <= 35)) return;
			}

			uint32_t sysno;
			uc_reg_read(uc, UC_X86_REG_EAX, &sysno);
			//printf("SYSCALL: %d\n", sysno);
			if ((sysno == state->cgc_transmit_sysno) && (state->cgc_transmit_bbl != 0)) {
				state->perform_cgc_transmit();
			}
			else if ((sysno == state->cgc_receive_sysno) && (state->cgc_receive_bbl != 0)) {
				state->perform_cgc_receive();
			}
			else if ((sysno == state->cgc_random_sysno) && (state->cgc_random_bbl != 0)) {
				state->perform_cgc_random();
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
State *simunicorn_alloc(uc_engine *uc, uint64_t cache_key, simos_t simos, bool handle_symbolic_addrs, bool handle_symb_cond) {
	State *state = new State(uc, cache_key, simos, handle_symbolic_addrs, handle_symb_cond);
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
uint64_t simunicorn_step(State *state) {
	return state->cur_steps;
}

extern "C"
void simunicorn_set_last_block_details(State *state, address_t block_addr, uint64_t curr_count, uint64_t total_count) {
	state->set_last_block_details(block_addr, curr_count, total_count);
}

extern "C"
void simunicorn_set_random_syscall_data(State *state, uint64_t *values, uint64_t *sizes, uint64_t count) {
	state->init_random_bytes(values, sizes, count);
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
stop_details_t simunicorn_get_stop_details(State *state) {
	return state->stop_details;
}

//
// Symbolic register tracking
//

extern "C"
void simunicorn_symbolic_register_data(State *state, uint64_t count, uint64_t *offsets)
{
	state->symbolic_registers.clear();
	for (auto i = 0; i < count; i++) {
		state->symbolic_registers.insert(offsets[i]);
	}
}

extern "C"
uint64_t simunicorn_get_symbolic_registers(State *state, uint64_t *output)
{
	int i = 0;
	for (auto r : state->symbolic_registers) {
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
void simunicorn_set_cgc_syscall_details(State *state, uint32_t transmit_num, uint64_t transmit_bbl,
  uint32_t receive_num, uint64_t receive_bbl, uint32_t random_num, uint64_t random_bbl) {
	state->cgc_random_sysno = random_num;
	state->cgc_random_bbl = random_bbl;
	state->cgc_receive_sysno = receive_num;
	state->cgc_receive_bbl = receive_bbl;
	state->cgc_transmit_sysno = transmit_num;
	state->cgc_transmit_bbl = transmit_bbl;
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
 * Set concrete bytes of an open file for use in tracing
 */

extern "C"
void simunicorn_set_fd_bytes(State *state, uint64_t fd, char *input, uint64_t len, uint64_t read_pos) {
	state->fd_init_bytes(fd, input, len, read_pos);
	return;
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
	for (auto i = 0; i < count; i++) {
		state->artificial_vex_registers.emplace(offsets[i]);
	}
	return;
}

// VEX register offsets to unicorn register ID mappings
extern "C"
void simunicorn_set_vex_to_unicorn_reg_mappings(State *state, uint64_t *vex_offsets, uint64_t *unicorn_ids,
  uint64_t *reg_sizes, uint64_t count) {
	state->vex_to_unicorn_map.clear();
	for (auto i = 0; i < count; i++) {
		state->vex_to_unicorn_map.emplace(vex_offsets[i], std::make_pair(unicorn_ids[i], reg_sizes[i]));
	}
	return;
}

// Mapping details for flags registers
extern "C"
void simunicorn_set_cpu_flags_details(State *state, uint64_t *flag_vex_id, uint64_t *uc_reg_id, uint64_t *bitmasks, uint64_t count) {
	state->cpu_flags.clear();
	for (auto i = 0; i < count; i++) {
		state->cpu_flags.emplace(flag_vex_id[i], std::make_pair(uc_reg_id[i], bitmasks[i]));
	}
	return;
}

extern "C"
void simunicorn_set_register_blacklist(State *state, uint64_t *reg_list, uint64_t count) {
	state->blacklisted_registers.clear();
	for (auto i = 0; i < count; i++) {
		state->blacklisted_registers.emplace(reg_list[i]);
	}
	return;
}

// VEX re-execution data

extern "C"
uint64_t simunicorn_get_count_of_blocks_with_symbolic_instrs(State *state) {
	return state->block_details_to_return.size();
}

extern "C"
void simunicorn_get_details_of_blocks_with_symbolic_instrs(State *state, sym_block_details_ret_t *ret_block_details) {
	for (auto i = 0; i < state->block_details_to_return.size(); i++) {
		ret_block_details[i].block_addr = state->block_details_to_return[i].block_addr;
		ret_block_details[i].block_size = state->block_details_to_return[i].block_size;
		ret_block_details[i].block_trace_ind = state->block_details_to_return[i].block_trace_ind;
		ret_block_details[i].has_symbolic_exit = state->block_details_to_return[i].has_symbolic_exit;
		ret_block_details[i].symbolic_instrs = &(state->block_details_to_return[i].symbolic_instrs[0]);
		ret_block_details[i].symbolic_instrs_count = state->block_details_to_return[i].symbolic_instrs.size();
		ret_block_details[i].register_values = &(state->block_details_to_return[i].register_values[0]);
		ret_block_details[i].register_values_count = state->block_details_to_return[i].register_values.size();
	}
	return;
}
