#include <map>
#include <set>
#include <cstdint>
#include <vector>
#include <unordered_map>

#include <pybind11/pybind11.h>
#include <pyvex.h>

#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__)
#include <dlfcn.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error "Unsupported platform - need dlopen equivalent"
#endif

#define ANGR_UNICORN_API
#include "sim_unicorn.hpp"

bool simunicorn_setup_imports(char *uc_path) {

#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__)
	void *handle = dlopen(uc_path, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		return false;
	}
#define XX(x) *((void**)&x) = (void*)dlsym(handle, #x); if (!x) { return false; }
#include "uc_macro.h"

#elif defined(_WIN32)
	HMODULE handle = LoadLibraryA(uc_path);
	if (!handle) {
		return false;
	}
#define XX(x) *((void**)&x) = (void*)GetProcAddress(handle, #x); if (!x) { return false; }
#include "uc_macro.h"

#endif

	return true;
}


State *simunicorn_alloc(void *uc, uint64_t cache_key, simos_t simos, bool handle_symbolic_addrs,
  bool handle_symb_cond, bool handle_symb_syscalls) {
	State *state = new State((uc_engine *)uc, cache_key, simos, handle_symbolic_addrs, handle_symb_cond, handle_symb_syscalls);
	return state;
}

void simunicorn_dealloc(State *state) {
	delete state;
}

uint64_t *simunicorn_bbl_addrs(State *state) {
	return &(state->bbl_addrs[0]);
}

uint64_t *simunicorn_stack_pointers(State *state) {
	return &(state->stack_pointers[0]);
}

uint64_t simunicorn_bbl_addr_count(State *state) {
	return state->bbl_addrs.size();
}

uint64_t simunicorn_syscall_count(State *state) {
	return state->syscall_count;
}

void simunicorn_hook(State *state) {
	state->hook();
}

void simunicorn_unhook(State *state) {
	state->unhook();
}

uc_err simunicorn_start(State *state, uint64_t pc, uint64_t step) {
	return state->start(pc, step);
}

void simunicorn_stop(State *state, stop_t reason) {
	state->stop(reason);
}

mem_update_t *simunicorn_sync(State *state) {
	return state->sync();
}

uint64_t simunicorn_step(State *state) {
	return state->cur_steps;
}

void simunicorn_set_last_block_details(State *state, address_t block_addr, uint64_t curr_count, uint64_t total_count) {
	state->set_last_block_details(block_addr, curr_count, total_count);
}

void simunicorn_set_random_syscall_data(State *state, uint64_t *values, uint64_t *sizes, uint64_t count) {
	state->init_random_bytes(values, sizes, count);
}

void simunicorn_set_stops(State *state, uint64_t count, uint64_t *stops)
{
	state->set_stops(count, stops);
}

void simunicorn_activate_page(State *state, uint64_t address, uint8_t *taint, uint8_t *data) {
    state->page_activate(address, taint, data);
}

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

stop_details_t simunicorn_get_stop_details(State *state) {
	return state->stop_details;
}

//
// Symbolic register tracking
//

void simunicorn_symbolic_register_data(State *state, uint64_t count, uint64_t *offsets)
{
	state->symbolic_registers.clear();
	for (auto i = 0; i < count; i++) {
		state->symbolic_registers.insert(offsets[i]);
	}
}

uint64_t simunicorn_get_symbolic_registers(State *state, uint64_t *output)
{
	int i = 0;
	for (auto r : state->symbolic_registers) {
		output[i] = r;
		i++;
	}
	return i;
}

void simunicorn_enable_symbolic_reg_tracking(State *state, VexArch guest, VexArchInfo archinfo) {
	state->vex_guest = guest;
	state->vex_archinfo = archinfo;
}

void simunicorn_disable_symbolic_reg_tracking(State *state) {
	state->vex_guest = VexArch_INVALID;
}

//
// Concrete transmits
//

bool simunicorn_is_interrupt_handled(State *state) {
	return state->interrupt_handled;
}

void simunicorn_set_cgc_syscall_details(State *state, uint32_t transmit_num, uint64_t transmit_bbl,
  uint32_t receive_num, uint64_t receive_bbl, uint64_t receive_size, uint32_t random_num, uint64_t random_bbl) {
	state->cgc_random_sysno = random_num;
	state->cgc_random_bbl = random_bbl;
	state->cgc_receive_sysno = receive_num;
	state->cgc_receive_bbl = receive_bbl;
	state->cgc_receive_max_size = receive_size;
	state->cgc_transmit_sysno = transmit_num;
	state->cgc_transmit_bbl = transmit_bbl;
}

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

void simunicorn_set_fd_bytes(State *state, uint64_t fd, char *input, taint_t *taints, uint64_t len, uint64_t read_pos) {
	state->fd_init_bytes(fd, input, taints, len, read_pos);
	return;
}

/*
 * Page cache
 */

bool simunicorn_cache_page(State *state, uint64_t address, uint64_t length, char *bytes, uint64_t permissions) {
	//LOG_I("caching [%#lx, %#lx]", address, address + length);

	auto actual = state->cache_page(address, length, bytes, permissions);
	if (!state->map_cache(actual.first, actual.second)) {
		return false;
	}
	return true;
}

void simunicorn_uncache_pages_touching_region(State *state, uint64_t address, uint64_t length) {
	state->uncache_pages_touching_region(address, length);
}

void simunicorn_clear_page_cache(State *state) {
	state->clear_page_cache();
}

// Tracking settings
void simunicorn_set_tracking(State *state, bool track_bbls, bool track_stack) {
	state->track_bbls = track_bbls;
	state->track_stack = track_stack;
}

bool simunicorn_in_cache(State *state, uint64_t address) {
	return state->in_cache(address);
}

void simunicorn_set_map_callback(State *state, uc_cb_eventmem_t cb) {
    state->py_mem_callback = cb;
}

// VEX artificial registers list
void simunicorn_set_artificial_registers(State *state, uint64_t *offsets, uint64_t count) {
	state->artificial_vex_registers.clear();
	for (auto i = 0; i < count; i++) {
		state->artificial_vex_registers.emplace(offsets[i]);
	}
	return;
}

// VEX register offsets to unicorn register ID mappings
void simunicorn_set_vex_to_unicorn_reg_mappings(State *state, uint64_t *vex_offsets, uint64_t *unicorn_ids,
  uint64_t *reg_sizes, uint64_t count) {
	state->vex_to_unicorn_map.clear();
	for (auto i = 0; i < count; i++) {
		state->vex_to_unicorn_map.emplace(vex_offsets[i], std::make_pair(unicorn_ids[i], reg_sizes[i]));
	}
	return;
}

// Mapping details for flags registers
void simunicorn_set_cpu_flags_details(State *state, uint64_t *flag_vex_id, uint64_t *uc_reg_id, uint64_t *bitmasks, uint64_t count) {
	state->cpu_flags.clear();
	for (auto i = 0; i < count; i++) {
		state->cpu_flags.emplace(flag_vex_id[i], std::make_pair(uc_reg_id[i], bitmasks[i]));
	}
	return;
}

void simunicorn_set_register_blacklist(State *state, uint64_t *reg_list, uint64_t count) {
	state->blacklisted_registers.clear();
	for (auto i = 0; i < count; i++) {
		state->blacklisted_registers.emplace(reg_list[i]);
	}
	return;
}

void simunicorn_set_vex_cc_reg_data(State *state, uint64_t *reg_offsets, uint64_t *reg_sizes, uint64_t count) {
	state->vex_cc_regs.clear();
	for (auto i = 0; i < count; i++) {
		state->vex_cc_regs.emplace(reg_offsets[i], reg_sizes[i]);
	}
	return;
}

// VEX re-execution data

uint64_t simunicorn_get_count_of_blocks_with_symbolic_vex_stmts(State *state) {
	return state->block_details_to_return.size();
}

void simunicorn_get_details_of_blocks_with_symbolic_vex_stmts(State *state, sym_block_details_ret_t *ret_block_details) {
	for (auto i = 0; i < state->block_details_to_return.size(); i++) {
		ret_block_details[i].block_addr = state->block_details_to_return[i].block_addr;
		ret_block_details[i].block_size = state->block_details_to_return[i].block_size;
		ret_block_details[i].block_trace_ind = state->block_details_to_return[i].block_trace_ind;
		ret_block_details[i].has_symbolic_exit = state->block_details_to_return[i].has_symbolic_exit;
		ret_block_details[i].symbolic_stmts = &(state->block_details_to_return[i].symbolic_stmts[0]);
		ret_block_details[i].symbolic_stmts_count = state->block_details_to_return[i].symbolic_stmts.size();
		ret_block_details[i].register_values = &(state->block_details_to_return[i].register_values[0]);
		ret_block_details[i].register_values_count = state->block_details_to_return[i].register_values.size();
	}
	return;
}

// Concrete writes to re-execute
uint64_t simunicorn_get_count_of_writes_to_reexecute(State *state) {
	return state->concrete_writes_to_reexecute.size();
}

void simunicorn_get_concrete_writes_to_reexecute(State *state, uint64_t *addrs, uint8_t *values) {
	uint64_t count = 0;
	for (auto &entry: state->concrete_writes_to_reexecute) {
		addrs[count] = entry.first;
		values[count] = entry.second;
		count++;
	}
	return;
 }

void simunicorn_set_fp_regs_fp_ops_vex_codes(State *state, uint64_t start_offset, uint64_t size, uint64_t *ops, uint32_t op_count) {
	state->fp_reg_vex_data.first = start_offset;
	state->fp_reg_vex_data.second = size;
	for (auto i = 0; i < op_count; i++) {
		state->fp_ops_to_avoid.emplace(ops[i]);
	}
}

PYBIND11_MODULE(unicornlib, m) {
    m.doc() = "C++ bits for unicorn integration";

	pybind11::enum_<simos_t>(m, "SimOS")
		.value("CGC", SIMOS_CGC)
		.value("LINUX", SIMOS_LINUX)
		.value("OTHER", SIMOS_OTHER)
		.export_values();

    pybind11::enum_<stop_t>(m, "StopReason")
        .value("NORMAL", STOP_NORMAL)
        .value("STOPPOINT", STOP_STOPPOINT)
        .value("ERROR", STOP_ERROR)
        .value("SYSCALL", STOP_SYSCALL)
        .value("EXECNONE", STOP_EXECNONE)
        .value("ZEROPAGE", STOP_ZEROPAGE)
        .value("NOSTART", STOP_NOSTART)
        .value("SEGFAULT", STOP_SEGFAULT)
        .value("ZERO_DIV", STOP_ZERO_DIV)
        .value("NODECODE", STOP_NODECODE)
        .value("HLT", STOP_HLT)
        .value("VEX_LIFT_FAILED", STOP_VEX_LIFT_FAILED)
        .value("SYMBOLIC_PC", STOP_SYMBOLIC_PC)
        .value("SYMBOLIC_READ_ADDR", STOP_SYMBOLIC_READ_ADDR)
        .value("SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED", STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED)
        .value("SYMBOLIC_WRITE_ADDR", STOP_SYMBOLIC_WRITE_ADDR)
        .value("SYMBOLIC_BLOCK_EXIT_CONDITION", STOP_SYMBOLIC_BLOCK_EXIT_CONDITION)
        .value("SYMBOLIC_BLOCK_EXIT_TARGET", STOP_SYMBOLIC_BLOCK_EXIT_TARGET)
        .value("UNSUPPORTED_STMT_PUTI", STOP_UNSUPPORTED_STMT_PUTI)
        .value("UNSUPPORTED_STMT_STOREG", STOP_UNSUPPORTED_STMT_STOREG)
        .value("UNSUPPORTED_STMT_LOADG", STOP_UNSUPPORTED_STMT_LOADG)
        .value("UNSUPPORTED_STMT_CAS", STOP_UNSUPPORTED_STMT_CAS)
        .value("UNSUPPORTED_STMT_LLSC", STOP_UNSUPPORTED_STMT_LLSC)
        .value("UNSUPPORTED_STMT_DIRTY", STOP_UNSUPPORTED_STMT_DIRTY)
        .value("UNSUPPORTED_STMT_UNKNOWN", STOP_UNSUPPORTED_STMT_UNKNOWN)
        .value("UNSUPPORTED_EXPR_GETI", STOP_UNSUPPORTED_EXPR_GETI)
        .value("UNSUPPORTED_EXPR_UNKNOWN", STOP_UNSUPPORTED_EXPR_UNKNOWN)
        .value("UNKNOWN_MEMORY_WRITE_SIZE", STOP_UNKNOWN_MEMORY_WRITE_SIZE)
        .value("SYSCALL_ARM", STOP_SYSCALL_ARM)
        .value("X86_CPUID", STOP_X86_CPUID)
        .export_values();

    pybind11::class_<stop_details_t>(m, "StopDetails")
        .def_readwrite("stop_reason", &stop_details_t::stop_reason)
        .def_readwrite("block_addr", &stop_details_t::block_addr)
        .def_readwrite("block_size", &stop_details_t::block_size);

    pybind11::class_<register_value_t>(m, "RegisterValue")
        .def_readwrite("offset", &register_value_t::offset)
		// FIXME: fixed-sized arrays can't be used with pybind11, need to use
		// a property instead to do a runtime check
        // .def_readwrite("value", &register_value_t::value)
        .def_readwrite("size", &register_value_t::size);

    pybind11::class_<sym_vex_stmt_details_t>(m, "SymVexStmtDetails")
        .def_readwrite("stmt_idx", &sym_vex_stmt_details_t::stmt_idx)
        .def_readwrite("has_memory_dep", &sym_vex_stmt_details_t::has_memory_dep)
        .def_readwrite("memory_values", &sym_vex_stmt_details_t::memory_values)
        .def_readwrite("memory_values_count", &sym_vex_stmt_details_t::memory_values_count);

    pybind11::class_<sym_block_details_ret_t>(m, "SymBlockDetailsRet")
        .def_readwrite("block_addr", &sym_block_details_ret_t::block_addr)
        .def_readwrite("block_size", &sym_block_details_ret_t::block_size)
        .def_readwrite("block_trace_ind", &sym_block_details_ret_t::block_trace_ind)
        .def_readwrite("has_symbolic_exit", &sym_block_details_ret_t::has_symbolic_exit)
        .def_readwrite("symbolic_stmts", &sym_block_details_ret_t::symbolic_stmts)
        .def_readwrite("symbolic_stmts_count", &sym_block_details_ret_t::symbolic_stmts_count)
        .def_readwrite("register_values", &sym_block_details_ret_t::register_values)
        .def_readwrite("register_values_count", &sym_block_details_ret_t::register_values_count);

    pybind11::class_<transmit_record_t>(m, "TransmitRecord")
        .def_readwrite("fd", &transmit_record_t::fd)
        .def_readwrite("data", &transmit_record_t::data)
        .def_readwrite("count", &transmit_record_t::count);

    pybind11::class_<State>(m, "State");

	m.def("setup_imports", &simunicorn_setup_imports);
    m.def("alloc", &simunicorn_alloc, pybind11::return_value_policy::reference);
    m.def("dealloc", &simunicorn_dealloc);
    m.def("bbl_addrs", &simunicorn_bbl_addrs, pybind11::return_value_policy::reference);
    m.def("stack_pointers", &simunicorn_stack_pointers, pybind11::return_value_policy::reference);
    m.def("bbl_addr_count", &simunicorn_bbl_addr_count);
    m.def("syscall_count", &simunicorn_syscall_count);
    m.def("hook", &simunicorn_hook);
    m.def("unhook", &simunicorn_unhook);
    m.def("start", &simunicorn_start);
    m.def("stop", &simunicorn_stop);
    m.def("sync", &simunicorn_sync, pybind11::return_value_policy::reference);
    m.def("step", &simunicorn_step);
    m.def("set_last_block_details", &simunicorn_set_last_block_details);
    m.def("set_random_syscall_data", &simunicorn_set_random_syscall_data);
    m.def("set_stops", &simunicorn_set_stops);
    m.def("activate_page", &simunicorn_activate_page);
    m.def("executed_pages", &simunicorn_executed_pages);
    m.def("get_stop_details", &simunicorn_get_stop_details);
    m.def("symbolic_register_data", &simunicorn_symbolic_register_data);
    m.def("get_symbolic_registers", &simunicorn_get_symbolic_registers);
    m.def("enable_symbolic_reg_tracking", &simunicorn_enable_symbolic_reg_tracking);
    m.def("disable_symbolic_reg_tracking", &simunicorn_disable_symbolic_reg_tracking);
    m.def("is_interrupt_handled", &simunicorn_is_interrupt_handled);
    m.def("set_cgc_syscall_details", &simunicorn_set_cgc_syscall_details);
    m.def("process_transmit", &simunicorn_process_transmit, pybind11::return_value_policy::reference);
    m.def("set_fd_bytes", &simunicorn_set_fd_bytes);
    m.def("cache_page", &simunicorn_cache_page);
    m.def("uncache_pages_touching_region", &simunicorn_uncache_pages_touching_region);
    m.def("clear_page_cache", &simunicorn_clear_page_cache);
    m.def("set_tracking", &simunicorn_set_tracking);
    m.def("in_cache", &simunicorn_in_cache);
    m.def("set_map_callback", &simunicorn_set_map_callback);
    m.def("set_artificial_registers", &simunicorn_set_artificial_registers);
    m.def("set_vex_to_unicorn_reg_mappings", &simunicorn_set_vex_to_unicorn_reg_mappings);
    m.def("set_cpu_flags_details", &simunicorn_set_cpu_flags_details);
    m.def("set_register_blacklist", &simunicorn_set_register_blacklist);
    m.def("set_vex_cc_reg_data", &simunicorn_set_vex_cc_reg_data);
    m.def("get_count_of_blocks_with_symbolic_vex_stmts", &simunicorn_get_count_of_blocks_with_symbolic_vex_stmts);
    m.def("get_details_of_blocks_with_symbolic_vex_stmts", &simunicorn_get_details_of_blocks_with_symbolic_vex_stmts);
    m.def("get_count_of_writes_to_reexecute", &simunicorn_get_count_of_writes_to_reexecute);
    m.def("get_concrete_writes_to_reexecute", &simunicorn_get_concrete_writes_to_reexecute);
    m.def("set_fp_regs_fp_ops_vex_codes", &simunicorn_set_fp_regs_fp_ops_vex_codes);
}
