import copy
import functools
import logging

import archinfo

from ..errors import SimIRSBError, SimIRSBNoDecodeError, SimValueError
from .engine import SuccessorsMixin
from .vex.heavy.heavy import VEXEarlyExit
from .. import sim_options as o
from ..misc.ux import once
from ..state_plugins.inspect import BP_AFTER, BP_BEFORE
from ..state_plugins.unicorn_engine import STOP, _UC_NATIVE, unicorn as uc_module
from ..utils.constants import DEFAULT_STATEMENT

# pylint: disable=arguments-differ

l = logging.getLogger(name=__name__)


class SimEngineUnicorn(SuccessorsMixin):
    """
    Concrete execution in the Unicorn Engine, a fork of qemu.

    Responds to the following parameters in the step stack:

    - step:                How many basic blocks we want to execute
    - extra_stop_points:   A collection of addresses at which execution should halt
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Cache of details of basic blocks containing statements that need to re-executed
        self._block_details_cache = {}
        # Addresses of basic blocks which native interface will not execute
        self._stop_block_addrs_cache = set()
        # Stop reasons to track and not switch to native interface for those basic blocks
        self._stop_reasons_to_track = STOP.unsupported_reasons | {
            STOP.STOP_STOPPOINT,
            STOP.STOP_ERROR,
            STOP.STOP_NODECODE,
            STOP.STOP_SYSCALL,
            STOP.STOP_EXECNONE,
            STOP.STOP_ZEROPAGE,
            STOP.STOP_NOSTART,
            STOP.STOP_SEGFAULT,
            STOP.STOP_ZERO_DIV,
            STOP.STOP_HLT,
            STOP.STOP_SYSCALL_ARM,
            STOP.STOP_X86_CPUID,
        }

    def __getstate__(self):
        parent_ret = super().__getstate__()
        return (parent_ret, self._block_details_cache, self._stop_block_addrs_cache, self._stop_reasons_to_track)

    def __setstate__(self, args):
        super().__setstate__(args[0])
        self._block_details_cache = args[1]
        self._stop_block_addrs_cache = args[2]
        self._stop_reasons_to_track = args[3]

    def __check(self, num_inst=None, **kwargs):  # pylint: disable=unused-argument
        state = self.state
        if o.UNICORN not in state.options:
            l.debug("Unicorn-engine is not enabled.")
            return False

        if uc_module is None or _UC_NATIVE is None:
            if once("unicorn_install_warning"):
                l.error(
                    "You are attempting to use unicorn engine support even though it or the angr native layer "
                    "isn't installed"
                )
            return False

        self.__countdown(state)

        # should the countdown still be updated if we're not stepping a whole block?
        # current decision: leave it updated, since we are moving forward
        if num_inst is not None:
            # we don't support single stepping with unicorn
            return False

        unicorn = state.unicorn  # shorthand

        # if we have a concrete target we want the program to synchronize the segment
        # registers before, otherwise undefined behavior could happen.
        if state.project.concrete_target and self.project.arch.name in ("x86", "x86_64"):
            if not state.concrete.segment_registers_initialized:
                l.debug("segment register must be synchronized with the concrete target before using unicorn engine")
                return False
        if state.regs.ip.symbolic:
            l.debug("symbolic IP!")
            return False
        if unicorn.countdown_symbolic_stop > 0:
            l.info("not enough blocks since symbolic stop (%d more)", unicorn.countdown_symbolic_stop)
            return False
        if unicorn.countdown_unsupported_stop > 0:
            l.info(
                "not enough blocks since unsupported VEX statement/expression stop (%d more)",
                unicorn.countdown_unsupported_stop,
            )
            return False
        if unicorn.countdown_nonunicorn_blocks > 0:
            l.info("not enough runs since last unicorn (%d)", unicorn.countdown_nonunicorn_blocks)
            return False
        if unicorn.countdown_stop_point > 0:
            l.info("not enough blocks since stop point (%d more)", unicorn.countdown_stop_point)
        elif o.UNICORN_SYM_REGS_SUPPORT not in state.options and not unicorn._check_registers():
            l.info("failed register check")
            return False

        if state.addr in self._stop_block_addrs_cache:
            l.info("Block will likely not execute in native interface")
            return False

        return True

    @staticmethod
    def __countdown(state):
        state.unicorn.countdown_nonunicorn_blocks -= 1
        state.unicorn.countdown_symbolic_stop -= 1
        state.unicorn.countdown_unsupported_stop -= 1
        state.unicorn.countdown_stop_point -= 1

    def _execute_block_instrs_in_vex(self, block_details):
        if block_details["block_addr"] not in self._block_details_cache:
            vex_block = self._get_vex_block_details(block_details["block_addr"], block_details["block_size"])
            self._block_details_cache[block_details["block_addr"]] = vex_block
        else:
            vex_block = self._block_details_cache[block_details["block_addr"]]

        # Save breakpoints for restoring later
        saved_mem_read_breakpoints = copy.copy(self.state.inspect._breakpoints["mem_read"])
        saved_mem_write_breakpoints = copy.copy(self.state.inspect._breakpoints["mem_write"])
        for reg_name, reg_value in block_details["registers"]:
            self.state.registers.store(reg_name, reg_value, inspect=False, disable_actions=True)

        self.state.scratch.set_tyenv(vex_block.tyenv)
        for stmt_entry in block_details["stmts"]:
            self._instr_mem_reads = list(stmt_entry["mem_dep"])  # pylint:disable=attribute-defined-outside-init
            if self._instr_mem_reads:
                # Insert breakpoint to set the correct memory read address
                self.state.inspect.b("mem_read", when=BP_BEFORE, action=self._set_correct_mem_read_addr)

            self.state.inspect.b("mem_write", when=BP_AFTER, action=self._save_mem_write_addrs)
            execute_default_exit = True
            # Execute handler from HeavyVEXMixin for the statement
            vex_stmt = vex_block.statements[stmt_entry["stmt_idx"]]
            self.stmt_idx = stmt_entry["stmt_idx"]  # pylint:disable=attribute-defined-outside-init
            try:
                super()._handle_vex_stmt(vex_stmt)  # pylint:disable=no-member
            except VEXEarlyExit:
                # Only one path is satisfiable in this branch.
                execute_default_exit = False

            # Restore breakpoints
            self.state.inspect._breakpoints["mem_read"] = copy.copy(saved_mem_read_breakpoints)
            self.state.inspect._breakpoints["mem_write"] = copy.copy(saved_mem_write_breakpoints)
            del self._instr_mem_reads

        if execute_default_exit and block_details["has_symbolic_exit"]:
            # Process block's default exit
            self.stmt_idx = DEFAULT_STATEMENT  # pylint:disable=attribute-defined-outside-init
            super()._handle_vex_defaultexit(vex_block.next, vex_block.jumpkind)  # pylint:disable=no-member

        # Restore breakpoints
        for succ_state in self.successors.successors:
            succ_state.inspect._breakpoints["mem_read"] = copy.copy(saved_mem_read_breakpoints)
            succ_state.inspect._breakpoints["mem_write"] = copy.copy(saved_mem_read_breakpoints)

        del self.stmt_idx

    def _execute_symbolic_instrs(self, syscall_data):
        recent_bbl_addrs = None
        stop_details = None

        self._instr_mem_write_addrs = set()  # pylint:disable=attribute-defined-outside-init
        for block_details in self.state.unicorn._get_details_of_blocks_with_symbolic_vex_stmts():
            self.state.scratch.guard = self.state.solver.true
            try:
                if self.state.os_name == "CGC" and block_details["block_addr"] in {
                    self.state.unicorn.cgc_random_addr,
                    self.state.unicorn.cgc_receive_addr,
                }:
                    # Re-execute CGC syscall
                    reg_vals = dict(block_details["registers"])
                    curr_regs = self.state.regs
                    # If any regs are not present in the block details for re-execute, they are probably symbolic and so
                    # were not saved in native interface. Use current register values in those cases: they should have
                    # correct values right now.
                    if block_details["block_addr"] == self.state.unicorn.cgc_receive_addr:
                        # rx_bytes argument is set to 0 since we care about updating symbolic values only
                        syscall_args = [
                            reg_vals.get("ebx", curr_regs.ebx),
                            reg_vals.get("ecx", curr_regs.ecx),
                            reg_vals.get("edx", curr_regs.edx),
                            0,
                        ]
                        syscall_simproc = self.state.project.simos.syscall_from_number(3, abi=None)
                        syscall_simproc.arch = self.state.arch
                        syscall_simproc.project = self.state.project
                        syscall_simproc.state = self.state
                        syscall_simproc.cc = self.state.project.simos.syscall_cc(self.state)
                        ret_val = getattr(syscall_simproc, syscall_simproc.run_func)(*syscall_args)
                        self.state.registers.store("eax", ret_val, inspect=False, disable_actions=True)
                    elif block_details["block_addr"] == self.state.unicorn.cgc_random_addr:
                        syscall_simproc = self.state.project.simos.syscall_from_number(7, abi=None)
                        # rnd_bytes argument is set to 0 since we care about updating symbolic values only
                        syscall_args = [reg_vals.get("ebx", curr_regs.ebx), reg_vals.get("ecx", curr_regs.ecx), 0]
                        if o.UNICORN_HANDLE_CGC_RANDOM_SYSCALL in self.state.options:
                            # Update concrete value before invoking syscall
                            concrete_data = b""
                            curr_size = 0
                            max_size = self.state.solver.eval(syscall_args[1])
                            while curr_size != max_size:
                                next_entry = syscall_data["random"].pop(0)
                                curr_size = curr_size + next_entry[1]
                                endianness = "little" if self.state.arch.memory_endness == "Iend_LE" else "big"
                                concrete_data = concrete_data + next_entry[0].to_bytes(next_entry[1], endianness)
                        else:
                            concrete_data = None

                        syscall_simproc.arch = self.state.arch
                        syscall_simproc.project = self.state.project
                        syscall_simproc.state = self.state
                        syscall_simproc.cc = self.state.project.simos.syscall_cc(self.state)
                        ret_val = getattr(syscall_simproc, syscall_simproc.run_func)(*syscall_args, concrete_data)
                        self.state.registers.store("eax", ret_val, inspect=False, disable_actions=True)
                else:
                    if block_details["has_symbolic_exit"]:
                        curr_succs_count = len(self.successors.successors)
                        if not recent_bbl_addrs:
                            recent_bbl_addrs = self.state.unicorn.get_recent_bbl_addrs()

                        if not stop_details:
                            stop_details = self.state.unicorn.get_stop_details()

                    self._execute_block_instrs_in_vex(block_details)
                    if block_details["has_symbolic_exit"]:
                        curr_succs = self.successors.successors
                        if len(curr_succs) == curr_succs_count + 1:
                            # There is only one newly added satisfiable successor state and so that is the state that
                            # follows path being traced
                            self.state = curr_succs[curr_succs_count]
                            self.successors.flat_successors.remove(self.state)
                            self.successors.all_successors.remove(self.state)
                            self.successors.successors.remove(self.state)
                        else:
                            # There are multiple satisfiable states. Use the state's record of basic blocks executed
                            # and block where native interface stopped to determine which state followed the path traced
                            # till now

                            next_block_on_path = None
                            if block_details["block_hist_ind"] + 1 < len(recent_bbl_addrs):
                                next_block_on_path = recent_bbl_addrs[block_details["block_hist_ind"] + 1]
                            else:
                                next_block_on_path = stop_details.block_addr

                            for succ in curr_succs[curr_succs_count:]:
                                if succ.addr == next_block_on_path:
                                    self.state = succ
                                    self.successors.flat_successors.remove(succ)
                                    self.successors.successors.remove(succ)
                                    break
                            else:
                                raise Exception("Multiple valid successor states found but none followed the trace!")
            except SimValueError as e:
                l.error(e)

        del self._instr_mem_write_addrs

    def _get_vex_block_details(self, block_addr, block_size):
        # Mostly based on the lifting code in HeavyVEXMixin
        # pylint:disable=no-member
        irsb = super().lift_vex(addr=block_addr, state=self.state, size=block_size)
        if irsb.size == 0:
            if irsb.jumpkind == "Ijk_NoDecode":
                if not self.state.project.is_hooked(irsb.addr):
                    raise SimIRSBNoDecodeError(
                        f"IR decoding error at 0x{irsb.addr:02x}. You can hook this instruction"
                        " with a python replacement using project.hook"
                        f"(0x{irsb.addr:02x}, your_function, length=length_of_instruction)."
                    )

                raise SimIRSBError("Block is hooked with custom code but original block was executed in unicorn")

            raise SimIRSBError(f"Empty IRSB found at 0x{irsb.addr:02x}.")

        return irsb

    def _set_correct_mem_read_addr(self, state):
        assert len(self._instr_mem_reads) != 0
        mem_read_val = b""
        mem_read_size = 0
        mem_read_address = None
        mem_read_taint_map = []
        while mem_read_size != state.inspect.mem_read_length and self._instr_mem_reads:
            next_val = self._instr_mem_reads.pop(0)
            if not mem_read_address:
                mem_read_address = next_val["address"]

            if next_val["symbolic"]:
                if next_val["address"] in self._instr_mem_write_addrs:
                    # This address was modified during re-execution. Ignore taint reported by native interface
                    mem_read_taint_map.append(-1)
                else:
                    mem_read_taint_map.append(1)
            else:
                mem_read_taint_map.append(0)

            mem_read_size += 1
            mem_read_val += next_val["value"]

        assert state.inspect.mem_read_length == mem_read_size
        state.inspect.mem_read_address = state.solver.BVV(mem_read_address, state.inspect.mem_read_address.size())
        if mem_read_taint_map.count(-1) != mem_read_size:
            # Since read is might need bitmap adjustment, insert breakpoint to return the correct concrete value
            self.state.inspect.b(
                "mem_read",
                when=BP_AFTER,
                action=functools.partial(
                    self._set_correct_mem_read_val, value=mem_read_val, taint_map=mem_read_taint_map
                ),
            )

    def _set_correct_mem_read_val(self, state, value, taint_map):  # pylint: disable=no-self-use
        state.inspect._breakpoints["mem_read"].pop()
        if taint_map.count(0) == state.inspect.mem_read_length:
            # The value is completely concrete
            if state.arch.memory_endness == archinfo.Endness.LE:
                state.inspect.mem_read_expr = state.solver.BVV(value[::-1])
            else:
                state.inspect.mem_read_expr = state.solver.BVV(value)
        else:
            # The value may be partially concrete. Set the symbolic bitmap to read correct value and restore it
            mem_read_addr = state.solver.eval(state.inspect.mem_read_address)
            mem_read_len = state.inspect.mem_read_length
            saved_taints = []
            for offset in range(mem_read_len):
                page_num, page_off = state.memory._divide_addr(mem_read_addr + offset)
                page_obj = state.memory._get_page(page_num, writing=False)
                saved_taints.append(page_obj.symbolic_bitmap[page_off])

            restore_taints = False
            if saved_taints != taint_map:
                # Symbolic bitmap needs fixing before reading value from memory.
                restore_taints = True
                for offset, expected_taint in enumerate(taint_map):
                    if expected_taint != -1:
                        page_num, page_off = state.memory._divide_addr(mem_read_addr + offset)
                        page_obj = state.memory._get_page(page_num, writing=False)
                        page_obj.symbolic_bitmap[page_off] = expected_taint

            curr_value = state.memory.load(
                mem_read_addr, mem_read_len, endness=state.arch.memory_endness, inspect=False, disable_actions=True
            )
            if restore_taints:
                for offset, saved_taint in enumerate(saved_taints):
                    page_num, page_off = state.memory._divide_addr(mem_read_addr + offset)
                    page_obj = state.memory._get_page(page_num, writing=False)
                    page_obj.symbolic_bitmap[page_off] = saved_taint

            if taint_map.count(0) != 0:
                # Update concrete bytes using values reported by native interface
                curr_value_bytes = curr_value.chop(8)
                if state.arch.memory_endness == archinfo.Endness.LE:
                    curr_value_bytes.reverse()

                for offset, expected_taint in enumerate(taint_map):
                    if expected_taint == 0:
                        curr_value_bytes[offset] = state.solver.BVV(value[offset], 8)

                if state.arch.memory_endness == archinfo.Endness.LE:
                    curr_value_bytes = reversed(curr_value_bytes)

                curr_value = state.solver.Concat(*curr_value_bytes)

            state.inspect.mem_read_expr = curr_value

    def _save_mem_write_addrs(self, state):
        mem_write_addr = state.solver.eval(state.inspect.mem_write_address)
        self._instr_mem_write_addrs.update(range(mem_write_addr, mem_write_addr + state.inspect.mem_write_length))

    def process_successors(self, successors, **kwargs):
        state = self.state
        if not self.__check(**kwargs):
            return super().process_successors(successors, **kwargs)

        extra_stop_points = kwargs.get("extra_stop_points", None)
        last_block_details = kwargs.get("last_block_details", None)
        step = kwargs.get("step", None)
        if extra_stop_points is None:
            extra_stop_points = set(self.project._sim_procedures)
        else:
            # convert extra_stop_points to a set
            extra_stop_points = set(extra_stop_points)
            extra_stop_points.update(self.project._sim_procedures)
        if successors.addr in extra_stop_points:
            # trying to start unicorn execution on a stop point, fallback to next engine
            return super().process_successors(successors, **kwargs)

        successors.sort = "Unicorn"

        # add all instruction breakpoints as extra_stop_points
        if state.supports_inspect:
            for bp in state.inspect._breakpoints["instruction"]:
                # if there is an instruction breakpoint on every instruction, it does not make sense
                # to use unicorn.
                if "instruction" not in bp.kwargs:
                    l.info("disabling unicorn because of breakpoint on every instruction")
                    return super().process_successors(successors, **kwargs)

                # add the breakpoint to extra_stop_points. We don't care if the breakpoint is BP_BEFORE or
                # BP_AFTER, this is only to stop unicorn when we get near a breakpoint. The breakpoint itself
                # will then be handled by another engine that can more accurately step instruction-by-instruction.
                extra_stop_points.add(bp.kwargs["instruction"])

        # initialize unicorn plugin
        try:
            syscall_data = kwargs["syscall_data"] if "syscall_data" in kwargs else None
            fd_bytes = kwargs["fd_bytes"] if "fd_bytes" in kwargs else None
            state.unicorn.setup(syscall_data=syscall_data, fd_bytes=fd_bytes)
        except SimValueError:
            # it's trying to set a symbolic register somehow
            # fail out, force fallback to next engine
            return super().process_successors(successors, **kwargs)

        try:
            state.unicorn.set_stops(extra_stop_points)
            if last_block_details is not None:
                state.unicorn.set_last_block_details(last_block_details)
            state.unicorn.set_tracking(
                track_bbls=o.UNICORN_TRACK_BBL_ADDRS in state.options,
                track_stack=o.UNICORN_TRACK_STACK_POINTERS in state.options,
            )
            state.unicorn.hook()
            state.unicorn.start(step=step)
            self._execute_symbolic_instrs(syscall_data=syscall_data)
            state.unicorn.finish(self.state)
        finally:
            state.unicorn.destroy(self.state)

        state = self.state
        if state.unicorn.stop_reason in self._stop_reasons_to_track:
            if state.unicorn.steps == 0:
                self._stop_block_addrs_cache.add(state.addr)
            else:
                self._stop_block_addrs_cache.add(state.unicorn.stop_details.block_addr)

        if state.unicorn.steps == 0 or state.unicorn.stop_reason == STOP.STOP_NOSTART:
            # fail out, force fallback to next engine
            # TODO: idk what the consequences of this might be. If this failed step can actually change non-unicorn
            # state then this is bad news.
            return super().process_successors(successors, **kwargs)

        description = f"Unicorn ({STOP.name_stop(state.unicorn.stop_reason)} after {state.unicorn.steps} steps)"

        state.history.recent_block_count += state.unicorn.steps
        state.history.recent_description = description

        # this can be expensive, so check first
        if state.supports_inspect:
            for bp in state.inspect._breakpoints["irsb"]:
                if bp.check(state, BP_AFTER):
                    for bbl_addr in state.history.recent_bbl_addrs:
                        state._inspect("irsb", BP_AFTER, address=bbl_addr)
                    break

        if state.unicorn.stop_reason in (
            STOP.symbolic_stop_reasons | STOP.unsupported_reasons
        ) or state.unicorn.stop_reason in (STOP.STOP_UNKNOWN_MEMORY_WRITE_SIZE, STOP.STOP_VEX_LIFT_FAILED):
            l.info(state.unicorn.stop_message)

        if state.unicorn.jumpkind.startswith("Ijk_Sys"):
            state.ip = state.unicorn._syscall_pc
        successors.add_successor(state, state.ip, state.solver.true, state.unicorn.jumpkind)

        successors.description = description
        successors.processed = True

        return None
