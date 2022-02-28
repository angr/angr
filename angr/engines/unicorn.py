import copy
import functools
import logging

import archinfo

from ..errors import SimIRSBError, SimIRSBNoDecodeError, SimValueError
from .engine import SuccessorsMixin
from .. import sim_options as o
from ..misc.ux import once
from ..state_plugins.inspect import BP_AFTER, BP_BEFORE
from ..state_plugins.unicorn_engine import STOP, _UC_NATIVE, unicorn as uc_module

#pylint: disable=arguments-differ

l = logging.getLogger(name=__name__)


class SimEngineUnicorn(SuccessorsMixin):
    """
    Concrete execution in the Unicorn Engine, a fork of qemu.

    Responds to the following parameters in the step stack:

    - step:                How many basic blocks we want to execute
    - extra_stop_points:   A collection of addresses at which execution should halt
    """

    def __check(self, num_inst=None, **kwargs):  # pylint: disable=unused-argument
        state = self.state
        if o.UNICORN not in state.options:
            l.debug('Unicorn-engine is not enabled.')
            return False

        if uc_module is None or _UC_NATIVE is None:
            if once('unicorn_install_warning'):
                l.error("You are attempting to use unicorn engine support even though it or the angr native layer "
                        "isn't installed")
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
        if state.project.concrete_target and self.project.arch.name in ('x86', 'x86_64'):
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
            l.info("not enough blocks since unsupported VEX statement/expression stop (%d more)",
                   unicorn.countdown_unsupported_stop)
            return False
        if unicorn.countdown_nonunicorn_blocks > 0:
            l.info("not enough runs since last unicorn (%d)", unicorn.countdown_nonunicorn_blocks)
            return False
        if unicorn.countdown_stop_point > 0:
            l.info("not enough blocks since stop point (%d more)", unicorn.countdown_stop_point)
        elif o.UNICORN_SYM_REGS_SUPPORT not in state.options and not unicorn._check_registers():
            l.info("failed register check")
            return False

        return True

    @staticmethod
    def __countdown(state):
        state.unicorn.countdown_nonunicorn_blocks -= 1
        state.unicorn.countdown_symbolic_stop -= 1
        state.unicorn.countdown_unsupported_stop -= 1
        state.unicorn.countdown_stop_point -= 1

    @staticmethod
    def __reset_countdowns(state, next_state):
        next_state.unicorn.countdown_symbolic_stop = 0
        next_state.unicorn.countdown_unsupported_stop = 0
        next_state.unicorn.countdown_nonunicorn_blocks = state.unicorn.countdown_nonunicorn_blocks
        next_state.unicorn.countdown_stop_point = state.unicorn.countdown_stop_point

    def _execute_block_instrs_in_vex(self, block_details):
        if block_details["block_addr"] not in self.block_details_cache:
            vex_block_details = self._get_vex_block_details(block_details["block_addr"], block_details["block_size"])
            self.block_details_cache[block_details["block_addr"]] = vex_block_details
        else:
            vex_block_details = self.block_details_cache[block_details["block_addr"]]

        # Save breakpoints for restoring later
        saved_mem_read_breakpoints = copy.copy(self.state.inspect._breakpoints["mem_read"])
        vex_block = vex_block_details["block"]
        for reg_name, reg_value in block_details["registers"]:
            self.state.registers.store(reg_name, reg_value, inspect=False, disable_actions=True)

        # VEX statements to ignore when re-executing instructions that touched symbolic data
        ignored_statement_tags = ["Ist_AbiHint", "Ist_IMark", "Ist_MBE", "Ist_NoOP"]
        self.state.scratch.set_tyenv(vex_block.tyenv)
        for instr_entry in block_details["instrs"]:
            self._instr_mem_reads = list(instr_entry["mem_dep"])  # pylint:disable=attribute-defined-outside-init
            if self._instr_mem_reads:
                # Insert breakpoint to set the correct memory read address
                self.state.inspect.b('mem_read', when=BP_BEFORE, action=self._set_correct_mem_read_addr)

            instr_vex_stmt_indices = vex_block_details["stmt_indices"][instr_entry["instr_addr"]]
            start_index = instr_vex_stmt_indices["start"]
            end_index = instr_vex_stmt_indices["end"]
            for vex_stmt_idx in range(start_index, end_index + 1):
                # Execute handler from HeavyVEXMixin for the statement
                vex_stmt = vex_block.statements[vex_stmt_idx]
                if vex_stmt.tag not in ignored_statement_tags:
                    self.stmt_idx = vex_stmt_idx  # pylint:disable=attribute-defined-outside-init
                    super()._handle_vex_stmt(vex_stmt)  # pylint:disable=no-member

            # Restore breakpoints
            self.state.inspect._breakpoints["mem_read"] = copy.copy(saved_mem_read_breakpoints)
            del self._instr_mem_reads

        del self.stmt_idx

    def _execute_symbolic_instrs(self):
        for block_details in self.state.unicorn._get_details_of_blocks_with_symbolic_instrs():
            try:
                if self.state.os_name == "CGC" and block_details["block_addr"] == self.state.unicorn.cgc_receive_addr:
                    # Re-execute receive syscall
                    reg_vals = dict(block_details["registers"])
                    curr_regs = self.state.regs
                    # If any regs are not present in the block details for re-execute, they are probably symbolic and so
                    # were not saved in native interface. Use current register values in those cases: they should have
                    # correct values right now. rx_bytes argument is set to 0 since we care about updating symbolic
                    # values only
                    syscall_args = [reg_vals.get("ebx", curr_regs.ebx), reg_vals.get("ecx", curr_regs.ecx),
                                    reg_vals.get("edx", curr_regs.edx), 0]
                    syscall_simproc = self.state.project.simos.syscall_from_number(3, abi=None)
                    syscall_simproc.arch = self.state.arch
                    syscall_simproc.project = self.state.project
                    syscall_simproc.state = self.state
                    syscall_simproc.cc = self.state.project.simos.syscall_cc(self.state)
                    ret_val = getattr(syscall_simproc, syscall_simproc.run_func)(*syscall_args)
                    self.state.registers.store("eax", ret_val, inspect=False, disable_actions=True)
                else:
                    self._execute_block_instrs_in_vex(block_details)
            except SimValueError as e:
                l.error(e)

    def _get_vex_block_details(self, block_addr, block_size):
        # Mostly based on the lifting code in HeavyVEXMixin
        # pylint:disable=no-member
        irsb = super().lift_vex(addr=block_addr, state=self.state, size=block_size, cross_insn_opt=False)
        if irsb.size == 0:
            if irsb.jumpkind == 'Ijk_NoDecode':
                if not self.state.project.is_hooked(irsb.addr):
                    raise SimIRSBNoDecodeError(f"IR decoding error at 0x{irsb.addr:02x}. You can hook this instruction"
                                               " with a python replacement using project.hook"
                                               f"(0x{irsb.addr:02x}, your_function, length=length_of_instruction).")

                raise SimIRSBError("Block is hooked with custom code but original block was executed in unicorn")

            raise SimIRSBError(f"Empty IRSB found at 0x{irsb.addr:02x}.")

        instrs_stmt_indices = {}
        curr_instr_addr = None
        curr_instr_stmts_start_idx = 0
        for idx, statement in enumerate(irsb.statements):
            if statement.tag == "Ist_IMark":
                if curr_instr_addr is not None:
                    instrs_stmt_indices[curr_instr_addr] = {"start": curr_instr_stmts_start_idx, "end": idx - 1}

                curr_instr_addr = statement.addr
                curr_instr_stmts_start_idx = idx

        # Adding details of the last instruction
        instrs_stmt_indices[curr_instr_addr] = {"start": curr_instr_stmts_start_idx, "end": len(irsb.statements) - 1}
        block_details = {"block": irsb, "stmt_indices": instrs_stmt_indices}
        return block_details

    def _set_correct_mem_read_addr(self, state):
        assert len(self._instr_mem_reads) != 0
        mem_read_val = b""
        mem_read_size = 0
        mem_read_address = None
        mem_read_taint_map = []
        mem_read_symbolic = True
        while mem_read_size != state.inspect.mem_read_length and self._instr_mem_reads:
            next_val = self._instr_mem_reads.pop(0)
            if not mem_read_address:
                mem_read_address = next_val["address"]

            if next_val["symbolic"]:
                mem_read_taint_map.extend([1] * next_val["size"])
            else:
                mem_read_taint_map.extend([0] * next_val["size"])

            mem_read_size += next_val["size"]
            mem_read_symbolic &= next_val["symbolic"]
            mem_read_val += next_val["value"]

        assert state.inspect.mem_read_length == mem_read_size
        state.inspect.mem_read_address = state.solver.BVV(mem_read_address, state.inspect.mem_read_address.size())
        if not mem_read_symbolic:
            # Since read is (partially) concrete, insert breakpoint to return the correct concrete value
            self.state.inspect.b('mem_read', mem_read_address=mem_read_address, when=BP_AFTER,
                                 action=functools.partial(self._set_correct_mem_read_val, value=mem_read_val,
                                 taint_map=mem_read_taint_map))

    def _set_correct_mem_read_val(self, state, value, taint_map):  # pylint: disable=no-self-use
        if taint_map.count(1) == 0:
            # The value is completely concrete
            if state.arch.memory_endness == archinfo.Endness.LE:
                state.inspect.mem_read_expr = state.solver.BVV(value[::-1])
            else:
                state.inspect.mem_read_expr = state.solver.BVV(value)
        else:
            # The value is partially concrete. Use the bitmap to read the symbolic bytes from memory and construct the
            # correct value
            actual_value = []
            for offset, taint in enumerate(taint_map):
                if taint == 1:
                    # Byte is symbolic. Read the value from memory
                    actual_value.append(state.memory.load(state.inspect.mem_read_address + offset, 1, inspect=False,
                                                          disable_actions=True))
                else:
                    actual_value.append(state.solver.BVV(value[offset], 8))

            if state.arch.memory_endness == archinfo.Endness.LE:
                actual_value = actual_value[::-1]

            state.inspect.mem_read_expr = state.solver.Concat(*actual_value)

    def process_successors(self, successors, **kwargs):
        state = self.state
        if not self.__check(**kwargs):
            return super().process_successors(successors, **kwargs)

        extra_stop_points = kwargs.get('extra_stop_points', None)
        last_block_details = kwargs.get('last_block_details', None)
        step = kwargs.get('step', None)
        if extra_stop_points is None:
            extra_stop_points = set(self.project._sim_procedures)
        else:
            # convert extra_stop_points to a set
            extra_stop_points = set(extra_stop_points)
            extra_stop_points.update(self.project._sim_procedures)
        if successors.addr in extra_stop_points:
            # trying to start unicorn execution on a stop point, fallback to next engine
            return super().process_successors(successors, **kwargs)

        successors.sort = 'Unicorn'

        # add all instruction breakpoints as extra_stop_points
        if state.supports_inspect:
            for bp in state.inspect._breakpoints['instruction']:
                # if there is an instruction breakpoint on every instruction, it does not make sense
                # to use unicorn.
                if "instruction" not in bp.kwargs:
                    l.info("disabling unicorn because of breakpoint on every instruction")
                    return super().process_successors(successors, **kwargs)

                # add the breakpoint to extra_stop_points. We don't care if the breakpoint is BP_BEFORE or
                # BP_AFTER, this is only to stop unicorn when we get near a breakpoint. The breakpoint itself
                # will then be handled by another engine that can more accurately step instruction-by-instruction.
                extra_stop_points.add(bp.kwargs["instruction"])

        # VEX block cache for executing instructions skipped by native interface
        self.block_details_cache = {}  # pylint:disable=attribute-defined-outside-init

        # initialize unicorn plugin
        try:
            state.unicorn.setup()
        except SimValueError:
            # it's trying to set a symbolic register somehow
            # fail out, force fallback to next engine
            self.__reset_countdowns(successors.initial_state, state)
            return super().process_successors(successors, **kwargs)

        try:
            state.unicorn.set_stops(extra_stop_points)
            if last_block_details is not None:
                state.unicorn.set_last_block_details(last_block_details)
            state.unicorn.set_tracking(track_bbls=o.UNICORN_TRACK_BBL_ADDRS in state.options,
                                       track_stack=o.UNICORN_TRACK_STACK_POINTERS in state.options)
            state.unicorn.hook()
            state.unicorn.start(step=step)
            self._execute_symbolic_instrs()
            state.unicorn.finish()
        finally:
            state.unicorn.destroy()

        if state.unicorn.steps == 0 or state.unicorn.stop_reason == STOP.STOP_NOSTART:
            # fail out, force fallback to next engine
            self.__reset_countdowns(successors.initial_state, state)
            # TODO: idk what the consequences of this might be. If this failed step can actually change non-unicorn
            # state then this is bad news.
            return super().process_successors(successors, **kwargs)

        description = f'Unicorn ({STOP.name_stop(state.unicorn.stop_reason)} after {state.unicorn.steps} steps)'

        state.history.recent_block_count += state.unicorn.steps
        state.history.recent_description = description

        # this can be expensive, so check first
        if state.supports_inspect:
            for bp in state.inspect._breakpoints['irsb']:
                if bp.check(state, BP_AFTER):
                    for bbl_addr in state.history.recent_bbl_addrs:
                        state._inspect('irsb', BP_AFTER, address=bbl_addr)
                    break

        if (state.unicorn.stop_reason in (STOP.symbolic_stop_reasons + STOP.unsupported_reasons) or
            state.unicorn.stop_reason in (STOP.STOP_UNKNOWN_MEMORY_WRITE_SIZE, STOP.STOP_VEX_LIFT_FAILED)):
            l.info(state.unicorn.stop_message)

        if state.unicorn.jumpkind.startswith('Ijk_Sys'):
            state.ip = state.unicorn._syscall_pc
        successors.add_successor(state, state.ip, state.solver.true, state.unicorn.jumpkind)

        successors.description = description
        successors.processed = True
