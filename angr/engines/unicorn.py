import logging

from ..errors import SimIRSBError, SimIRSBNoDecodeError, SimValueError
from .engine import SuccessorsMixin
from ..state_plugins.inspect import BP_AFTER

#pylint: disable=arguments-differ

l = logging.getLogger(name=__name__)


class SimEngineUnicorn(SuccessorsMixin):
    """
    Concrete execution in the Unicorn Engine, a fork of qemu.

    Responds to the following parameters in the step stack:

    - step:                How many basic blocks we want to execute
    - extra_stop_points:   A collection of addresses at which execution should halt
    """

    def __check(self, num_inst=None, **kwargs):
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
            l.info("not enough blocks since unsupported VEX statement/expression stop (%d more)", unicorn.countdown_unsupported_stop)
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

        vex_block = vex_block_details["block"]
        for reg_name, reg_value in block_details["registers"]:
            self.state.registers.store(reg_name, reg_value, inspect=False, disable_actions=True)

        # VEX statements to ignore when re-executing instructions that touched symbolic data
        ignored_statement_tags = ["Ist_AbiHint", "Ist_IMark", "Ist_MBE", "Ist_NoOP"]
        self.state.scratch.set_tyenv(vex_block.tyenv)
        for instr_entry in block_details["instrs"]:
            saved_memory_values = {}
            for memory_val in instr_entry["mem_dep"]:
                address = memory_val["address"]
                value = memory_val["value"]
                size = memory_val["size"]
                curr_value = self.state.memory.load(address, size=size, endness=self.state.arch.memory_endness)
                # Save current memory value for restoring later
                saved_memory_values[address] = (curr_value, size)
                self.state.memory.store(address, value, size=size, endness=self.state.arch.memory_endness)

            instr_vex_stmt_indices = vex_block_details["stmt_indices"][instr_entry["instr_addr"]]
            start_index = instr_vex_stmt_indices["start"]
            end_index = instr_vex_stmt_indices["end"]
            for vex_stmt_idx in range(start_index, end_index + 1):
                # Execute handler from HeavyVEXMixin for the statement
                vex_stmt = vex_block.statements[vex_stmt_idx]
                if vex_stmt.tag not in ignored_statement_tags:
                    self.stmt_idx = vex_stmt_idx  # pylint:disable=attribute-defined-outside-init
                    super()._handle_vex_stmt(vex_stmt)  # pylint:disable=no-member

            # Restore previously saved value
            for address, (value, size) in saved_memory_values.items():
                curr_value = self.state.memory.load(address, size=size, endness=self.state.arch.memory_endness)
                if not curr_value.symbolic:
                    # Restore the saved value only if current value is not symbolic. If it is, that would mean the value
                    # was changed by re-executing the block in VEX engine
                    self.state.memory.store(address, value, size=size, endness=self.state.arch.memory_endness)

        del self.stmt_idx

    def _execute_symbolic_instrs(self):
        for block_details in self.state.unicorn._get_details_of_blocks_with_symbolic_instrs():
            try:
                self._execute_block_instrs_in_vex(block_details)
            except SimValueError as e:
                l.error(e)

    def _get_vex_block_details(self, block_addr, block_size):
        # Mostly based on the lifting code in HeavyVEXMixin
        irsb = super().lift_vex(addr=block_addr, state=self.state, size=block_size)    # pylint:disable=no-member
        if irsb.size == 0:
            if irsb.jumpkind == 'Ijk_NoDecode':
                if not self.state.project.is_hooked(irsb.addr):
                    raise SimIRSBNoDecodeError("IR decoding error at %#x. You can hook this instruction with "
                                            "a python replacement using project.hook"
                                            "(%#x, your_function, length=length_of_instruction)." % (irsb.addr, irsb.addr))

                raise SimIRSBError("Block is hooked with custom code but original block was executed in unicorn")

            raise SimIRSBError("Empty IRSB found at %#x." % (irsb.addr))

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

    def process_successors(self, successors, **kwargs):
        state = self.state
        if not self.__check(**kwargs):
            return super().process_successors(successors, **kwargs)

        extra_stop_points = kwargs.get('extra_stop_points', None)
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
            # TODO: idk what the consequences of this might be. If this failed step can actually change non-unicorn state then this is bad news.
            return super().process_successors(successors, **kwargs)

        description = 'Unicorn (%s after %d steps)' % (STOP.name_stop(state.unicorn.stop_reason), state.unicorn.steps)

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

from ..state_plugins.unicorn_engine import STOP, _UC_NATIVE, unicorn as uc_module
from .. import sim_options as o
from ..misc.ux import once
