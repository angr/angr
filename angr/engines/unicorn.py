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
        if unicorn.countdown_symbolic_registers > 0:
            l.debug("not enough blocks since symbolic registers (%d more)", unicorn.countdown_symbolic_registers)
            return False
        if unicorn.countdown_symbolic_memory > 0:
            l.info("not enough blocks since symbolic memory (%d more)", unicorn.countdown_symbolic_memory)
            return False
        if unicorn.countdown_nonunicorn_blocks > 0:
            l.info("not enough runs since last unicorn (%d)", unicorn.countdown_nonunicorn_blocks)
            return False
        if unicorn.countdown_stop_point > 0:
            l.info("not enough blocks since stop point (%d more)", unicorn.countdown_stop_point)
        elif o.UNICORN_SYM_REGS_SUPPORT not in state.options and not unicorn._check_registers():
            l.info("failed register check")
            unicorn.countdown_symbolic_registers = unicorn.cooldown_symbolic_registers
            return False

        return True

    @staticmethod
    def __countdown(state):
        state.unicorn.countdown_nonunicorn_blocks -= 1
        state.unicorn.countdown_symbolic_registers -= 1
        state.unicorn.countdown_symbolic_memory -= 1
        state.unicorn.countdown_symbolic_memory -= 1
        state.unicorn.countdown_stop_point -= 1

    @staticmethod
    def __reset_countdowns(state, next_state):
        next_state.unicorn.countdown_symbolic_memory = state.unicorn.countdown_symbolic_memory
        next_state.unicorn.countdown_symbolic_registers = state.unicorn.countdown_symbolic_registers
        next_state.unicorn.countdown_nonunicorn_blocks = state.unicorn.countdown_nonunicorn_blocks
        next_state.unicorn.countdown_stop_point = state.unicorn.countdown_stop_point

    def _execute_instruction_in_vex(self, instr_entry):
        if instr_entry["block_addr"] not in self.vex_block_cache:
            vex_block_stmts = self._get_block_vex(instr_entry["block_addr"], instr_entry["block_size"])
            self.vex_block_cache[instr_entry["block_addr"]] = vex_block_stmts
        else:
            vex_block_stmts = self.vex_block_cache[instr_entry["block_addr"]]

        instr_vex_stmts = vex_block_stmts[instr_entry["instr_addr"]]
        for dep_entry in instr_entry["dependencies"]:
            if dep_entry["type"] == self.unicorn.TaintEntityEnum.TAINT_ENTITY_REG:
                # Set register
                reg_offset = dep_entry["reg_offset"]
                reg_value = dep_entry["reg_value"]
                setattr(self.state.regs, reg_offset, reg_value)
            elif dep_entry["type"] == self.unicorn.TaintEntityEnum.TAINT_ENTITY_MEM:
                # Set memory location value
                address = dep_entry["mem_address"]
                value = dep_entry["mem_value"]
                self.state.memory.store(address, value)

        for vex_stmt in instr_vex_stmts:
            # Execute handler from HeavyVEXMixin for the statement
            super()._handle_vex_stmt(vex_stmt)

        return

    def _execute_symbolic_instrs(self):
        instr_details_list = self.state.unicorn._get_details_of_instrs_to_execute_symbolically()
        for instr_detail_entry in instr_details_list:
            self._execute_instruction_in_vex(instr_detail_entry)

        return

    def _get_block_vex(self, block_addr, block_size):
        # Mostly based on the lifting code in HeavyVEXMixin
        irsb = super().lift_vex(addr=block_addr, state=self.state, size=block_size)
        if irsb.size == 0:
            if irsb.jumpkind == 'Ijk_NoDecode':
                if not self.state.project.is_hooked(irsb.addr):
                    raise SimIRSBNoDecodeError("IR decoding error at %#x. You can hook this instruction with "
                                            "a python replacement using project.hook"
                                            "(%#x, your_function, length=length_of_instruction)." % (irsb.addr, irsb.addr))
                else:
                    raise SimIRSBError("Block is hooked with custom code but original block was executed in unicorn")

            raise SimIRSBError("Empty IRSB found at %#x." % (irsb.addr))

        block_statements = {}
        curr_instr_addr = None
        curr_instr_stmts = []
        ignored_statement_tags = ["Ist_AbiHint", "Ist_MBE", "Ist_NoOP"]
        for statement in irsb.statements:
            if statement.tag == "Ist_IMark":
                if curr_instr_addr is not None:
                    block_statements[curr_instr_addr] = curr_instr_stmts
                    curr_instr_stmts = []

                curr_instr_addr = statement.addr
            elif statement.tag not in ignored_statement_tags:
                curr_instr_stmts.append(statement)

        return block_statements

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
        self.vex_block_cache = {}

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

        if state.unicorn.stop_reason == STOP.STOP_SYMBOLIC_BLOCK_EXIT_STMT:
            # Unicorn stopped at an instruction symbolic guard condition for exit statement.
            # Execute the instruction and stop.
            stopping_instr_block = self.unicorn.stopped_instr_block_details
            block_addr = stopping_instr_block.block_addr
            block_exit_instr_addr = stopping_instr_block.block_exit_instr_addr
            if block_addr not in self.block_details_cache:
                stopped_block_size = stopping_instr_block.block_size
                stopping_block_details = self._get_block_details(block_addr, stopped_block_size)
                self.block_details_cache[block_addr] = stopping_block_details
            else:
                stopping_block_details = self.block_details_cache[block_addr]

            stopping_block_stmts = stopping_block_details["statements"]
            stopping_block = stopping_block_details["block"]
            # self.state.scratch.set_tyenv(stopping_block.tyenv)
            stopping_instr_stmts = stopping_block_stmts[block_exit_instr_addr]
            for vex_stmt in stopping_instr_stmts:
                # Execute handler from HeavyVEXMixin for the statement
                super()._handle_vex_stmt(vex_stmt)
        elif state.unicorn.stop_reason in STOP.symbolic_stop_reasons:
            # Unicorn stopped for a symbolic data related reason. Switch to VEX engine.
            return super().process_successors(successors, **kwargs)
        elif state.unicorn.stop_reason in STOP.unsupported_reasons:
            # Unicorn stopped because of some unsupported VEX statement, VEX expression or some
            # other unsupported operation. Switch to VEX engine.
            l.warn(state.unicorn.stop_message)
            return super().process_successors(successors, **kwargs)
        else:
            if state.unicorn.jumpkind.startswith('Ijk_Sys'):
                state.ip = state.unicorn._syscall_pc
            successors.add_successor(state, state.ip, state.solver.true, state.unicorn.jumpkind)

        successors.description = description
        successors.processed = True

from ..state_plugins.unicorn_engine import STOP, _UC_NATIVE, unicorn as uc_module
from .. import sim_options as o
from ..misc.ux import once
