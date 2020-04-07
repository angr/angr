import logging

from ..errors import SimValueError
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
        if state.project.concrete_target:
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

        if state.unicorn.jumpkind.startswith('Ijk_Sys'):
            state.ip = state.unicorn._syscall_pc
        successors.add_successor(state, state.ip, state.solver.true, state.unicorn.jumpkind)

        successors.description = description
        successors.processed = True

from ..state_plugins.unicorn_engine import STOP, _UC_NATIVE, unicorn as uc_module
from .. import sim_options as o
from ..misc.ux import once
