try:
    import unicorn
except ImportError:
    pass

import logging
l = logging.getLogger('simuvex.s_unicorn')

from .s_run import SimRun

class SimUnicorn(SimRun):
    ''' concrete exection in unicorn engine '''

    def __init__(self, state, step=None, stop_points=None, force_bbl_addr=None, **kwargs):
        '''
        :param state: current state
        :param step: how many basic blocks we want to execute. now we only
            support single step.
        '''
        SimRun.__init__(self, state, **kwargs) # use inline to avoid copying states

        self.addr = state.se.any_int(state.ip)
        self.state.scratch.bbl_addr = self.addr if force_bbl_addr is None else force_bbl_addr

        if stop_points is not None and self.addr in stop_points:
            raise SimUnicornError("trying to start unicorn execution on a stop point")

        # initialize unicorn plugin
        self.state.unicorn.setup()
        try:
            self.state.unicorn.set_stops(stop_points)
            self.state.unicorn.hook()
            self.state.unicorn.start(step=step)
            self.state.unicorn.finish()
        finally:
            self.state.unicorn.destroy()

        self.stop_reason = self.state.unicorn.stop_reason
        try:
            self.end_addr = self.state.scratch.bbl_addr_list[-1]
        except IndexError:
            self.end_addr = self.addr

        if self.state.unicorn.errno:
            # error from unicorn
            err = str(unicorn.UcError(self.state.unicorn.errno))
            self.initial_state.unicorn.countdown_symbolic_memory = self.state.unicorn.countdown_symbolic_memory
            self.initial_state.unicorn.countdown_symbolic_registers = self.state.unicorn.countdown_symbolic_registers
            self.initial_state.unicorn.countdown_nonunicorn_blocks = self.state.unicorn.countdown_nonunicorn_blocks
            raise SimUnicornError(err)
        elif self.state.unicorn.steps == 0:
            self.initial_state.unicorn.countdown_symbolic_memory = self.state.unicorn.countdown_symbolic_memory
            self.initial_state.unicorn.countdown_symbolic_registers = self.state.unicorn.countdown_symbolic_registers
            self.initial_state.unicorn.countdown_nonunicorn_blocks = self.state.unicorn.countdown_nonunicorn_blocks
            raise SimUnicornError("Didn't take any steps in Unicorn (error: %s)" % self.state.unicorn.error)

        self.state.scratch.executed_block_count += self.state.unicorn.steps

        if self.state.unicorn.jumpkind.startswith('Ijk_Sys'):
            self.state.ip = self.state.unicorn._syscall_pc
        self.add_successor(self.state, self.state.ip, self.state.se.true, self.state.unicorn.jumpkind)

    def __repr__(self):
        return "<SimUnicorn %#x-%#x with %d steps (%s)>" % (self.addr, self.end_addr, self.state.unicorn.steps, STOP.name_stop(self.stop_reason))

from .s_errors import SimUnicornError
from .plugins.unicorn_engine import STOP
