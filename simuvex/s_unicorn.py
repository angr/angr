try:
    import unicorn
except ImportError:
    pass

import logging
l = logging.getLogger('simuvex.s_unicorn')

from .s_run import SimRun

class SimUnicorn(SimRun):
    ''' concrete exection in unicorn engine '''

    def __init__(self, state, step=1, stop_points=None, **kwargs):
        '''
        :param state: current state
        :param step: how many basic blocks we want to execute. now we only
            support single step.
        '''
        SimRun.__init__(self, state, **kwargs) # use inline to avoid copying states

        self.addr = state.se.any_int(state.ip)
        self.state.scratch.bbl_addr = self.addr

        # initialize unicorn plugin
        self.state.unicorn.setup()
        try:
            self.state.unicorn.set_stops(stop_points)
            self.state.unicorn.hook()
            self.state.unicorn.start(step=step)
            self.state.unicorn.finish()
        finally:
            self.state.unicorn.destroy()

        self.success = True
        self.state.scratch.executed_block_count += self.state.unicorn.steps

        # FIXME what's this?
        guard = self.state.se.true

        if self.state.unicorn.stop_reason == STOP.STOP_SYMBOLIC:
            self.success = self.state.unicorn.steps > 0

        if self.state.unicorn.error is not None:
            # error from hook
            self.success = False
            raise SimUnicornError(self.state.unicorn.error)

        if self.state.unicorn.errno:
            # error from unicorn
            self.success = False
            raise unicorn.UcError(self.state.unicorn.errno)

        if self.state.unicorn.jumpkind.startswith('Ijk_Sys'):
            self.state.ip = self.state.unicorn._syscall_pc
            self.add_successor(self.state, self.state.ip, guard, self.state.unicorn.jumpkind)
        else:
            self.add_successor(self.state, self.state.ip, guard, self.state.unicorn.jumpkind)

    def __repr__(self):
        return "<SimUnicorn from %#x with %d steps>" % (self.addr, self.state.unicorn.steps)

from .s_errors import SimUnicornError
from .plugins.unicorn_engine import STOP
