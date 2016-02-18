try:
    import unicorn
except ImportError:
    pass

import logging
l = logging.getLogger('simuvex.s_unicorn')

from .s_run import SimRun

class SimUnicorn(SimRun):
    ''' concrete exection in unicorn engine '''

    def __init__(self, state, step=1, **kwargs):
        '''
        :param state: current state
        :param step: how many basic blocks we want to execute. now we only
            support single step.
        '''
        SimRun.__init__(self, state, inline=True, **kwargs) # use inline to avoid copying states

        self.addr = state.se.any_int(state.ip)
        self.state.scratch.bbl_addr = self.addr

        # initialize unicorn plugin
        uc = self.state.unicorn
        uc.set_state(self.state)

        uc.hook()
        uc.start(step=step)
        uc.finish()

        self.success = True
        
        # FIXME what's this?
        guard = self.state.se.true

        if uc.stop_reason == STOP.STOP_SYMBOLIC:
            self.success = False

        if uc.error is not None:
            # error from hook
            self.success = False
            raise SimUnicornError(uc.error)

        if uc.errno:
            # error from unicorn
            self.success = False
            raise unicorn.UcError(uc.errno)

        if uc.jumpkind.startswith('Ijk_Sys'):
            self.state.ip = uc._syscall_pc
            self.add_successor(self.state, self.state.ip, guard, uc.jumpkind)
        else:
            self.add_successor(self.state, self.state.ip, guard, uc.jumpkind)

    @staticmethod
    def quick_check(state):
        ''' check if this state might be used in unicorn (has no concrete register)'''
        try:
            _, _, uc_regs, _ = Unicorn.load_arch(state.arch)
        except (NotImplementedError) as e:
            raise
            return False
        except Exception as e:
            raise
            return False
        for r in uc_regs.iterkeys():
            v = getattr(state.regs, r)
            if not state.se.unique(v):
                l.debug('detected symbolic register')
                return False
        l.debug('passed quick check')
        return True


from .s_errors import SimUnicornUnsupport, SimUnicornError
from .plugins.unicorn_engine import Unicorn, STOP

