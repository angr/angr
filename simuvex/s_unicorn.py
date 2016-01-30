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

        # initialize unicorn plugin
        uc = self.state.unicorn
        uc.set_state(self.state)

        uc.hook()
        uc.start(step=step)
        uc.finish()
        
        # FIXME what's this?
        guard = self.state.se.true

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
            if v.symbolic:
                l.debug('detected symbolic register')
                return False
        l.debug('passed quick check')
        return True


from .s_errors import SimUnicornUnsupport
from .plugins.unicorn_engine import Unicorn

