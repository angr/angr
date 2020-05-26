import angr
import random

class rand(angr.SimProcedure):
    RAND_MAX = 32767
    def run(self):
        # rval = self.state.solver.BVS('rand', 31, key=('api', 'rand'))
        # rval = rval.zero_extend(self.state.arch.bits - 31)

        if not hasattr(self.project, 'random'):
            setattr(self.project, 'random', random.Random())
        
        value = self.project.random.randint(0, self.RAND_MAX)
        return value
