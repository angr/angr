import angr
import random

class srand(angr.SimProcedure):
    def run(self, seed):
        seed = self.state.solver.eval(seed)
        if not hasattr(self.project, 'random'):
            setattr(self.project, 'random', random.Random())
        
        self.project.random.seed(seed)
        self.ret()
