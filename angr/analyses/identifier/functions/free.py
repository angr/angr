
import logging

from ..func import Func, TestData
from ..errors import IdentifierException


l = logging.getLogger(name=__name__)


class free(Func):
    def __init__(self):
        super(free, self).__init__() #pylint disable=useless-super-delegation

    def num_args(self):
        return 1

    def get_name(self):
        return "free"

    def gen_input_output_pair(self):
        return None

    def pre_test(self, func, runner):
        # free should not be identified here
        return False

    def try_match(self, func, identifier, runner): #pylint disable=no-self-use
        malloc = None
        for k, v in identifier.matches.items():
            if v[0] == "malloc":
                malloc = k
        if malloc is None:
            return False

        num = 0x80
        test_input = [num]
        test_output = [None]
        return_val = None
        max_steps = 10
        malloc_test = TestData(test_input, test_output, return_val, max_steps)

        malloc_vals = []
        state = None
        for i in range(10): #pylint disable=unused-variable
            state = runner.get_out_state(malloc, malloc_test, initial_state=state)
            if state is None:
                l.critical("malloc failed")
                raise IdentifierException("malloc failed")
            malloc_vals.append(state.solver.eval(state.regs.eax))
            if malloc_vals[-1] < 0x10000:
                return False
            test_input = [malloc_vals[-1]]
            test_output = [None]
            return_val = None
            state.memory.store(malloc_vals[-1], state.solver.BVS("some_data", 0x80*8))
            free_test = TestData(test_input, test_output, return_val, max_steps)
            state = runner.get_out_state(func, free_test, initial_state=state)
            if state is None:
                return False

        if len(malloc_vals) == len(set(malloc_vals)):
            return False

        return True
