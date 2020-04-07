
from ..func import Func, TestData
from ....errors import SimMemoryError


class malloc(Func):
    def __init__(self):
        super(malloc, self).__init__() #pylint disable=useless-super-delegation

    def num_args(self):
        return 1

    def get_name(self):
        return "malloc"

    def gen_input_output_pair(self):
        return None

    def pre_test(self, func, runner):
        # we should not get a real output from the function with a value this large
        num = 0xffff0000
        test_input = [num]
        test_output = [None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        state = runner.get_out_state(func, test, concrete_rand=True)
        if state is not None and 0x10 < state.solver.eval(state.regs.eax) < 0xfffffff0:
            return False

        # we should be able to get different outputs if we call malloc multiple times
        num = 0x80
        test_input = [num]
        test_output = [None]
        return_val = None

        max_steps = 40
        test = TestData(test_input, test_output, return_val, max_steps)
        returned_locs = []
        state = runner.get_out_state(func, test, concrete_rand=True)
        if state is None:
            return False
        returned_locs.append(state.solver.eval(state.regs.eax))

        for i in range(6): #pylint disable=unused-variable
            state = runner.get_out_state(func, test, initial_state=state, concrete_rand=True)
            if state is None:
                return False
            returned_locs.append(state.solver.eval(state.regs.eax))
            if any(a < 0x3000 for a in returned_locs):
                return False

        # if we got the same value 2x it didnt work
        if len(set(returned_locs)) != len(returned_locs):
            return False

        # if we got 0 it didn't work
        if any(a == 0 for a in returned_locs):
            return False

        # if they are all multiples of 0x1000 it seems to be always calling allocate
        if all(a % 0x1000 == returned_locs[0] % 0x1000 for a in returned_locs):
            return False

        # they all should be writable/readable
        try:
            if any(state.solver.eval(state.memory.permissions(a)) & 3 != 3 for a in returned_locs):
                return False
        except SimMemoryError:
            return False

        # we should be able to call malloc 0xf00 afterwards
        num = 0xf00
        test_input = [num]
        test_output = [None]
        return_val = None

        max_steps = 40
        test = TestData(test_input, test_output, return_val, max_steps)
        returned_locs = []
        state = runner.get_out_state(func, test, initial_state=state, concrete_rand=True)

        if state is None:
            return False

        res = state.solver.eval(state.regs.eax)
        if res < 0x10 or res > 0xfffffff0:
            return False

        # we should get different values if we try with a different size
        num = 0x320
        test_input = [num]
        test_output = [None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        returned_locs2 = []
        state = runner.get_out_state(func, test, concrete_rand=True)
        if state is None:
            return False
        returned_locs2.append(state.solver.eval(state.regs.eax))

        for i in range(10):
            state = runner.get_out_state(func, test, initial_state=state, concrete_rand=True)
            if state is None:
                return False
            returned_locs2.append(state.solver.eval(state.regs.eax))
            if any(a < 0x3000 for a in returned_locs2):
                return False

        if returned_locs == returned_locs2:
            return False

        return True
