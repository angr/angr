from __future__ import annotations
import random

from ..func import Func, TestData


def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in range(length))
    return "".join(random.choice(byte_list) for _ in range(length))


class strcmp(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super().__init__()  # pylint disable=useless-super-delegation

    def get_name(self):
        return "strcmp"

    def num_args(self):
        return 2

    def args(self):  # pylint disable=no-self-use
        return ["buf1", "buf2"]

    def gen_input_output_pair(self):
        l = 5
        rand_str(l, strcmp.non_null)  # s

        return

    def can_call_other_funcs(self):
        return False

    def pre_test(self, func, runner):
        r = self._strcmp_pretest(func, runner)
        if not isinstance(r, bool):
            v1, v2, v3, v4 = r
            return v1 == 0 and v2 != 0 and v3 != 0 and v4 != 0
        return r

    @staticmethod
    def _strcmp_pretest(func, runner):
        # todo we don't test which order it returns the signs in
        bufa = "asdf\x00"
        bufb = "asdf\x00"
        test_input = [bufa, bufb]
        test_output = [bufa, bufb]
        max_steps = 10
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None or s.solver.eval(s.regs.eax) != 0:
            return False

        bufa = "asde\x00"
        bufb = "asde\x00"
        test_input = [bufa, bufb]
        test_output = [bufa, bufb]
        max_steps = 10
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None or s.solver.eval(s.regs.eax) != 0:
            return False

        # should return true for strcmp, false for memcpy
        bufa = "asdfa\x00sfdadfsa"
        bufb = "asdfa\x00sadfsadf"
        test_input = [bufa, bufb]
        test_output = [bufa, bufb]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval1 = s.solver.eval(s.regs.eax)

        # should fail
        bufa = "asdfc\x00as"
        bufb = "asdfb\x0011232"
        test_input = [bufa, bufb]
        test_output = [bufa, bufb]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval2 = s.solver.eval(s.regs.eax)

        # should prevent us from misidentifying strcasecmp
        bufa = "ASDFC\x00"
        bufb = "asdfc\x00"
        test_input = [bufa, bufb]
        test_output = [bufa, bufb]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval3 = s.solver.eval(s.regs.eax)

        # should distinguish between strcmp and strncmp
        bufa = "abc555"
        bufb = "abc666"
        test_input = [bufa, bufb, 3]
        test_output = [bufa, bufb, 3]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval4 = s.solver.eval(s.regs.eax)

        return outval1, outval2, outval3, outval4
