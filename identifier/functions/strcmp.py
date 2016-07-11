from ..func import Func, TestData
import random
import itertools
import struct

from ..errors import FunctionNotInitialized

def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
    return "".join(random.choice(byte_list) for _ in xrange(length))


class strcmp(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super(strcmp, self).__init__()

    def get_name(self):
        return "strcmp"

    def num_args(self):
        return 2

    def args(self):
        return ["buf1", "buf2"]

    def gen_input_output_pair(self):
        l = 5
        s = rand_str(l, strcmp.non_null)

        return None

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
        if s is None or s.se.any_int(s.regs.eax) != 0:
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
        outval1 = s.se.any_int(s.regs.eax)

        # should fail
        bufa = "asdfc\x00as"
        bufb = "asdfb\x0011232"
        test_input = [bufa, bufb]
        test_output = [bufa, bufb]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval2 = s.se.any_int(s.regs.eax)

        # should prevent us from misidentifying strcasecmp
        bufa = "ASDFC\x00"
        bufb = "asdfc\x00"
        test_input = [bufa, bufb]
        test_output = [bufa, bufb]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval3 = s.se.any_int(s.regs.eax)

        return outval1, outval2, outval3

    def pre_test(self, func, runner):
        r = self._strcmp_pretest(func, runner)
        if not isinstance(r, bool):
            v1, v2, v3 = r
            return v1 == 0 and v2 != 0 and v3 != 0
        return r
