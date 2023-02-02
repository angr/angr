import random

from ..func import Func, TestData


def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in range(length))
    return "".join(random.choice(byte_list) for _ in range(length))


class strncmp(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super().__init__()  # pylint disable=useless-super-delegation

    def get_name(self):
        return "strncmp"

    def num_args(self):
        return 3

    def args(self):  # pylint disable=no-self-use
        return ["buf1", "buf2", "len"]

    def gen_input_output_pair(self):
        l = 5
        rand_str(l, strncmp.non_null)  # s
        return None

    def can_call_other_funcs(self):
        return False

    def pre_test(self, func, runner):
        # todo we don't test which order it returns the signs in
        bufa = "asdf\x00"
        bufb = "asdf\x00"
        test_input = [bufa, bufb, 5]
        test_output = [bufa, bufb, 5]
        max_steps = 10
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None or s.solver.eval(s.regs.eax) != 0:
            return False

        # should return true for strcmp, false for memcpy
        bufa = "asdfa\x00sfdadfsa"
        bufb = "asdfa\x00sadfsadf"
        test_input = [bufa, bufb, 10]
        test_output = [bufa, bufb, 10]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval1 = s.solver.eval(s.regs.eax)

        # should fail
        bufa = "asdfc\x00as"
        bufb = "asdfb\x0011232"
        test_input = [bufa, bufb, 10]
        test_output = [bufa, bufb, 10]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval2 = s.solver.eval(s.regs.eax)

        # should prevent us from misidentifying strcasecmp
        bufa = "ASDFC\x00"
        bufb = "asdfc\x00"
        test_input = [bufa, bufb, 5]
        test_output = [bufa, bufb, 5]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval3 = s.solver.eval(s.regs.eax)

        # should distinguish strncmp and strcmp
        bufa = "abc5555"
        bufb = "abc6666"
        test_input = [bufa, bufb, 3]
        test_output = [bufa, bufb, 3]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval4 = s.solver.eval(s.regs.eax)

        # should distinguish strncmp and strcmp
        bufa = "abc5555"
        bufb = "abc6666"
        test_input = [bufa, bufb, 6]
        test_output = [bufa, bufb, 6]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False
        outval5 = s.solver.eval(s.regs.eax)

        return outval1 == 0 and outval2 != 0 and outval3 != 0 and outval4 == 0 and outval5 != 0
