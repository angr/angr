import random

from ..func import Func, TestData


def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in range(length))
    return "".join(random.choice(byte_list) for _ in range(length))


class memcmp(Func):
    def __init__(self):
        super().__init__()  # pylint disable=useless-super-delegation

    def get_name(self):
        return "memcmp"

    def num_args(self):
        return 3

    def args(self):  # pylint disable=no-self-use
        return ["buf1", "buf2", "len"]

    def gen_input_output_pair(self):
        return None

    def can_call_other_funcs(self):
        return False

    def pre_test(self, func, runner):
        # todo we don't test which order it returns the signs in
        l = random.randint(1, 20)
        bufb = rand_str(l)
        bufa = bufb + rand_str(5)
        test_input = [bufa, bufb, l]
        test_output = [bufa, bufb, l]
        max_steps = 10
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None or s.solver.eval(s.regs.eax) != 0:
            return False

        bufa = "asd\x00a"
        bufb = "asd\x00a"
        test_input = [bufa, bufb, 5]
        test_output = [bufa, bufb, 5]
        test = TestData(test_input, test_output, return_val, max_steps)
        x = runner.get_out_state(func, test)
        if x is None:
            return False
        outval1 = x.solver.eval(x.regs.eax)

        bufa = "asd\x00c"
        bufb = "asd\x00b"
        test_input = [bufa, bufb, 5]
        test_output = [bufa, bufb, 5]
        test = TestData(test_input, test_output, return_val, max_steps)
        s = runner.get_out_state(func, test)
        if s is None:
            return False

        outval2 = s.solver.eval(s.regs.eax)

        if outval1 != 0 or outval2 == 0:
            return False

        return True
