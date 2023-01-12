import random

from ..func import Func, TestData


def rand_str(length, byte_list=None):
    if byte_list is None:
        return bytes(random.randint(0, 255) for _ in range(length))
    return bytes(random.choice(byte_list) for _ in range(length))


class strcpy(Func):
    non_null = list(range(1, 256))

    def __init__(self):
        super().__init__()  # pylint disable=useless-super-delegation

    def get_name(self):
        return "strcpy"

    def num_args(self):
        return 2

    def args(self):  # pylint disable=no-self-use
        return ["dst", "src"]

    def can_call_other_funcs(self):
        return False

    def gen_input_output_pair(self):
        # TODO we don't check the return val, some cases I saw char * strcpy, some size_t strcpy
        strlen = random.randint(1, 80)
        buf = rand_str(strlen, byte_list=strcpy.non_null) + b"\x00"
        result_buf = rand_str(strlen + 1)
        test_input = [result_buf, buf]
        test_output = [buf, buf]
        max_steps = 20
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):
        return True
