import random

from ..func import Func, TestData


def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in range(length))
    return "".join(random.choice(byte_list) for _ in range(length))


class memset(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super().__init__()  # pylint disable=useless-super-delegation

    def get_name(self):
        return "memset"

    def num_args(self):
        return 3

    def args(self):  # pylint disable=no-self-use
        return ["buf", "char", "size"]

    def can_call_other_funcs(self):
        return False

    def gen_input_output_pair(self):
        # TODO we don't check the return val
        set_len = random.randint(1, 40)
        char = random.randint(0, 255)
        result_buf = rand_str(set_len + 5)
        test_input = [result_buf, char, set_len]
        test_output = [chr(char) * set_len + result_buf[-5:], None, None]
        max_steps = 20
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):
        return True
