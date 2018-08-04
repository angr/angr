import random

from ..func import Func, TestData


def rand_str(length, byte_list=None):
    if byte_list is None:
        return bytes(random.randint(0, 255) for _ in range(length))
    return bytes(random.choice(byte_list) for _ in range(length))


class strncpy(Func):
    non_null = list(range(1, 256))

    def __init__(self):
        super(strncpy, self).__init__()
        self.forced_null = False

    def get_name(self):
        if self.forced_null:
            return "strncpy_null"
        return "strncpy"

    def num_args(self):
        return 3

    def args(self): #pylint disable=no-self-use
        return ["dst", "src", "len"]

    def can_call_other_funcs(self):
        return False

    def gen_input_output_pair(self):
        # TODO we don't check the return val, some cases I saw char * strcpy, some size_t strcpy
        strlen = random.randint(1, 20)
        max_len = random.randint(1, 10)
        buf = rand_str(strlen, byte_list=strncpy.non_null) + b"\x00"
        result_buf = rand_str(strlen+1)
        test_input = [result_buf, buf, max_len]
        outlen = min(max_len, strlen+1)
        test_output = [buf[:outlen], buf, None]
        max_steps = 5
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):

        # check only copies up to null
        test_input = ["A"*7, "abc\x00ccc", 7]
        test_output = ["abc\x00AAA", "abc\x00ccc", None]
        max_steps = 5
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False
        # check has a max to copy
        test_input = ["A" * 7, "ccccccc", 3]
        test_output = ["cccAAAA", "ccccccc", 7]
        max_steps = 5
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)

        if not runner.test(func, test):
            self.forced_null = True
        return True
