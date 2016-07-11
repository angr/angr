from ..func import Func, TestData
import random
import itertools
import struct

from ..errors import FunctionNotInitialized

def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
    return "".join(random.choice(byte_list) for _ in xrange(length))


class memcpy(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super(memcpy, self).__init__()

    def get_name(self):
        return "memcpy"

    def num_args(self):
        return 3

    def args(self):
        return ["dst", "src", "len"]

    def gen_input_output_pair(self):
        # TODO we don't check the return val
        copy_len = random.randint(1,40)
        buf = rand_str(copy_len)
        result_buf = rand_str(copy_len+5)
        test_input = [result_buf, buf, copy_len]
        test_output = [buf + result_buf[-5:], buf, None]
        max_steps = 20
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):

        result_buf = "A" * 6
        in_buf = "a\x00bbbc"

        test_input = [result_buf, in_buf, 6]
        test_output = [in_buf, in_buf, None]
        max_steps = 20
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        result = runner.test(func, test)

        return result
