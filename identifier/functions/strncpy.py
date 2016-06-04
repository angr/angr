from ..func import Func, TestData
import random
import itertools
import struct

from ..errors import FunctionNotInitialized

def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
    return "".join(random.choice(byte_list) for _ in xrange(length))


class strncpy(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super(strncpy, self).__init__()

    def get_name(self):
        return "strncpy"

    def num_args(self):
        return 3

    def args(self):
        return ["dst", "src", "len"]

    def gen_input_output_pair(self):
        # TODO we don't check the return val, some cases I saw char * strcpy, some size_t strcpy
        strlen = random.randint(1, 80)
        max_len = random.randint(1,40)
        buf = rand_str(strlen, byte_list=strncpy.non_null) + "\x00"
        result_buf = rand_str(strlen+1)
        test_input = [result_buf, buf, max_len]
        outlen = min(max_len, strlen+1)
        test_output = [buf[:outlen], buf, None]
        max_steps = 20
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):
        return True
