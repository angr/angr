
import random
import struct

from ..func import Func, TestData

def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in range(length))
    return "".join(random.choice(byte_list) for _ in range(length))


class receive_n4(Func):
    # fd buf size rx_bytes
    # fd buf size
    # buf size
    def __init__(self):
        super(receive_n4, self).__init__()  #pylint disable=useless-super-delegation

    def get_name(self):
        return "receive_n4"

    def num_args(self):
        return 4

    def args(self):
        return ["fd", "buf", "len", "rxbytes"]

    def gen_input_output_pair(self): #pylint disable=no-self-use
        max_len = random.randint(1, 10)
        buf = rand_str(max_len+5)
        result_buf = "ZZZZ"
        test_input = [0, buf, max_len, result_buf]
        stdin = rand_str(max_len+5)
        outbuf = stdin[:max_len]
        test_output = [None, outbuf, None, struct.pack("<I", max_len)]
        max_steps = max_len*4 + 10
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        return test

    def pre_test(self, func, runner):
        return True


class receive_n3(Func):
    # fd buf size rx_bytes
    # fd buf size
    # buf size
    def __init__(self):
        super(receive_n3, self).__init__()  #pylint disable=useless-super-delegation

    def get_name(self):
        return "receive_n3"

    def num_args(self):
        return 3

    def args(self):
        return ["fd", "buf", "len"]

    def gen_input_output_pair(self): #pylint disable=no-self-use
        max_len = random.randint(1, 10)
        buf = rand_str(max_len+5)
        test_input = [0, buf, max_len]
        stdin = rand_str(max_len+5)
        outbuf = stdin[:max_len]
        test_output = [None, outbuf, None]
        max_steps = max_len * 4 + 10
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        return test

    def pre_test(self, func, runner):
        return True

class receive_n2(Func):
    # fd buf size rx_bytes
    # fd buf size
    # buf size
    def __init__(self):
        super(receive_n2, self).__init__()  #pylint disable=useless-super-delegation

    def get_name(self):
        return "receive_n2"

    def num_args(self):
        return 2

    def args(self):
        return ["buf", "len"]

    def gen_input_output_pair(self): #pylint disable=no-self-use
        max_len = random.randint(1, 10)
        buf = rand_str(max_len+5)
        test_input = [buf, max_len]
        stdin = rand_str(max_len+5)
        outbuf = stdin[:max_len]
        test_output = [outbuf, None]
        max_steps = max_len * 4 + 10
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        return test

    def pre_test(self, func, runner):
        return True
