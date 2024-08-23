from __future__ import annotations
import random
import string

from ..func import Func, TestData


digs = string.digits + string.ascii_letters


def int2base(x, base):
    if x < 0:
        sign = -1
    elif x == 0:
        return digs[0]
    else:
        sign = 1
    x *= sign
    digits = []
    while x:
        digits.append(digs[x % base])
        x //= base
    if sign < 0:
        digits.append("-")
    digits.reverse()
    return "".join(digits)


class strtol(Func):
    def __init__(self):
        super().__init__()
        self.skips_whitespace = False
        self.version = ""

    def rand_str(self, length, byte_list=None):  # pylint disable=no-self-use
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in range(length))
        return "".join(random.choice(byte_list) for _ in range(length))

    def num_args(self):  # pylint disable=no-self-use
        return 3

    def args(self):  # pylint disable=no-self-use
        return ["nptr", "endpointer", "base"]

    def get_name(self):
        return "strtol" + self.version

    def gen_input_output_pair(self):
        num = random.randint(-(2**31), 2**31 - 1)

        base = random.randint(2, 16)
        s = int2base(num, base)
        test_input = [s, 0, base]
        test_output = [s, None, None]
        return_val = num
        max_steps = 20
        return TestData(test_input, test_output, return_val, max_steps)

    def pre_test(self, func, runner):
        num = random.randint(-(2**31), 2**31 - 1)

        s = str(num)
        test_input = [s, 0, 10]
        test_output = [s, None, None]
        return_val = num
        max_steps = 20
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False

        s = str(num)
        s = self.rand_str(10, string.whitespace) + s
        test_input = [s, 0, 10]
        test_output = [s, None, None]
        return_val = num
        max_steps = 20
        test = TestData(test_input, test_output, return_val, max_steps)
        self.skips_whitespace = runner.test(func, test)

        # base 0
        base = 0
        s = hex(num)
        test_input = [s, 0, base]
        test_output = [s, None, None]
        return_val = num
        max_steps = 20
        test = TestData(test_input, test_output, return_val, max_steps)
        return runner.test(func, test)
