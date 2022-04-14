
import random
import string

from ..func import Func, TestData


class atoi(Func):
    def __init__(self):
        super(atoi, self).__init__()
        self.skips_whitespace = False
        self.allows_negative = True

    def rand_str(self, length, byte_list=None): #pylint disable=no-self-use
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in range(length))
        return "".join(random.choice(byte_list) for _ in range(length))

    def num_args(self):
        return 1

    def get_name(self):
        if self.allows_negative:
            suffix = ""
        else:
            suffix = "_no_signs"
        if self.skips_whitespace:
            return "atoi_whitespace_skip" + suffix
        return "atoi" + suffix

    def gen_input_output_pair(self):
        num = random.randint(-(2**26), 2**26-1)

        if not self.allows_negative:
            num = abs(num)

        s = str(num)
        test_input = [s]
        test_output = [s]
        return_val = num
        max_steps = 20
        return TestData(test_input, test_output, return_val, max_steps)

    def pre_test(self, func, runner):
        num = random.randint(-(2 ** 26), 2 ** 26 - 1)

        num = abs(num)
        s = str(num)
        test_input = [s]
        test_output = [s]
        return_val = num
        max_steps = 20
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False

        s = str(num)
        s = self.rand_str(10, string.whitespace) + s
        test_input = [s]
        test_output = [s]
        return_val = num
        max_steps = 20
        test = TestData(test_input, test_output, return_val, max_steps)
        self.skips_whitespace = runner.test(func, test)

        num = -random.randint(2000, 8000)
        s = str(num)
        test_input = [s]
        test_output = [s]
        return_val = num
        max_steps = 20
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            self.allows_negative = False

        return True
