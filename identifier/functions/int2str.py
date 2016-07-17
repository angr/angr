from ..func import Func, TestData
import random
import string

digs = string.digits + string.letters


class int2str(Func):
    def __init__(self):
        super(int2str, self).__init__()
        self.is_signed = False

    def rand_str(self, length, byte_list=None):
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
        return "".join(random.choice(byte_list) for _ in xrange(length))

    def num_args(self):
        return 3

    def args(self):
        return ["buf", "len", "val"]

    def get_name(self):
        if self.is_signed:
            return "int2str"
        else:
            return "uint2str"

    def gen_input_output_pair(self):
        num = random.randint(-(2 ** 31), 2 ** 31 - 1)
        if not self.is_signed:
            num = abs(num)
        s = str(num)
        test_input = ["A"*15, 15, num]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):
        num = random.randint(-(2 ** 31), 2 ** 31 - 1)
        num = abs(num)
        s = str(num)
        test_input = ["A"*15, 15, num]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False

        num = random.randint(-(2 ** 31), 2 ** 31 - 1)
        num = -abs(num)
        s = str(num)
        test_input = ["A"*15, 15, num]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            self.is_signed = False
        else:
            self.is_signed = True


        return True


class int2str_v2(Func):
    def __init__(self):
        super(int2str_v2, self).__init__()
        self.is_signed = False

    def rand_str(self, length, byte_list=None):
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
        return "".join(random.choice(byte_list) for _ in xrange(length))

    def num_args(self):
        return 2

    def args(self):
        return ["val", "buf"]

    def get_name(self):
        if self.is_signed:
            return "int2str_v2"
        else:
            return "uint2str_v2"

    def gen_input_output_pair(self):
        num = random.randint(-(2 ** 31), 2 ** 31 - 1)
        if not self.is_signed:
            num = abs(num)
        s = str(num)
        test_input = [num, "A"*15]
        test_output = [None, s]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):
        num = random.randint(-(2 ** 31), 2 ** 31 - 1)
        num = abs(num)
        s = str(num)
        test_input = [num, "A"*15]
        test_output = [None, s]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False

        num = random.randint(-(2 ** 31), 2 ** 31 - 1)
        num = -abs(num)
        s = str(num)
        test_input = [num, "A"*15]
        test_output = [None, s]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            self.is_signed = False
        else:
            self.is_signed = True

        return True


class int2str_v3(Func):
    def __init__(self):
        super(int2str_v3, self).__init__()
        self.is_signed = False

    def rand_str(self, length, byte_list=None):
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
        return "".join(random.choice(byte_list) for _ in xrange(length))

    def num_args(self):
        return 2

    def args(self):
        return ["buf", "val"]

    def get_name(self):
        if self.is_signed:
            return "int2str_v3"
        else:
            return "uint2str_v3"

    def gen_input_output_pair(self):
        num = random.randint(-(2 ** 31), 2 ** 31 - 1)
        if not self.is_signed:
            num = abs(num)
        s = str(num)
        test_input = ["A"*15, num]
        test_output = [s, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):
        num = random.randint(-(2 ** 31), 2 ** 31 - 1)
        num = abs(num)
        s = str(num)
        test_input = ["A"*15, num]
        test_output = [s, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False

        num = random.randint(-(2 ** 31), 2 ** 31 - 1)
        num = -abs(num)
        s = str(num)
        test_input = [num, "A"*15]
        test_output = [s, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            self.is_signed = False
        else:
            self.is_signed = True

        return True

