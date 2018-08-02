
import random
import string

from ..func import Func, TestData


digs = string.digits + string.ascii_letters


class TwoOrThree(object):
    def __eq__(self, other):
        if other == 2:
            return True
        if other == 3:
            return True
        return False

    def __ne__(self, other):
        if other == 2:
            return False
        if other == 3:
            return False
        return True


class ThreeOrFour(object):
    def __eq__(self, other):
        if other == 3:
            return True
        if other == 4:
            return True
        return False

    def __ne__(self, other):
        if other == 3:
            return False
        if other == 4:
            return False
        return True


class FourOrFive(object):
    def __eq__(self, other):
        if other == 4:
            return True
        if other == 5:
            return True
        return False

    def __ne__(self, other):
        if other == 4:
            return False
        if other == 5:
            return False
        return True


class int2str(Func):
    def __init__(self):
        super(int2str, self).__init__()
        self.is_signed = False

    def rand_str(self, length, byte_list=None): #pylint disable=no-self-use
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in range(length))
        return "".join(random.choice(byte_list) for _ in range(length))

    def num_args(self):
        return 3

    def args(self): #pylint disable=no-self-use
        return ["buf", "len", "val"]

    def get_name(self):
        if self.is_signed:
            return "int2str"
        return "uint2str"

    def gen_input_output_pair(self):
        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
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
        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        num = abs(num)
        s = str(num)
        test_input = ["A"*15, 15, num]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False

        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
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

    def rand_str(self, length, byte_list=None): #pylint disable=no-self-use
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in range(length))
        return "".join(random.choice(byte_list) for _ in range(length))

    def num_args(self):
        return TwoOrThree()

    def args(self): #pylint disable=no-self-use
        return ["val", "buf", "max"]

    def get_name(self):
        if self.is_signed:
            return "int2str_v2"
        return "uint2str_v2"

    def gen_input_output_pair(self):
        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        if not self.is_signed:
            num = abs(num)
        s = str(num)
        test_input = [num, "A"*15, 12]
        test_output = [None, s, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):
        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        num = abs(num)
        s = str(num)
        test_input = [num, "A"*15, 12]
        test_output = [None, s, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False

        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        num = -abs(num)
        s = str(num)
        test_input = [num, "A"*15, 12]
        test_output = [None, s, None]
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

    def rand_str(self, length, byte_list=None): #pylint disable=no-self-use
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in range(length))
        return "".join(random.choice(byte_list) for _ in range(length))

    def num_args(self):
        return TwoOrThree()

    def args(self): #pylint disable=no-self-use
        return ["buf", "val", "max"]

    def get_name(self):
        if self.is_signed:
            return "int2str_v3"
        return "uint2str_v3"

    def gen_input_output_pair(self):
        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        if not self.is_signed:
            num = abs(num)
        s = str(num)
        test_input = ["A"*15, num, 12]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):
        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        num = abs(num)
        s = str(num)
        test_input = ["A"*15, num, 12]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False

        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        num = -abs(num)
        s = str(num)
        test_input = [num, "A"*15, 12]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            self.is_signed = False
        else:
            self.is_signed = True

        return True


class int2str_v4(Func):
    def __init__(self):
        super(int2str_v4, self).__init__()
        self.is_signed = False

    def rand_str(self, length, byte_list=None): #pylint disable=no-self-use
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in range(length))
        return "".join(random.choice(byte_list) for _ in range(length))

    def num_args(self):
        return ThreeOrFour()

    def args(self): #pylint disable=no-self-use
        return ["buf", "val", "base"]

    def get_name(self):
        if self.is_signed:
            return "int2str_v4"
        return "uint2str_v4"

    def gen_input_output_pair(self):
        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        if not self.is_signed:
            num = abs(num)
        s = str(num)
        test_input = ["A"*15, num, 10]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        return test

    def pre_test(self, func, runner):
        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        num = abs(num)
        s = hex(num).replace("0x", "").replace("L", "").lower()
        s2 = hex(num).replace("0x", "").replace("L", "").upper()
        test_input = ["A"*15, num, 16]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        test_output2 = [s2, None, None]
        test2 = TestData(test_input, test_output2, return_val, max_steps)
        if not runner.test(func, test) and not runner.test(func, test2):
            return False

        num = random.randint(-(2 ** 26), 2 ** 26 - 1)
        num = -abs(num)
        s = str(num)
        test_input = [num, "A"*15, 10]
        test_output = [s, None, None]
        return_val = None
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            self.is_signed = False
        else:
            self.is_signed = True

        return True
