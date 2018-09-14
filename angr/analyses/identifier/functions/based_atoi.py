
import random
import string

from ..func import Func, TestData


BASES = [8, 10, 16]


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
        digits.append('-')
    digits.reverse()
    return ''.join(digits)


class OneTwoOrThree(object):
    def __eq__(self, other):
        if other == 1:
            return True
        if other == 2:
            return True
        if other == 3:
            return True
        return False

    def __ne__(self, other):
        if other == 1:
            return False
        if other == 2:
            return False
        if other == 3:
            return False
        return True


class based_atoi(Func):
    def __init__(self):
        super(based_atoi, self).__init__()
        self.allows_negative = True
        self.base = None

    def rand_str(self, length, byte_list=None): #pylint disable=no-self-use
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in range(length))
        return "".join(random.choice(byte_list) for _ in range(length))

    def num_args(self):
        return OneTwoOrThree()

    def args(self): #pylint disable=no-self-use
        return ["buf", "size", "err"]

    def get_name(self):
        name = "based_atoi_"
        if self.allows_negative:
            name += "signed_"
        name += str(self.base)
        return name

    def gen_input_output_pair(self):
        num = random.randint(-(2**26), 2**26-1)

        if not self.allows_negative:
            num = abs(num)

        num = abs(num)
        s = int2base(num, self.base)
        test_input = [s, 30, b"foo"]
        test_output = [s, None, None]
        return_val = num
        max_steps = 10
        return TestData(test_input, test_output, return_val, max_steps)

    def pre_test(self, func, runner):
        s = "1111"
        test_input = [s, 10, "foo"]
        max_steps = 10
        test = TestData(test_input, [None, None, None], 1234, max_steps=max_steps)
        state = runner.get_out_state(func, test, concrete_rand=True)
        if state is None:
            return False
        out_val = state.solver.eval(state.regs.eax)
        self.base = None
        for i in range(2, 16):
            if out_val == int(s, i):
                self.base = i
                break
        if self.base is None:
            return False

        num = random.randint(-(2 ** 26), 2 ** 26 - 1)

        num = abs(num)
        s = int2base(num, self.base)
        test_input = [s, 30, "foo"]
        test_output = [s, None, None]
        return_val = num
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            return False

        num = -random.randint(2000, 8000)
        s = int2base(num, self.base)
        test_input = [s, 30, "foo"]
        test_output = [s, None, None]
        return_val = num
        max_steps = 10
        test = TestData(test_input, test_output, return_val, max_steps)
        if not runner.test(func, test):
            self.allows_negative = False

        return True
