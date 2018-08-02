
import random
import itertools

from ..func import Func, TestData
from ..errors import FunctionNotInitialized


def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in range(length))
    return "".join(random.choice(byte_list) for _ in range(length))


# FIXME this can fail test 2
# FIXME need a way to test these, ie run 1000 times test2
class receive_until_fd(Func):
    # fd buf char max_len
    def __init__(self):
        super(receive_until_fd, self).__init__()
        self.version = None
        self.error_return = None
        self.arg_order = None
        self.has_return = True

    def get_name(self):
        if self.version is None:
            raise FunctionNotInitialized("version is none")
        return "receive_until_fd" + self.version

    def num_args(self):
        return len(self.base_args())

    def base_args(self): #pylint disable=no-self-use
        return ["fd", "buf", "end_char", "max_len"]

    def args(self):
        a = self.base_args()
        return [a[order] for order in self.arg_order]

    def gen_input_output_pair(self):
        max_len = random.randint(1, 60)
        term_char = random.randint(0, 255)
        buf = rand_str(max_len+5)
        test_input = [0, buf, term_char, max_len]
        stdin = rand_str(max_len+5)
        return_val = stdin.find(chr(term_char))
        if return_val < 0 or return_val >= max_len:
            if "allow_too_long" in self.version:
                return_val = max_len
                if "allow_too_long_nullterm" in self.version:
                    outbuf = stdin[:return_val-1] + "\x00"
                else:
                    outbuf = stdin[:return_val]
            else:
                outbuf = None
                return_val = self.error_return
        else:
            outbuf = stdin[:return_val] + "\x00"
            if "null_replace_counted" in self.version:
                return_val += 1

        test_output = [None, outbuf, None, None]
        max_steps = max_len * 8 + 20
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        self.fixup_test(test)
        return test

    def pre_test(self, func, runner):
        for perm in itertools.permutations(range(len(self.base_args()))):
            self.arg_order = perm
            if self.do_pretests(func, runner):
                return True
        return False

    def do_pretests(self, func, runner):
        test_input = [0, "A"*0x100, ord("X"), 40]
        stdin = "a"*10 + "X" + "b"*10
        max_len = 10
        max_steps = max_len * 8 + 20

        # prefilter
        test_output = [None, "a"*10, None, None]
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        if not self.run_test(func, runner, test):
            return False

        # version checks
        test_output = [None, "a"*10 + "\x00", None, None]
        return_val = 10
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        null_replace_not_counted = self.run_test(func, runner, test)

        test_output = [None, "a"*10 + "\x00", None, None]
        return_val = 11
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        null_replace_counted = self.run_test(func, runner, test)

        if not (null_replace_counted or null_replace_not_counted):
            return False

        stdin = "a"*30
        max_len = 20
        max_steps = max_len * 8 + 20
        test_output = [None, "a" * 20, None, None]
        return_val = 20
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        allow_too_long_no_null = self.run_test(func, runner, test)

        test_output = [None, "a" * 19 + "\x00", None, None]
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        allow_too_long_nullterm = self.run_test(func, runner, test)

        test_output = [None, "a" * 20 + "\x00", None, None]
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        allow_too_long_null_overflow = self.run_test(func, runner, test)

        test_output = [None, None, None, None]
        return_val = 0
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        error_too_long = self.run_test(func, runner, test)

        if error_too_long:
            self.error_return = 0
        else:
            return_val = -1
            test = TestData(test_input, test_output, return_val, max_steps, stdin)
            error_too_long = error_too_long or self.run_test(func, runner, test)
            if error_too_long:
                self.error_return = -1

        self.version = ""
        if null_replace_not_counted:
            self.version += "_null_replace_not_counted"
        if null_replace_counted:
            self.version += "_null_replace_counted"
        if allow_too_long_no_null:
            self.version += "_allow_too_long_no_null"
        if allow_too_long_nullterm:
            self.version += "_allow_too_long_nullterm"
        if allow_too_long_null_overflow:
            self.version += "_allow_too_long_null_overflow"
        if error_too_long:
            self.version += "_error_too_long"
        if self.version == "":
            return False
        return True

    def run_test(self, func, runner, test):
        # reorder args
        self.fixup_test(test)
        return runner.test(func, test)

    def fixup_test(self, test):
        test.input_args = [test.input_args[o] for o in self.arg_order]
        test.expected_output_args = [test.expected_output_args[o] for o in self.arg_order]
        if not self.has_return:
            test.expected_return_val = None


class receive_until(Func):
    # buf char max_len
    def __init__(self):
        super(receive_until, self).__init__()
        self.version = None
        self.error_return = None
        self.arg_order = None
        self.has_return = True

    def get_name(self):
        if self.version is None:
            raise FunctionNotInitialized("version is none")
        return "receive_until" + self.version

    def num_args(self):
        return len(self.base_args())

    def base_args(self): #pylint disable=no-self-use
        return ["buf", "end_char", "max_len"]

    def args(self):
        a = self.base_args()
        return [a[order] for order in self.arg_order]

    def gen_input_output_pair(self):
        max_len = random.randint(1, 60)
        term_char = random.randint(0, 255)
        buf = rand_str(max_len+5)
        test_input = [buf, term_char, max_len]
        stdin = rand_str(max_len+5)
        return_val = stdin.find(chr(term_char))
        if return_val < 0 or return_val >= max_len:
            if "allow_too_long" in self.version:
                return_val = max_len
                if "allow_too_long_nullterm" in self.version:
                    outbuf = stdin[:return_val-1] + "\x00"
                else:
                    outbuf = stdin[:return_val]
            else:
                outbuf = None
                return_val = self.error_return
        else:
            outbuf = stdin[:return_val] + "\x00"
            if "null_replace_counted" in self.version:
                return_val += 1

        test_output = [outbuf, None, None]
        max_steps = max_len * 8 + 20
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        self.fixup_test(test)
        return test

    def pre_test(self, func, runner):
        for perm in itertools.permutations(range(len(self.base_args()))):
            self.arg_order = perm
            # print "trying arg order:", self.arg_order
            if self.do_pretests(func, runner):
                return True
        return False

    def do_pretests(self, func, runner):
        test_input = ["A"*0x100, ord("X"), 40]
        stdin = "a"*10 + "X" + "b"*10
        max_len = 10
        max_steps = max_len * 8 + 20

        # prefilter
        test_output = ["a"*10, None, None]
        return_val = None
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        if not self.run_test(func, runner, test):
            return False

        # check for has return
        test_output = ["a"*10, None, None]
        return_val = 10
        test1 = TestData(test_input, test_output, return_val, max_steps, stdin)
        return_val = 11
        test2 = TestData(test_input, test_output, return_val, max_steps, stdin)
        if not (self.run_test(func, runner, test1) or self.run_test(func, runner, test2)):
            self.has_return = False

        # version checks
        test_output = ["a"*10 + "\x00", None, None]
        return_val = 10
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        null_replace_not_counted = self.run_test(func, runner, test)

        test_output = ["a"*10 + "\x00", None, None]
        return_val = 11
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        null_replace_counted = self.run_test(func, runner, test)

        if not (null_replace_counted or null_replace_not_counted):
            return False

        stdin = "a"*30
        max_len = 20
        max_steps = max_len * 8 + 20
        test_output = ["a" * 20, None, None]
        return_val = 20
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        allow_too_long_no_null = self.run_test(func, runner, test)

        test_output = ["a" * 19 + "\x00", None, None]
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        allow_too_long_nullterm = self.run_test(func, runner, test)

        test_output = ["a" * 20 + "\x00", None, None]
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        allow_too_long_null_overflow = self.run_test(func, runner, test)

        test_output = [None, None, None]
        return_val = 0
        test = TestData(test_input, test_output, return_val, max_steps, stdin)
        error_too_long = self.run_test(func, runner, test)

        if error_too_long:
            self.error_return = 0
        else:
            return_val = -1
            test = TestData(test_input, test_output, return_val, max_steps, stdin)
            error_too_long = error_too_long or self.run_test(func, runner, test)
            if error_too_long:
                self.error_return = -1

        self.version = ""
        if null_replace_not_counted:
            self.version += "_null_replace_not_counted"
        if null_replace_counted:
            self.version += "_null_replace_counted"
        if allow_too_long_no_null:
            self.version += "_allow_too_long_no_null"
        if allow_too_long_nullterm:
            self.version += "_allow_too_long_nullterm"
        if allow_too_long_null_overflow:
            self.version += "_allow_too_long_null_overflow"
        if error_too_long:
            self.version += "_error_too_long"
        if not self.has_return:
            self.version += "_no_return"
        if self.version == "":
            return False
        return True

    def run_test(self, func, runner, test):
        # reorder args
        self.fixup_test(test)
        return runner.test(func, test)

    def fixup_test(self, test):
        test.input_args = [test.input_args[o] for o in self.arg_order]
        test.expected_output_args = [test.expected_output_args[o] for o in self.arg_order]
        if not self.has_return:
            test.expected_return_val = None
