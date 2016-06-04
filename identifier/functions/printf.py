from ..func import Func, TestData
import random
import string


class printf(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super(printf, self).__init__()
        self.format_spec_char = None
        self.allows_n = False

    def rand_str(self, length, byte_list=None):
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
        return "".join(random.choice(byte_list) for _ in xrange(length))

    def num_args(self):
        return 1

    def args(self):
        return "str"

    def get_name(self):
        return "printf"

    def var_args(self):
        return True

    def gen_input_output_pair(self):
        # I'm kinda already assuming it's printf if it passed pretests...
        # make sure it prints alphanumeric stuff
        length = 10
        test_str = self.rand_str(length, string.ascii_letters + string.digits)
        test_input = [test_str]
        test_output = [test_str]
        max_steps = len(test_str) * 3 + 20
        stdout = test_str
        test = TestData(test_input, test_output, None, max_steps, expected_stdout=stdout)

        return test

    def pre_test(self, func, runner):
        # make sure it prints alphanumeric stuff
        length = 10
        test_str = self.rand_str(length, string.ascii_letters + string.digits)
        test_input = [test_str]
        test_output = [test_str]
        max_steps = len(test_str) * 3 + 20
        stdout = test_str
        test = TestData(test_input, test_output, None, max_steps, expected_stdout=stdout)
        if not runner.test(func, test):
            return False

        # find the format specifier
        second_str = "findme"
        for char in "@%!#$^&*()_+-=`~<>,.?/\'\":;\\":
            test_str = char + "s\n"
            test_input = [test_str, second_str]
            test_output = [test_str, second_str]
            stdout = second_str + "\n"
            max_steps = len(test_str) * 3 + 20
            test = TestData(test_input, test_output, None, max_steps, expected_stdout=stdout)
            if runner.test(func, test):
                self.format_spec_char = char
                break

        if self.format_spec_char is None:
            return False

        # check if %n is allowed
        first_arg = "A"*22 + self.format_spec_char + "n"
        second_arg = 0x41414140
        test_input = [first_arg, second_arg]
        test_output = [first_arg, None]
        stdout = "A"*22
        max_steps = len(test_str) * 3 + 20
        test = TestData(test_input, test_output, None, max_steps, expected_stdout=stdout)
        state = runner.get_out_state(func, test)
        if state is not None and state.se.any_int(state.mem[second_arg:].dword.resolved) == 22:
            self.allows_n = True

        return True
