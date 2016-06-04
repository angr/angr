from ..func import Func, TestData
import random
import string


class sprintf(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super(sprintf, self).__init__()
        self.format_spec_char = None
        self.allows_n = False

    def rand_str(self, length, byte_list=None):
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
        return "".join(random.choice(byte_list) for _ in xrange(length))

    def num_args(self):
        return 2

    def args(self):
        return ["buf", "format"]

    def get_name(self):
        return "sprintf"

    def var_args(self):
        return True

    def gen_input_output_pair(self):
        # I'm kinda already assuming it's printf if it passed pretests...
        # make sure it prints alphanumeric stuff
        length = 10
        test_str = self.rand_str(length, string.ascii_letters + string.digits)
        outbuf = self.rand_str(length + 2)
        test_input = [outbuf, test_str]
        test_output = [test_str + "\x00", test_str]
        max_steps = 20
        test = TestData(test_input, test_output, None, max_steps)
        return test

    def pre_test(self, func, runner):
        # make sure it prints alphanumeric stuff
        length = 10
        test_str = self.rand_str(length, string.ascii_letters + string.digits)
        outbuf = self.rand_str(length + 2)
        test_input = [outbuf, test_str]
        test_output = [test_str + "\x00", test_str]
        max_steps = 20
        test = TestData(test_input, test_output, None, max_steps)
        if not runner.test(func, test):
            return False

        # find the format specifier
        second_str = "findme"
        for char in "@%!#$^&*()_+-=`~<>,.?/\'\":;\\":
            test_str = char + "s\n\x00"
            test_input = [outbuf, test_str, second_str]
            test_output = [second_str + "\n" + "\x00", test_str, second_str]
            max_steps = 20
            test = TestData(test_input, test_output, None, max_steps)
            if runner.test(func, test):
                self.format_spec_char = char
                break

        if self.format_spec_char is None:
            return False

        # check if %n is allowed
        first_arg = "A"*22 + self.format_spec_char + "n"
        second_arg = 0x41414140
        test_input = [self.rand_str(30), first_arg, second_arg]
        test_output = [first_arg + "\x00", first_arg, None]
        max_steps = 20
        test = TestData(test_input, test_output, None, max_steps)
        state = runner.get_out_state(func, test)
        if state is not None and state.se.any_int(state.mem[second_arg:].dword.resolved) == 22:
            self.allows_n = True

        self._runner = runner
        return True
