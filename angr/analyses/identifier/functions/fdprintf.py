import random
import string
import logging

import claripy

from ..func import Func, TestData


l = logging.getLogger(name=__name__)


class fdprintf(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super().__init__()
        self.format_spec_char = None
        self.string_spec_char = None
        self.allows_n = False

    def rand_str(self, length, byte_list=None):  # pylint disable=no-self-use
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in range(length))
        return "".join(random.choice(byte_list) for _ in range(length))

    def num_args(self):
        return 2

    def args(self):  # pylint disable=no-self-use
        return ["fd", "str"]

    def get_name(self):
        return "fdprintf"

    def var_args(self):
        return True

    def gen_input_output_pair(self):
        # I'm kinda already assuming it's printf if it passed pretests...
        return None

    def pre_test(self, func, runner):
        # make sure it prints alphanumeric stuff
        length = 10
        test_str = self.rand_str(length, string.ascii_letters + string.digits)
        test_input = [1, test_str]
        test_output = [None, test_str]
        max_steps = len(test_str) * 3 + 20
        stdout = test_str
        test = TestData(test_input, test_output, None, max_steps, expected_stdout=stdout)
        if not runner.test(func, test):
            return False

        # find interesting characters
        test_input = [1, claripy.BVS("input", 10 * 8)]
        test_output = [None, None]
        test = TestData(test_input, test_output, None, max_steps)
        s = runner.get_base_call_state(func, test)
        pg = runner.project.factory.simulation_manager(s)
        pg.run(n=18)
        interesting_chars = set()
        for p in pg.active:
            for g in p.history.jump_guards:
                if g.op == "__ne__" or g.op == "__eq__":
                    for a in g.args:
                        if not a.symbolic:
                            interesting_chars.add(s.solver.eval(a))

        interesting_chars = {chr(a) for a in interesting_chars if 0 < a < 0x80}
        alphanum = set(string.ascii_letters + string.digits)
        possible_format_specifiers = [
            c for c in interesting_chars if c not in alphanum and c in string.printable and c not in string.whitespace
        ]
        possible_formats = [c for c in interesting_chars if c in alphanum]

        if len(possible_format_specifiers) > 10:
            # too many to test :(
            return False

        # find the format specifier
        second_str = "findme"
        for char in possible_format_specifiers:
            if self.format_spec_char is not None:
                break
            for cc in possible_formats:
                test_str = char + cc + "\n\x00"
                test_input = [1, test_str, second_str]
                test_output = [None, test_str, second_str]
                stdout = second_str + "\n"
                max_steps = 20
                test = TestData(test_input, test_output, None, max_steps, expected_stdout=stdout)
                if runner.test(func, test):
                    self.format_spec_char = char
                    self.string_spec_char = cc
                    break

        # brute force...
        if self.format_spec_char is None:
            second_str = "findme"
            for char in possible_format_specifiers:
                if self.format_spec_char is not None:
                    break
                for cc in string.ascii_lowercase:
                    if cc in possible_formats:
                        continue
                    test_str = char + cc + "\n\x00"
                    test_input = [1, test_str, second_str]
                    test_output = [None, test_str, second_str]
                    stdout = second_str + "\n"
                    max_steps = 10
                    test = TestData(test_input, test_output, None, max_steps, expected_stdout=stdout)
                    if runner.test(func, test):
                        self.format_spec_char = char
                        self.string_spec_char = cc
                        break

        if self.format_spec_char is None:
            l.warning("format spec is none :(")
            return False

        return True
