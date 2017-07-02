
import random

from ..func import Func, TestData


class strlen(Func):
    non_null = [chr(i) for i in range(1, 256)]

    def rand_str(self, length, byte_list=None): #pylint disable=no-self-use
        if byte_list is None:
            return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
        return "".join(random.choice(byte_list) for _ in xrange(length))

    def num_args(self):
        return 1

    def get_name(self):
        return "strlen"

    def gen_input_output_pair(self):
        length = random.randint(2, 100)
        s = self.rand_str(length, strlen.non_null) + "\x00" + self.rand_str(length)
        test_input = [s]
        test_output = [s]
        max_steps = 20
        return TestData(test_input, test_output, length, max_steps)
