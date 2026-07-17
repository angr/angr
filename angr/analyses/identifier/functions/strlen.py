from __future__ import annotations

import random

from angr.analyses.identifier.func import Func, TestData, rand_bytes


class strlen(Func):
    non_null = list(range(1, 256))

    def num_args(self):
        return 1

    def get_name(self):
        return "strlen"

    def gen_input_output_pair(self):
        length = random.randint(2, 100)
        s = rand_bytes(length, strlen.non_null) + b"\x00" + rand_bytes(length)
        test_input = [s]
        test_output = [s]
        max_steps = 20
        return TestData(test_input, test_output, length, max_steps)
