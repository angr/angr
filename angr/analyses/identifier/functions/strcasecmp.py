
import random

from .strcmp import strcmp


def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in range(length))
    return "".join(random.choice(byte_list) for _ in range(length))


class strcasecmp(strcmp):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super(strcasecmp, self).__init__() #pylint disable=useless-super-delegation

    def get_name(self):
        return "strcasecmp"

    def num_args(self):
        return 2

    def can_call_other_funcs(self):
        return True

    def pre_test(self, func, runner):
        r = self._strcmp_pretest(func, runner)
        if not isinstance(r, bool):
            v1, v2, v3, v4 = r
            return v1 == 0 and v2 != 0 and v3 == 0 and v4 != 0
        return r
