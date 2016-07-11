import random

from .strcmp import strcmp

def rand_str(length, byte_list=None):
    if byte_list is None:
        return "".join(chr(random.randint(0, 255)) for _ in xrange(length))
    return "".join(random.choice(byte_list) for _ in xrange(length))


class strcasecmp(strcmp):
    non_null = [chr(i) for i in range(1, 256)]

    def __init__(self):
        super(strcasecmp, self).__init__()

    def get_name(self):
        return "strcasecmp"

    def pre_test(self, func, runner):
        r = self._strcmp_pretest(func, runner)
        if not isinstance(r, bool):
            v1, v2, v3 = r
            return v1 == 0 and v2 != 0 and v3 == 0
        return r
