
class Top:
    def __add__(self, other):
        return self

    def __and__(self, other):
        return self

    def __sub__(self, other):
        return self


class Bottom:
    def __add__(self, other):
        return self

    def __sub__(self, other):
        return self

    def __and__(self, other):
        return self

    def __rshift__(self, other):
        return self


TOP = Top()
BOTTOM = Bottom()
