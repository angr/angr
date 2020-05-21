
# pylint: disable=unused-argument


class Top:

    __slots__ = ('size', )

    def __init__(self, size):
        self.size = size

    @property
    def bits(self):
        return self.size * 8

    def __add__(self, other):
        return self

    def __and__(self, other):
        return self

    def __sub__(self, other):
        return self

    def __rsub__(self, other):
        return self

    def __radd__(self, other):
        return self

    def __ror__(self, other):
        return self

    def __rand__(self, other):
        return self

    def __mul__(self, other):
        return self

    def __rmul__(self, other):
        return self

    def __rdiv__(self, other):
        return self

    def __floordiv__(self, other):
        return self

    def __rfloordiv__(self, other):
        return self

    def __invert__(self):
        return self

    def __rshift__(self, other):
        return self

    def __rlshift__(self, other):
        return self

    def __rrshift__(self, other):
        return self

    def __lshift__(self, other):
        return self

    def __xor__(self, other):
        return self

    def __rxor__(self, other):
        return self

    def __or__(self, other):
        return self

    def __repr__(self):
        return "TOP"

    def __eq__(self, other):
        return Top(1)

    def __le__(self, other):
        return Top(1)

    def __lt__(self, other):
        return Top(1)

    def __gt__(self, other):
        return Top(1)

    def __ge__(self, other):
        return Top(1)

    def __neg__(self):
        return self

    def __hash__(self):
        return hash((Top, self.size))


class Bottom:
    def __add__(self, other):
        return self

    def __sub__(self, other):
        return self

    def __and__(self, other):
        return self

    def __rshift__(self, other):
        return self

    def __repr__(self):
        return "BOTTOM"

    def __eq__(self, other):
        return type(other) is Bottom

    def __hash__(self):
        return hash(Bottom)
