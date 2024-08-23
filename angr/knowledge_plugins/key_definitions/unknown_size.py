from __future__ import annotations


class UnknownSize:
    """
    A value indicating an unknown size for elements of DataSets.
    Should "behave" like an integer.
    """

    def __add__(self, other):
        return self

    def __radd__(self, other):
        return self

    def __sub__(self, other):
        return self

    def __rsub__(self, other):
        return self

    def __floordiv__(self, other):
        return self

    def __lshift__(self, other):
        return self

    def __rlshift__(self, other):
        return self

    def __rshift__(self, other):
        return self

    def __rrshift__(self, other):
        return self

    def __and__(self, other):
        return self

    def __rand__(self, other):
        return self

    def __xor__(self, other):
        return self

    def __rxor__(self, other):
        return self

    def __or__(self, other):
        return self

    def __ror__(self, other):
        return self

    def __neg__(self):
        return self

    def __eq__(self, other):
        return type(other) is UnknownSize

    def __ne__(self, other):
        return not (self == other)

    def __le__(self, other):
        return False

    def __lt__(self, other):
        return False

    def __ge__(self, other):
        return True

    def __gt__(self, other):
        return True

    def __hash__(self):
        return hash("unknown size")

    def __str__(self):
        return "<UnknownSize>"

    def __repr__(self):
        return "<UnknownSize>"


UNKNOWN_SIZE = UnknownSize()
