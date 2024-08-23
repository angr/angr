from __future__ import annotations


class Undefined:
    """
    A TOP-like value indicating an unknown data source. Should live next to raw integers in DataSets.
    """

    def __add__(self, other):
        return self

    def __radd__(self, other):
        return self

    def __sub__(self, other):
        return self

    def __rsub__(self, other):
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
        return type(other) is Undefined

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash("undefined")

    def __str__(self):
        return "<Undefined>"

    def __repr__(self):
        return "<Undefined>"


UNDEFINED = Undefined()
