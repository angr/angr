
class Top:
    def __add__(self, other):
        return self

    def __and__(self, other):
        return self

    def __sub__(self, other):
        return self

    def __repr__(self):
        return "TOP"

    def __eq__(self, other):
        return type(other) is Top

    def __hash__(self):
        return hash(Top)


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


TOP = Top()
BOTTOM = Bottom()
