
class Expression(object):
    """
    The base class of all AIL expressions.
    """
    def __init__(self, idx):
        self.idx = idx

    def __repr__(self):
        raise NotImplementedError()


class Atom(Expression):
    def __init__(self, idx, variable):
        super(Atom, self).__init__(idx)
        self.variable = variable

    def __repr__(self):
        return "Atom (%d)" % self.idx
