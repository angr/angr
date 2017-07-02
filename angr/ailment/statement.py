
class Statement(object):
    """
    The base class of all AIL statements.
    """

    def __init__(self, idx):
        self.idx = idx

    def __repr__(self):
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()


class Assignment(Statement):
    """
    Assignment statement: expr_a = expr_b
    """
    def __init__(self, idx, dst, src):
        super(Assignment, self).__init__(idx)

        self.dst = dst
        self.src = src

    def __repr__(self):
        return "Assignment (%s, %s)" % (self.dst, self.src)

    def __str__(self):
        return "%s = %s" % (str(self.dst), str(self.src))


class DirtyStatement(Statement):
    """
    Wrapper around the original statement, which is usually not convertible (temporiraly).
    """
    def __init__(self, idx, dirty_stmt):
        super(DirtyStatement, self).__init__(idx)
        self.dirty_stmt = dirty_stmt

    def __repr__(self):
        return "DirtyStatement (%s)" % (type(self.dirty_stmt))

    def __str__(self):
        return "[D] %s" % (str(self.dirty_stmt))
