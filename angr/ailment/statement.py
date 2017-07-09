
from .tagged_object import TaggedObject


class Statement(TaggedObject):
    """
    The base class of all AIL statements.
    """

    def __init__(self, idx, **kwargs):
        super(Statement, self).__init__(**kwargs)

        self.idx = idx
        self.tags = { }

    def __repr__(self):
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()


class Assignment(Statement):
    """
    Assignment statement: expr_a = expr_b
    """
    def __init__(self, idx, dst, src, **kwargs):
        super(Assignment, self).__init__(idx, **kwargs)

        self.dst = dst
        self.src = src

    def __repr__(self):
        return "Assignment (%s, %s)" % (self.dst, self.src)

    def __str__(self):
        return "%s = %s" % (str(self.dst), str(self.src))


class Store(Statement):
    def __init__(self, idx, address, data, **kwargs):
        super(Store, self).__init__(idx, **kwargs)

        self.address = address
        self.data = data

    def __str__(self):
        return "STORE(addr=%s, data=%s)" % (self.address, str(self.data))


class DirtyStatement(Statement):
    """
    Wrapper around the original statement, which is usually not convertible (temporarily).
    """
    def __init__(self, idx, dirty_stmt, **kwargs):
        super(DirtyStatement, self).__init__(idx, **kwargs)
        self.dirty_stmt = dirty_stmt

    def __repr__(self):
        return "DirtyStatement (%s)" % (type(self.dirty_stmt))

    def __str__(self):
        return "[D] %s" % (str(self.dirty_stmt))
