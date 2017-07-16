
from .tagged_object import TaggedObject


class Statement(TaggedObject):
    """
    The base class of all AIL statements.
    """

    def __init__(self, idx, **kwargs):
        super(Statement, self).__init__(**kwargs)

        self.idx = idx

    def __repr__(self):
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()

    def replace(self, old_expr, new_expr):
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

    def replace(self, old_expr, new_expr):

        r_dst, replaced_dst = self.dst.replace(old_expr, new_expr)
        r_src, replaced_src = self.src.replace(old_expr, new_expr)

        if r_dst or r_src:
            return True, Assignment(self.idx, replaced_dst, replaced_src, **self.tags)
        else:
            return False, self


class Store(Statement):
    def __init__(self, idx, addr, data, **kwargs):
        super(Store, self).__init__(idx, **kwargs)

        self.addr = addr
        self.data = data

    def __repr__(self):
        return "Store (%s, %s)" % (self.address, str(self.data))

    def __str__(self):
        return "STORE(addr=%s, data=%s)" % (self.addr, str(self.data))

    def replace(self, old_expr, new_expr):
        r_addr, replaced_addr = self.addr.replace(old_expr, new_expr)
        r_data, replaced_data = self.data.replace(old_expr, new_expr)

        if r_addr or r_data:
            return True, Store(self.idx, replaced_addr, replaced_data, **self.tags)
        else:
            return False, self


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
