
from .tagged_object import TaggedObject


class Statement(TaggedObject):
    """
    The base class of all AIL statements.
    """

    __slots__ = ('idx', )

    def __init__(self, idx, **kwargs):
        super(Statement, self).__init__(**kwargs)

        self.idx = idx

    def __repr__(self):
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()

    def __hash__(self):
        raise NotImplementedError()

    def replace(self, old_expr, new_expr):
        raise NotImplementedError()


class Assignment(Statement):
    """
    Assignment statement: expr_a = expr_b
    """

    __slots__ = ('dst', 'src', )

    def __init__(self, idx, dst, src, **kwargs):
        super(Assignment, self).__init__(idx, **kwargs)

        self.dst = dst
        self.src = src

    def __eq__(self, other):
        return type(other) is Assignment and \
               self.idx == other.idx and \
               self.dst == other.dst and \
               self.src == other.src

    def __hash__(self):
        return hash((Assignment, self.idx, self.dst, self.src))

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

    __slots__ = ('addr', 'size', 'data', 'endness', 'variable', 'offset', 'guard', )

    def __init__(self, idx, addr, data, size, endness, guard=None, variable=None, offset=None, **kwargs):
        super(Store, self).__init__(idx, **kwargs)

        self.addr = addr
        self.data = data
        self.size = size
        self.endness = endness
        self.variable = variable
        self.guard = guard
        self.offset = offset  # variable_offset

    def __eq__(self, other):
        return type(other) is Store and \
               self.idx == other.idx and \
               self.addr == other.addr and \
               self.data == other.data and \
               self.size == other.size and \
               self.guard == other.guard and \
               self.endness == other.endness

    def __hash__(self):
        return hash((Store, self.idx, self.addr, self.data, self.size, self.endness, self.guard))

    def __repr__(self):
        return "Store (%s, %s[%d])%s" % (self.addr, str(self.data), self.size,
                                         "" if self.guard is None else "[%s]" % self.guard)

    def __str__(self):
        if self.variable is None:
            return "STORE(addr=%s, data=%s, size=%s, endness=%s, guard=%s)" % (self.addr, str(self.data), self.size,
                                                                               self.endness, self.guard)
        else:
            return "%s =%s %s<%d>%s" % (self.variable.name, self.endness[0], str(self.data), self.size,
                                        "" if self.guard is None else "[%s]" % self.guard)

    def replace(self, old_expr, new_expr):
        r_addr, replaced_addr = self.addr.replace(old_expr, new_expr)
        r_data, replaced_data = self.data.replace(old_expr, new_expr)
        if self.guard is not None:
            r_guard, replaced_guard = self.guard.replace(old_expr, new_expr)
        else:
            r_guard, replaced_guard = False, None

        if r_addr or r_data or r_guard:
            return True, Store(self.idx, replaced_addr, replaced_data, self.size, self.endness,
                               guard=replaced_guard, variable=self.variable, **self.tags)
        else:
            return False, self


class Jump(Statement):

    __slots__ = ('target', )

    def __init__(self, idx, target, **kwargs):
        super(Jump, self).__init__(idx, **kwargs)

        self.target = target

    def __eq__(self, other):
        return type(other) is Jump and \
               self.idx == other.idx and \
               self.target == other.target

    def __hash__(self):
        return hash((Jump, self.idx, self.target))

    def __repr__(self):
        return "Jump (%s)" % self.target

    def __str__(self):
        return "Goto(%s)" % self.target

    def replace(self, old_expr, new_expr):
        r, replaced_target = self.target.replace(old_expr, new_expr)

        if r:
            return True, Jump(self.idx, replaced_target, **self.tags)
        else:
            return False, self


class ConditionalJump(Statement):

    __slots__ = ('condition', 'true_target', 'false_target', )

    def __init__(self, idx, condition, true_target, false_target, **kwargs):
        super(ConditionalJump, self).__init__(idx, **kwargs)

        self.condition = condition
        self.true_target = true_target
        self.false_target = false_target

    def __eq__(self, other):
        return type(other) is ConditionalJump and \
               self.idx == other.idx and \
               self.condition == other.condition and \
               self.true_target == other.true_target and \
               self.false_target == other.false_target

    def __hash__(self):
        return hash((ConditionalJump, self.idx, self.condition, self.true_target, self.false_target))

    def __repr__(self):
        return "ConditionalJump (condition: %s, true: %s, false: %s)" % (self.condition, self.true_target,
                                                                         self.false_target)

    def __str__(self):
        return "if (%s) { Goto %s } else { Goto %s }" % (
            self.condition,
            self.true_target,
            self.false_target,
        )

    def replace(self, old_expr, new_expr):
        r_cond, replaced_cond = self.condition.replace(old_expr, new_expr)
        if self.true_target is not None:
            r_true, replaced_true = self.true_target.replace(old_expr, new_expr)
        else:
            r_true, replaced_true = False, self.true_target
        if self.false_target is not None:
            r_false, replaced_false = self.false_target.replace(old_expr, new_expr)
        else:
            r_false, replaced_false = False, self.false_target

        r = r_cond or r_true or r_false

        if r:
            return True, ConditionalJump(self.idx, replaced_cond, replaced_true, replaced_false, **self.tags)
        else:
            return False, self


class Call(Statement):

    __slots__ = ('target', 'calling_convention', 'prototype', 'args', 'ret_expr', )

    def __init__(self, idx, target, calling_convention=None, prototype=None, args=None, ret_expr=None, **kwargs):
        super(Call, self).__init__(idx, **kwargs)

        self.target = target
        self.calling_convention = calling_convention
        self.prototype = prototype
        self.args = args
        self.ret_expr = ret_expr

    def __eq__(self, other):
        return type(other) is Call and \
               self.idx == other.idx and \
               self.target == other.target and \
               self.calling_convention == other.calling_convention and \
               self.prototype == other.prototype and \
               self.args == other.args and \
               self.ret_expr == other.ret_expr

    def __hash__(self):
        return hash((Call, self.idx, self.target))

    def __repr__(self):
        return "Call (target: %s, prototype: %s, args: %s)" % (self.target, self.prototype, self.args)

    def __str__(self):

        cc = "Unknown CC" if self.calling_convention is None else "%s" % self.calling_convention
        if self.args is None:
            s = ("%s" % cc) if self.prototype is None else "%s: %s" % (self.calling_convention, self.calling_convention.arg_locs())
        else:
            s = ("%s" % cc) if self.prototype is None else "%s: %s" % (self.calling_convention, self.args)

        return "Call(%s, %s)" % (
            self.target,
            s
        )

    def replace(self, old_expr, new_expr):
        r0, replaced_target = self.target.replace(old_expr, new_expr)

        r = r0

        new_args = None
        if self.args:
            new_args = [ ]
            for arg in self.args:
                r_arg, replaced_arg = arg.replace(old_expr, new_expr)
                r |= r_arg
                new_args.append(replaced_arg)

        new_ret_expr = None
        if self.ret_expr:
            r_ret, replaced_ret = self.ret_expr.replace(old_expr, new_expr)
            r |= r_ret
            new_ret_expr = replaced_ret

        if r:
            return True, Call(self.idx, replaced_target,
                              calling_convention=self.calling_convention,
                              prototype=self.prototype,
                              args=new_args,
                              ret_expr=new_ret_expr,
                              **self.tags
                              )
        else:
            return False, self

    def copy(self):
        return Call(
            self.idx,
            self.target,
            calling_convention=self.calling_convention,
            prototype=self.prototype,
            args=self.args[::] if self.args is not None else None,
            ret_expr=self.ret_expr,
            **self.tags,
        )


class Return(Statement):

    __slots__ = ('target', 'ret_exprs', )

    def __init__(self, idx, target, ret_exprs, **kwargs):
        super().__init__(idx, **kwargs)

        self.target = target
        self.ret_exprs = list(ret_exprs) if not isinstance(ret_exprs, list) else [ ]

    def __eq__(self, other):
        return type(other) is Return and \
                self.idx == other.idx and \
                self.target == other.target and \
                self.ret_exprs == other.ret_exprs

    def __hash__(self):
        return hash((self.Return, self.idx, self.target, tuple(self.ret_exprs)))

    def __repr__(self):
        return "Return to %r (%r)" % (self.target, ",".join(self.ret_exprs))

    def __str__(self):
        exprs = (",".join(str(ret_expr) for ret_expr in self.ret_exprs))
        if not exprs:
            return "return;"
        else:
            return "return %s;" % exprs

    def replace(self, old_expr, new_expr):

        new_ret_exprs = [ ]
        replaced = False

        r, new_target = self.target.replace(old_expr, new_expr)
        if r:
            replaced = True
        else:
            new_target = self.target

        for expr in self.ret_exprs:
            r_expr, replaced_expr = expr.replace(old_expr, new_expr)
            if r_expr:
                replaced = True
                new_ret_exprs.append(replaced_expr)
            else:
                new_ret_exprs.append(old_expr)

        if replaced:
            return True, Return(self.idx,
                                new_target,
                                new_ret_exprs,
                                **self.tags,
                                )

        return False, self

    def copy(self):
        return Return(
            self.idx,
            self.target,
            self.ret_exprs[::],
            **self.tags,
        )


class DirtyStatement(Statement):
    """
    Wrapper around the original statement, which is usually not convertible (temporarily).
    """

    __slots__ = ('dirty_stmt', )

    def __init__(self, idx, dirty_stmt, **kwargs):
        super(DirtyStatement, self).__init__(idx, **kwargs)
        self.dirty_stmt = dirty_stmt

    def __hash__(self):
        return hash((DirtyStatement, self.dirty_stmt))

    def __repr__(self):
        return "DirtyStatement (%s)" % (type(self.dirty_stmt))

    def __str__(self):
        return "[D] %s" % (str(self.dirty_stmt))
