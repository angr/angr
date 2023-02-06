# pylint:disable=isinstance-second-argument-not-valid-type
from typing import Optional, TYPE_CHECKING

try:
    import claripy
except ImportError:
    claripy = None

from .utils import stable_hash, is_none_or_likeable
from .tagged_object import TaggedObject
from .expression import Expression

if TYPE_CHECKING:
    from angr.calling_conventions import SimCC


class Statement(TaggedObject):
    """
    The base class of all AIL statements.
    """

    __slots__ = ()

    def __repr__(self):
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()

    def replace(self, old_expr, new_expr):
        raise NotImplementedError()

    def eq(self, expr0, expr1):  # pylint:disable=no-self-use
        if claripy is not None and (isinstance(expr0, claripy.ast.Base) or isinstance(expr1, claripy.ast.Base)):
            return expr0 is expr1
        return expr0 == expr1


class Assignment(Statement):
    """
    Assignment statement: expr_a = expr_b
    """

    __slots__ = (
        "dst",
        "src",
    )

    def __init__(self, idx, dst, src, **kwargs):
        super().__init__(idx, **kwargs)

        self.dst = dst
        self.src = src

    def __eq__(self, other):
        return type(other) is Assignment and self.idx == other.idx and self.dst == other.dst and self.src == other.src

    def likes(self, other):
        return type(other) is Assignment and self.dst.likes(other.dst) and self.src.likes(other.src)

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Assignment, self.idx, self.dst, self.src))

    def __repr__(self):
        return f"Assignment ({self.dst}, {self.src})"

    def __str__(self):
        return f"{str(self.dst)} = {str(self.src)}"

    def replace(self, old_expr, new_expr):
        if self.dst == old_expr:
            r_dst = True
            replaced_dst = new_expr
        else:
            r_dst, replaced_dst = self.dst.replace(old_expr, new_expr)

        if self.src == old_expr:
            r_src = True
            replaced_src = new_expr
        else:
            r_src, replaced_src = self.src.replace(old_expr, new_expr)

        if r_dst or r_src:
            return True, Assignment(self.idx, replaced_dst, replaced_src, **self.tags)
        else:
            return False, self

    def copy(self) -> "Assignment":
        return Assignment(self.idx, self.dst, self.src, **self.tags)


class Store(Statement):
    __slots__ = (
        "addr",
        "size",
        "data",
        "endness",
        "variable",
        "offset",
        "guard",
    )

    def __init__(self, idx, addr, data, size, endness, guard=None, variable=None, offset=None, **kwargs):
        super().__init__(idx, **kwargs)

        self.addr = addr
        self.data = data
        self.size = size
        self.endness = endness
        self.variable = variable
        self.guard = guard
        self.offset = offset  # variable_offset

    def __eq__(self, other):
        return (
            type(other) is Store
            and self.idx == other.idx
            and self.eq(self.addr, other.addr)
            and self.eq(self.data, other.data)
            and self.size == other.size
            and self.guard == other.guard
            and self.endness == other.endness
        )

    def likes(self, other):
        return (
            type(other) is Store
            and self.addr.likes(other.addr)
            and self.data.likes(other.data)
            and self.size == other.size
            and self.guard == other.guard
            and self.endness == other.endness
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Store, self.idx, self.addr, self.data, self.size, self.endness, self.guard))

    def __repr__(self):
        return "Store (%s, %s[%d])%s" % (
            self.addr,
            str(self.data),
            self.size,
            "" if self.guard is None else "[%s]" % self.guard,
        )

    def __str__(self):
        if self.variable is None:
            return "STORE(addr={}, data={}, size={}, endness={}, guard={})".format(
                self.addr, str(self.data), self.size, self.endness, self.guard
            )
        else:
            return "%s =%s %s<%d>%s" % (
                self.variable.name,
                "L" if self.endness == "Iend_LE" else "B",
                str(self.data),
                self.size,
                "" if self.guard is None else "[%s]" % self.guard,
            )

    def replace(self, old_expr, new_expr):
        if self.addr.likes(old_expr):
            r_addr = True
            replaced_addr = new_expr
        else:
            r_addr, replaced_addr = self.addr.replace(old_expr, new_expr)

        if isinstance(self.data, Expression):
            if self.data.likes(old_expr):
                r_data = True
                replaced_data = new_expr
            else:
                r_data, replaced_data = self.data.replace(old_expr, new_expr)
        else:
            r_data, replaced_data = False, self.data

        if self.guard is not None:
            r_guard, replaced_guard = self.guard.replace(old_expr, new_expr)
        else:
            r_guard, replaced_guard = False, None

        if r_addr or r_data or r_guard:
            return True, Store(
                self.idx,
                replaced_addr,
                replaced_data,
                self.size,
                self.endness,
                guard=replaced_guard,
                variable=self.variable,
                **self.tags,
            )
        else:
            return False, self

    def copy(self) -> "Store":
        return Store(
            self.idx,
            self.addr,
            self.data,
            self.size,
            self.endness,
            guard=self.guard,
            variable=self.variable,
            offset=self.offset,
            **self.tags,
        )


class Jump(Statement):
    __slots__ = (
        "target",
        "target_idx",
    )

    def __init__(self, idx, target, target_idx: Optional[int] = None, **kwargs):
        super().__init__(idx, **kwargs)

        self.target = target
        self.target_idx = target_idx

    def __eq__(self, other):
        return type(other) is Jump and self.idx == other.idx and self.target == other.target

    def likes(self, other):
        return type(other) is Jump and is_none_or_likeable(self.target, other.target)

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Jump, self.idx, self.target))

    def __repr__(self):
        if self.target_idx is not None:
            return f"Jump ({self.target}.{self.target_idx})"
        return "Jump (%s)" % self.target

    def __str__(self):
        if self.target_idx is not None:
            return f"Goto({self.target}.{self.target_idx})"
        return "Goto(%s)" % self.target

    def replace(self, old_expr, new_expr):
        r, replaced_target = self.target.replace(old_expr, new_expr)

        if r:
            return True, Jump(self.idx, replaced_target, **self.tags)
        else:
            return False, self

    def copy(self):
        return Jump(
            self.idx,
            self.target,
            **self.tags,
        )


class ConditionalJump(Statement):
    __slots__ = (
        "condition",
        "true_target",
        "false_target",
    )

    def __init__(self, idx, condition, true_target, false_target, **kwargs):
        super().__init__(idx, **kwargs)

        self.condition = condition
        self.true_target = true_target
        self.false_target = false_target

    def __eq__(self, other):
        return (
            type(other) is ConditionalJump
            and self.idx == other.idx
            and self.condition == other.condition
            and self.true_target == other.true_target
            and self.false_target == other.false_target
        )

    def likes(self, other):
        return (
            type(other) is ConditionalJump
            and self.condition.likes(other.condition)
            and is_none_or_likeable(self.true_target, other.true_target)
            and is_none_or_likeable(self.false_target, other.false_target)
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((ConditionalJump, self.idx, self.condition, self.true_target, self.false_target))

    def __repr__(self):
        return "ConditionalJump (condition: {}, true: {}, false: {})".format(
            self.condition, self.true_target, self.false_target
        )

    def __str__(self):
        return "if ({}) {{ Goto {} }} else {{ Goto {} }}".format(
            self.condition,
            self.true_target,
            self.false_target,
        )

    def replace(self, old_expr, new_expr):
        if self.condition == old_expr:
            r_cond = True
            replaced_cond = new_expr
        else:
            r_cond, replaced_cond = self.condition.replace(old_expr, new_expr)

        if self.true_target is not None:
            if self.true_target == old_expr:
                r_true = True
                replaced_true = new_expr
            else:
                r_true, replaced_true = self.true_target.replace(old_expr, new_expr)
        else:
            r_true, replaced_true = False, self.true_target

        if self.false_target is not None:
            if self.false_target == old_expr:
                r_false = True
                replaced_false = new_expr
            else:
                r_false, replaced_false = self.false_target.replace(old_expr, new_expr)
        else:
            r_false, replaced_false = False, self.false_target

        r = r_cond or r_true or r_false

        if r:
            return True, ConditionalJump(self.idx, replaced_cond, replaced_true, replaced_false, **self.tags)
        else:
            return False, self

    def copy(self) -> "ConditionalJump":
        return ConditionalJump(self.idx, self.condition, self.true_target, self.false_target, **self.tags)


class Call(Expression, Statement):
    """
    Call is both an expression and a statement. The return expression of a call is defined as the ret_expr if and only
    if the callee function has one return expression.
    """

    __slots__ = (
        "target",
        "calling_convention",
        "prototype",
        "args",
        "ret_expr",
        "fp_ret_expr",
    )

    def __init__(
        self,
        idx,
        target,
        calling_convention: Optional["SimCC"] = None,
        prototype=None,
        args=None,
        ret_expr=None,
        fp_ret_expr=None,
        **kwargs,
    ):
        super().__init__(idx, target.depth + 1 if isinstance(target, Expression) else 1, **kwargs)

        self.target = target
        self.calling_convention = calling_convention
        self.prototype = prototype
        self.args = args
        self.ret_expr = ret_expr
        self.fp_ret_expr = fp_ret_expr

    def likes(self, other):
        return (
            type(other) is Call
            and is_none_or_likeable(self.target, other.target)
            and self.calling_convention == other.calling_convention
            and self.prototype == other.prototype
            and is_none_or_likeable(self.args, other.args, is_list=True)
            and is_none_or_likeable(self.ret_expr, other.ret_expr)
            and is_none_or_likeable(self.fp_ret_expr, other.fp_ret_expr)
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Call, self.idx, self.target))

    def __repr__(self):
        return f"Call (target: {self.target}, prototype: {self.prototype}, args: {self.args})"

    def __str__(self):
        cc = "Unknown CC" if self.calling_convention is None else "%s" % self.calling_convention
        if self.args is None:
            if self.calling_convention is not None:
                s = (
                    ("%s" % cc)
                    if self.prototype is None
                    else f"{self.calling_convention}: {self.calling_convention.arg_locs(self.prototype)}"
                )
            else:
                s = ("%s" % cc) if self.prototype is None else repr(self.prototype)
        else:
            s = (f"{cc}: {self.args}") if self.prototype is None else f"{self.calling_convention}: {self.args}"

        if self.ret_expr is None:
            ret_s = "no-ret-value"
        else:
            ret_s = f"{self.ret_expr}"
        if self.fp_ret_expr is None:
            fp_ret_s = "no-fp-ret-value"
        else:
            fp_ret_s = f"{self.fp_ret_expr}"

        return f"Call({self.target}, {s}, ret: {ret_s}, fp_ret: {fp_ret_s})"

    @property
    def bits(self):
        return self.ret_expr.bits

    @property
    def size(self):
        return self.bits // 8

    @property
    def verbose_op(self):
        return "call"

    @property
    def op(self):
        return "call"

    def replace(self, old_expr, new_expr):
        if isinstance(self.target, Expression):
            r0, replaced_target = self.target.replace(old_expr, new_expr)
        else:
            r0 = False
            replaced_target = self.target

        r = r0

        new_args = None
        if self.args:
            new_args = []
            for arg in self.args:
                if arg == old_expr:
                    r_arg = True
                    replaced_arg = new_expr
                else:
                    r_arg, replaced_arg = arg.replace(old_expr, new_expr)
                r |= r_arg
                new_args.append(replaced_arg)

        new_ret_expr = None
        if self.ret_expr:
            if self.ret_expr == old_expr:
                r_ret = True
                replaced_ret = new_expr
            else:
                r_ret, replaced_ret = self.ret_expr.replace(old_expr, new_expr)
            r |= r_ret
            new_ret_expr = replaced_ret

        new_fp_ret_expr = None
        if self.fp_ret_expr:
            if self.fp_ret_expr == old_expr:
                r_ret = True
                replaced_fp_ret = new_expr
            else:
                r_ret, replaced_fp_ret = self.fp_ret_expr.replace(old_expr, new_expr)
            r |= r_ret
            new_fp_ret_expr = replaced_fp_ret

        if r:
            return True, Call(
                self.idx,
                replaced_target,
                calling_convention=self.calling_convention,
                prototype=self.prototype,
                args=new_args,
                ret_expr=new_ret_expr,
                fp_ret_expr=new_fp_ret_expr,
                **self.tags,
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
            fp_ret_expr=self.fp_ret_expr,
            **self.tags,
        )


class Return(Statement):
    __slots__ = (
        "target",
        "ret_exprs",
    )

    def __init__(self, idx, target, ret_exprs, **kwargs):
        super().__init__(idx, **kwargs)

        self.target = target
        self.ret_exprs = ret_exprs if isinstance(ret_exprs, list) else list(ret_exprs)

    def __eq__(self, other):
        return (
            type(other) is Return
            and self.idx == other.idx
            and self.target == other.target
            and self.ret_exprs == other.ret_exprs
        )

    def likes(self, other):
        return (
            type(other) is Return
            and is_none_or_likeable(self.target, other.target)
            and is_none_or_likeable(self.ret_exprs, other.ret_exprs, is_list=True)
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((Return, self.idx, self.target, tuple(self.ret_exprs)))

    def __repr__(self):
        return "Return to {!r} ({})".format(self.target, ",".join(repr(x) for x in self.ret_exprs))

    def __str__(self):
        exprs = ",".join(str(ret_expr) for ret_expr in self.ret_exprs)
        if not exprs:
            return "return;"
        else:
            return "return %s;" % exprs

    def replace(self, old_expr, new_expr):
        new_ret_exprs = []
        replaced = False

        if self.target is not None:
            r, new_target = self.target.replace(old_expr, new_expr)
            if r:
                replaced = True
            else:
                new_target = self.target
        else:
            new_target = None

        for expr in self.ret_exprs:
            if expr == old_expr:
                r_expr = True
                replaced_expr = new_expr
            else:
                r_expr, replaced_expr = expr.replace(old_expr, new_expr)
            if r_expr:
                replaced = True
                new_ret_exprs.append(replaced_expr)
            else:
                new_ret_exprs.append(old_expr)

        if replaced:
            return True, Return(
                self.idx,
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

    __slots__ = ("dirty_stmt",)

    def __init__(self, idx, dirty_stmt, **kwargs):
        super().__init__(idx, **kwargs)
        self.dirty_stmt = dirty_stmt

    def _hash_core(self):
        return stable_hash((DirtyStatement, self.dirty_stmt))

    def __repr__(self):
        return "DirtyStatement (%s)" % (type(self.dirty_stmt))

    def __str__(self):
        return "[D] %s" % (str(self.dirty_stmt))

    def copy(self) -> "DirtyStatement":
        return DirtyStatement(self.idx, self.dirty_stmt, **self.tags)


class Label(Statement):
    """
    A dummy statement that indicates a label with a name.
    """

    __slots__ = (
        "name",
        "ins_addr",
        "block_idx",
    )

    def __init__(self, idx, name: str, ins_addr: int, block_idx: Optional[int] = None, **kwargs):
        super().__init__(idx, **kwargs)
        self.name = name
        self.ins_addr = ins_addr
        self.block_idx = block_idx

    def likes(self, other: "Label"):
        return isinstance(other, Label)

    def _hash_core(self):
        return stable_hash(
            (
                Label,
                self.name,
                self.ins_addr,
                self.block_idx,
            )
        )

    def __repr__(self):
        return f"Label {self.name}"

    def __str__(self):
        return f"{self.name}:"

    def copy(self) -> "Label":
        return Label(self.idx, self.name, self.ins_addr, self.block_idx, **self.tags)
