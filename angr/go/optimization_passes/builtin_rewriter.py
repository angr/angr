from __future__ import annotations

import contextlib
import logging
from collections import Counter, OrderedDict

from angr.ailment import AILBlockRewriter, AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    StringLiteral,
    Struct,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, Jump, Label, Return, SideEffectStatement, Statement, Store
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimTypeFunction
from angr.go.utils.graph import block_before, conditional_pred, is_jump_only, leads_to, skip_jumps
from angr.go.utils.names import call_target_name
from angr.go.utils.types import go_type_at, go_type_name_at
from angr.rust.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.utils.go_runtime import normalize_go_func_name

l = logging.getLogger(__name__)

_COMPARISONS = frozenset({"CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"})
_STRING_BITS = 128
_SLICE_BITS = 192
_PTR, _LEN, _CAP = 0, 8, 16


def _addr_and_offset(addr: Expression) -> tuple[Expression | None, int]:
    """``base + k`` -> (base, k); ``Const c`` -> (None, c)."""
    if isinstance(addr, Const):
        return None, addr.value_int
    if isinstance(addr, BinaryOp) and addr.op == "Add":
        lhs, rhs = addr.operands
        if isinstance(rhs, Const):
            return lhs, rhs.value_int
        if isinstance(lhs, Const):
            return rhs, lhs.value_int
    return addr, 0


def _strip_converts(expr: Expression) -> Expression:
    while isinstance(expr, Convert):
        expr = expr.operand
    return expr


def _const(expr: Expression) -> int | None:
    return expr.value_int if isinstance(expr, Const) else None


def _has_node(expr: Expression, pred) -> bool:
    if pred(expr):
        return True
    if isinstance(expr, (BinaryOp, UnaryOp)):
        return any(_has_node(op, pred) for op in expr.operands)
    if isinstance(expr, Convert):
        return _has_node(expr.operand, pred)
    return False


class _Base:
    """Where a string/slice value lives: a combo-register variable or memory at ``addr``."""

    __slots__ = ("addr", "combo")

    def __init__(self, combo: VirtualVariable | None = None, addr: Expression | None = None):
        self.combo = combo
        self.addr = addr

    def same(self, other: _Base) -> bool:
        if self.combo is not None:
            return other.combo is not None and other.combo.varid == self.combo.varid
        if other.combo is not None or self.addr is None or other.addr is None:
            return False
        return self.addr.likes(other.addr)

    def value(self, manager, arch, size: int | None, tags) -> Expression | None:
        if self.combo is not None:
            return self.combo if size is None or self.combo.size == size else None
        if self.addr is None or size is None:
            return None
        return Load(manager.next_atom(), self.addr, size, arch.memory_endness, **tags)


class _Values:
    """Map the pieces the ABI splits string/slice values into back to the values they belong to."""

    def __init__(self, pass_: GoBuiltinRewriter):
        self.project = pass_.project
        self.manager = pass_.manager
        self.combo_of: dict[int, tuple[VirtualVariable, int]] = {}
        self.defs: dict[int, Expression] = {}

        def note(vvar: VirtualVariable):
            is_combo = vvar.category == VVC.COMBO_REGISTER or (
                vvar.category == VVC.PARAMETER and vvar.parameter_category == VVC.COMBO_REGISTER
            )
            if is_combo and vvar.reg_vvars:
                offset = 0
                for reg_vvar in vvar.reg_vvars:
                    self.combo_of[reg_vvar.varid] = (vvar, offset)
                    offset += reg_vvar.size

        if pass_._arg_vvars:
            for arg_vvar, _ in pass_._arg_vvars.values():
                if isinstance(arg_vvar, VirtualVariable):
                    note(arg_vvar)
        for block in pass_._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    note(stmt.dst)
                    self.defs[stmt.dst.varid] = stmt.src

    def resolve(self, expr: Expression) -> Expression:
        """Look through virtual-variable copies (register moves and spills)."""
        seen = set()
        while isinstance(expr, VirtualVariable) and expr.varid not in seen:
            seen.add(expr.varid)
            src = self.defs.get(expr.varid)
            if not isinstance(src, VirtualVariable):
                break
            expr = src
        return expr

    def expand(self, expr: Expression) -> Expression:
        """Like ``resolve`` but also returns the defining expression of the final variable when it has one."""
        expr = self.resolve(expr)
        if isinstance(expr, VirtualVariable):
            src = self.defs.get(expr.varid)
            if src is not None and not isinstance(src, Phi):
                return src
        return expr

    def field(self, expr: Expression) -> tuple[_Base, int] | None:
        """The (value, byte offset) a pointer-sized expression is a piece of."""
        expr = self.resolve(expr)
        if isinstance(expr, VirtualVariable):
            hit = self.combo_of.get(expr.varid)
            return (_Base(combo=hit[0]), hit[1]) if hit is not None else None
        if isinstance(expr, Load) and expr.size == self.project.arch.bytes:
            base, off = _addr_and_offset(expr.addr)
            if base is None:
                base = Const(self.manager.next_atom(), off, self.project.arch.bits)
                off = 0
            return _Base(addr=base), off
        return None

    def whole(self, size: int | None, *pieces: tuple[Expression, int], tags=None) -> Expression | None:
        """The value whose pieces at the given byte offsets are ``pieces``; ``size`` None means any size."""
        base = None
        for expr, want in pieces:
            hit = self.field(expr)
            if hit is None or hit[1] != want or (base is not None and not hit[0].same(base)):
                return None
            base = hit[0]
        if base is None:
            return None
        return base.value(self.manager, self.project.arch, size, tags or pieces[0][0].tags)

    def string(self, ptr: Expression, length: Expression) -> Expression | None:
        value = self.whole(_STRING_BITS // 8, (ptr, _PTR), (length, _LEN))
        if value is not None:
            return value
        return self.literal(ptr, length)

    def literal(self, ptr: Expression, length: Expression) -> StringLiteral | None:
        addr, n = _const(ptr), _const(length)
        if addr is None or n is None or n < 0 or n > 0x10000:
            return None
        if n == 0:
            return StringLiteral(self.manager.next_atom(), "", _STRING_BITS, **ptr.tags)
        section = self.project.loader.find_section_containing(addr)
        if section is None or not section.is_readable or section.is_writable:
            return None
        with contextlib.suppress(KeyError, UnicodeDecodeError):
            data = self.project.loader.memory.load(addr, n).decode("utf-8")
            return StringLiteral(self.manager.next_atom(), data, _STRING_BITS, **ptr.tags)
        return None

    def slice(self, ptr: Expression, length: Expression) -> Expression | None:
        """The slice (or string, when that is what the pieces belong to) with the given ptr and len pieces."""
        base = self.field(ptr)
        size = None if base is not None and base[0].combo is not None else _SLICE_BITS // 8
        return self.whole(size, (ptr, _PTR), (length, _LEN))

    def is_len_of(self, expr: Expression, base: _Base) -> bool:
        hit = self.field(expr)
        return hit is not None and hit[1] == _LEN and hit[0].same(base)


class GoBuiltinRewriter(OptimizationPass, CFGTransformationMixin):
    """
    Turn calls into the Go runtime back into the builtins and operators the compiler lowered them from: ``new``,
    ``make``, ``append``, ``copy``, ``panic``, string concatenation/comparison and the string/slice conversions.

    ``growslice`` is special: the compiler only calls it when the slice must grow, so the call sits under an
    ``if newLen > cap`` diamond whose join block stores the appended elements. The diamond is folded into one
    unconditional ``append(s, elems...)`` (append grows on demand itself) and the element stores are dropped. When the
    element stores cannot be matched the call still becomes ``append(s)`` with a comment giving the element count.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Rewrite Go runtime calls into builtins"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self.values: _Values | None = None
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self.values = _Values(self)
        touched = self._fold_growslice()
        if touched:
            self._drop_dead_defs(touched)
            self.values = _Values(self)
        rewriter = _BuiltinRewriter(self)
        for block in list(self._graph.nodes):
            rewriter.walk(block)
        if rewriter.changed:
            self._fold_returns()
        if touched or rewriter.changed:
            self.out_graph = self._graph

    #
    # Cleanups
    #

    def _use_counts(self) -> Counter:
        counter = _VVarCounter()
        for block in self._graph.nodes:
            counter.walk(block)
        return counter.counts

    def _drop_dead_defs(self, blocks: list[Block]) -> None:
        """Drop side-effect-free assignments in ``blocks`` whose variable is no longer used anywhere."""
        while True:
            counts = self._use_counts()
            dropped = False
            for block in blocks:
                kept = []
                for stmt in block.statements:
                    if (
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and not isinstance(stmt.src, (Call, Phi))
                        and counts[stmt.dst.varid] <= 1
                    ):
                        dropped = True
                        continue
                    kept.append(stmt)
                block.statements = kept
            if not dropped:
                return

    def _fold_returns(self) -> None:
        """``v = builtin(...)`` followed only by ``return v`` becomes ``return builtin(...)``."""
        counts = None
        for block in list(self._graph.nodes):
            if not block.statements or block not in self._graph:
                continue
            last = block.statements[-1]
            if not (isinstance(last, Assignment) and isinstance(last.dst, VirtualVariable)):
                continue
            src = last.src
            if not (isinstance(src, Call) and isinstance(src.target, str)) and not (
                isinstance(src, BinaryOp) and src.op == "Add" and src.bits == _STRING_BITS
            ):
                continue
            chain = []
            succs = list(self._graph.successors(block))
            while len(succs) == 1 and self._graph.in_degree(succs[0]) == 1 and is_jump_only(succs[0]):
                chain.append(succs[0])
                succs = list(self._graph.successors(succs[0]))
            if len(succs) != 1 or self._graph.in_degree(succs[0]) != 1:
                continue
            ret_block = succs[0]
            body = [stmt for stmt in ret_block.statements if not isinstance(stmt, Label)]
            if len(body) != 1 or not isinstance(body[0], Return) or self._graph.out_degree(ret_block) != 0:
                continue
            ret = body[0]
            exprs = list(ret.ret_exprs or [])
            if len(exprs) != 1 or not (isinstance(exprs[0], VirtualVariable) and exprs[0].varid == last.dst.varid):
                continue
            counts = counts if counts is not None else self._use_counts()
            if counts[last.dst.varid] != 2:
                continue
            block.statements = [*block.statements[:-1], Return(ret.idx, [src], **ret.tags)]
            for dead in [*chain, ret_block]:
                self._graph.remove_node(dead)
                self._block_by_addr_and_idx.pop((dead.addr, dead.idx), None)

    #
    # Helpers
    #

    def callee_name(self, call: Call) -> str | None:
        name = call_target_name(self.project, call)
        return normalize_go_func_name(name) if name is not None else None

    def type_name(self, expr: Expression) -> str | None:
        addr = _const(expr)
        return go_type_name_at(self.project, addr) if addr is not None else None

    def type_size(self, expr: Expression) -> int | None:
        addr = _const(expr)
        ty = go_type_at(self.project, addr) if addr is not None else None
        if ty is None or not ty.size:
            return None
        return ty.size // self.project.arch.byte_width

    def builtin(self, call: Call, name: str, args: list, bits: int | None = None, **extra) -> Call:
        tags = {k: v for k, v in call.tags.items() if not k.startswith("go_")}
        result_type = extra.get("go_result_type")
        if result_type is not None:
            tags["is_prototype_guessed"] = False
        new_call = Call(call.idx, name, args, bits=bits if bits is not None else call.bits, **tags, **extra)
        if result_type is not None:
            # lets type inference see the result type (arguments are left unconstrained)
            with contextlib.suppress(Exception):
                returnty = self.kb.go_signatures.type(result_type)
                proto = GoSimTypeFunction([], returnty).with_arch(self.project.arch)
                variable_map_of(self.manager).set_prototype(new_call, proto)
        return new_call

    def to_bits(self, expr: Expression, bits: int | None) -> Expression:
        if bits is None or expr.bits == bits:
            return expr
        return Convert(self.manager.next_atom(), expr.bits, bits, False, expr, **expr.tags)

    def compare(self, op: str, lhs: Expression, rhs: Expression, bits: int | None, tags) -> Expression:
        cmp = BinaryOp(self.manager.next_atom(), op, [lhs, rhs], False, bits=1, **tags)
        return self.to_bits(cmp, bits)

    #
    # Call rules
    #

    def rewrite_call(self, call: Call) -> Expression | None:
        name = self.callee_name(call)
        if name is None:
            return None
        rule = _CALL_RULES.get(name)
        if rule is None and name.startswith("runtime.mallocgc"):
            # go1.25+ inlines newobject into size-class specialized mallocgc variants
            rule = GoBuiltinRewriter._rw_mallocgc
        if rule is None:
            return None
        args = list(call.args or [])
        try:
            return rule(self, call, args)
        except Exception:  # pylint:disable=broad-exception-caught
            l.debug("Rewriting %s failed", name, exc_info=True)
            return None

    def _rw_newobject(self, call: Call, args: list) -> Expression | None:
        ty = self.type_name(args[0]) if len(args) == 1 else None
        if ty is None:
            return None
        return self.builtin(call, "new", [], go_type_args=[ty], go_result_type=f"*{ty}")

    def _rw_mallocgc(self, call: Call, args: list) -> Expression | None:
        if len(args) != 3:
            return None
        ty = self.type_name(args[1])
        if ty is None or _const(args[0]) != self.type_size(args[1]):
            return None
        return self.builtin(call, "new", [], go_type_args=[ty], go_result_type=f"*{ty}")

    def _rw_makeslice(self, call: Call, args: list) -> Expression | None:
        ty = self.type_name(args[0]) if len(args) == 3 else None
        if ty is None:
            return None
        length, cap = args[1], args[2]
        dims = [length] if cap.likes(length) else [length, cap]
        return self.builtin(call, "make", dims, go_type_args=[f"[]{ty}"], go_result_type="unsafe.Pointer")

    def _rw_growslice(self, call: Call, args: list) -> Expression | None:
        # the diamond was not folded; keep the growth visible as append(s) with the missing elements in a comment
        if len(args) != 5:
            return None
        s = self.values.whole(_SLICE_BITS // 8, (args[0], _PTR), (args[2], _CAP))
        if s is None:
            return None
        num = _const(args[3])
        comment = f"{num} element(s) not recovered" if num is not None else "elements not recovered"
        ty = self.type_name(args[4])
        extra = {"go_result_type": f"[]{ty}"} if ty else {}
        return self.builtin(call, "append", [s], bits=_SLICE_BITS, go_comment=comment, **extra)

    def _rw_concatstring(self, call: Call, args: list) -> Expression | None:
        parts = args[1:]
        if len(parts) < 2 or any(p.bits != _STRING_BITS for p in parts):
            return None
        expr = parts[0]
        for part in parts[1:]:
            expr = BinaryOp(self.manager.next_atom(), "Add", [expr, part], False, bits=_STRING_BITS, **call.tags)
        return expr

    def _rw_memequal(self, call: Call, args: list) -> Expression | None:
        if len(args) != 3:
            return None
        a = self.values.field(args[0])
        b = self.values.field(args[1])
        size = args[2]
        lhs = rhs = None
        if a is not None and a[1] == _PTR:
            lhs = a[0].value(self.manager, self.project.arch, _STRING_BITS // 8, args[0].tags)
        if b is not None and b[1] == _PTR:
            rhs = b[0].value(self.manager, self.project.arch, _STRING_BITS // 8, args[1].tags)
        # the compared length must be the length of one of the operands (or of a literal)
        ok = (a is not None and self.values.is_len_of(size, a[0])) or (
            b is not None and self.values.is_len_of(size, b[0])
        )
        if rhs is None and lhs is not None:
            rhs = self.values.literal(args[1], size)
            ok = ok or rhs is not None
        if lhs is None and rhs is not None:
            lhs = self.values.literal(args[0], size)
            ok = ok or lhs is not None
        if lhs is None or rhs is None or not ok:
            return None
        return self.compare("CmpEQ", lhs, rhs, call.bits, call.tags)

    def _rw_memequal_n(self, call: Call, args: list, size: int) -> Expression | None:
        if len(args) != 2:
            return None
        endness = self.project.arch.memory_endness
        lhs = Load(self.manager.next_atom(), args[0], size, endness, **args[0].tags)
        rhs = Load(self.manager.next_atom(), args[1], size, endness, **args[1].tags)
        return self.compare("CmpEQ", lhs, rhs, call.bits, call.tags)

    def _rw_rename(self, call: Call, args: list, name: str) -> Expression | None:
        return self.builtin(call, name, args)

    def _rw_slicebytetostring(self, call: Call, args: list) -> Expression | None:
        b = self.values.slice(args[1], args[2]) if len(args) == 3 else None
        if b is None:
            return None
        return self.builtin(call, "string", [b], bits=_STRING_BITS, go_result_type="string")

    def _rw_conversion(self, call: Call, args: list, name: str, bits: int, result: str) -> Expression | None:
        if len(args) != 2:
            return None
        return self.builtin(call, name, [args[1]], bits=bits, go_result_type=result)

    def _rw_intstring(self, call: Call, args: list) -> Expression | None:
        if len(args) != 2:
            return None
        rune = Call(self.manager.next_atom(), "rune", [args[1]], bits=32, go_result_type="rune", **args[1].tags)
        return self.builtin(call, "string", [rune], bits=_STRING_BITS, go_result_type="string")

    def _rw_slicecopy(self, call: Call, args: list) -> Expression | None:
        if len(args) != 5:
            return None
        dst = self.values.slice(args[0], args[1])
        src = self.values.slice(args[2], args[3])
        if dst is None or src is None:
            return None
        return self.builtin(call, "copy", [dst, src], go_result_type="int")

    def _rw_memmove(self, call: Call, args: list) -> Expression | None:
        # copy(dst, src): memmove(dst.ptr, src.ptr, min(len(dst), len(src)) * width)
        if len(args) != 3:
            return None
        dst = self.values.field(args[0])
        src = self.values.field(args[1])
        if dst is None or src is None or dst[1] != _PTR or src[1] != _PTR:
            return None
        count = args[2]
        if isinstance(count, BinaryOp) and count.op == "Mul" and isinstance(count.operands[1], Const):
            count = count.operands[0]
        if not self._is_min_len(count, dst[0], src[0]):
            return None
        arch = self.project.arch
        dst_val = dst[0].value(self.manager, arch, _SLICE_BITS // 8, args[0].tags)
        src_val = src[0].value(self.manager, arch, None if src[0].combo else _SLICE_BITS // 8, args[1].tags)
        if dst_val is None or src_val is None:
            return None
        return self.builtin(call, "copy", [dst_val, src_val], bits=self.project.arch.bits, go_result_type="int")

    def _is_min_len(self, count: Expression, a: _Base, b: _Base) -> bool:
        count = self.values.resolve(count)
        if self.values.is_len_of(count, a) or self.values.is_len_of(count, b):
            return True
        candidates = None
        if isinstance(count, VirtualVariable):
            src = self.values.defs.get(count.varid)
            if isinstance(src, Phi):
                candidates = [v for _, v in src.src_and_vvars]
            elif isinstance(src, ITE):
                candidates = [src.iftrue, src.iffalse]
        elif isinstance(count, ITE):
            candidates = [count.iftrue, count.iffalse]
        if not candidates or len(candidates) != 2 or any(c is None for c in candidates):
            return False
        x, y = candidates
        return (self.values.is_len_of(x, a) and self.values.is_len_of(y, b)) or (
            self.values.is_len_of(x, b) and self.values.is_len_of(y, a)
        )

    def _rw_gopanic(self, call: Call, args: list) -> Expression | None:
        return self.builtin(call, "panic", args) if len(args) == 1 else None

    #
    # Statement rules: typed moves and clears become stores
    #

    def rewrite_call_stmt(self, stmt: SideEffectStatement) -> Statement | None:
        call = stmt.expr
        if not isinstance(call, Call) or stmt.ret_expr is not None:
            return None
        name = self.callee_name(call)
        args = list(call.args or [])
        endness = self.project.arch.memory_endness
        if name == "runtime.typedmemmove" and len(args) == 3:
            size = self.type_size(args[0])
            if size is None:
                return None
            src = Load(self.manager.next_atom(), args[2], size, endness, **args[2].tags)
            return Store(stmt.idx, args[1], src, size, endness, **stmt.tags)
        if name == "runtime.typedmemclr" and len(args) == 2:
            size, ty = self.type_size(args[0]), self.type_name(args[0])
            if size is None or ty is None:
                return None
            zero = Struct(self.manager.next_atom(), ty, OrderedDict(), OrderedDict(), size * 8, **args[1].tags)
            return Store(stmt.idx, args[1], zero, size, endness, **stmt.tags)
        if name == "runtime.memclrNoHeapPointers" and len(args) == 2:
            size = _const(args[1])
            if size not in (1, 2, 4, 8, 16):
                return None
            zero = Const(self.manager.next_atom(), 0, size * 8, **args[1].tags)
            return Store(stmt.idx, args[0], zero, size, endness, **stmt.tags)
        return None

    #
    # Expression rules
    #

    def rewrite_binop(self, expr: BinaryOp) -> Expression | None:
        # cmpstring(a, b) <op> 0  ->  a <op> b
        if expr.op not in _COMPARISONS:
            return None
        lhs, rhs = expr.operands
        op = expr.op
        if _const(lhs) == 0 and isinstance(_strip_converts(rhs), Call):
            lhs, rhs = rhs, lhs
            op = _SWAPPED[op]
        call = _strip_converts(lhs)
        if _const(rhs) != 0 or not isinstance(call, Call) or self.callee_name(call) != "runtime.cmpstring":
            return None
        args = list(call.args or [])
        if len(args) != 2 or any(a.bits != _STRING_BITS for a in args):
            return None
        return self.compare(op, args[0], args[1], expr.bits, expr.tags)

    def rewrite_ite(self, expr: ITE) -> Expression | None:
        # len(a) == len(b) ? a == b : false  ->  a == b
        cond = _strip_converts(expr.cond)
        eq = _strip_converts(expr.iftrue)
        iffalse = _strip_converts(expr.iffalse)
        if not (isinstance(cond, BinaryOp) and cond.op == "CmpEQ" and isinstance(eq, BinaryOp) and eq.op == "CmpEQ"):
            return None
        if not (_const(iffalse) == 0 or iffalse.likes(cond)):
            return None
        a, b = eq.operands
        if a.bits != _STRING_BITS or b.bits != _STRING_BITS:
            return None
        if not all(self._is_len_check(operand, a, b) for operand in cond.operands):
            return None
        return self.to_bits(eq, expr.bits)

    def _is_len_check(self, operand: Expression, a: Expression, b: Expression) -> bool:
        for value in (a, b):
            if isinstance(value, StringLiteral):
                base = None
                if _const(operand) == len(value.data.encode("utf-8")):
                    return True
            elif isinstance(value, VirtualVariable):
                base = _Base(combo=value)
            elif isinstance(value, Load):
                base = _Base(addr=value.addr)
            else:
                base = None
            if base is not None and self.values.is_len_of(operand, base):
                return True
        return False

    def rewrite_struct(self, expr: Struct) -> Expression | None:
        fields = [expr.fields[off] for off in sorted(expr.fields)]
        if not fields:
            return None
        # the pieces of one combo-register value, in order: the value itself
        first = self.values.field(fields[0])
        if first is not None and first[0].combo is not None and first[1] == 0:
            combo = first[0].combo
            pieces = [self.values.resolve(f) for f in fields]
            ids = [rv.varid for rv in combo.reg_vvars]
            if (
                all(isinstance(p, VirtualVariable) for p in pieces)
                and [p.varid for p in pieces] == ids
                and combo.bits == expr.bits
            ):
                return combo
        return self._rewrite_slicing(expr, fields)

    def _rewrite_slicing(self, expr: Struct, fields: list) -> Expression | None:
        # s[i:j] / s[i:] / s[:j]: {ptr: s.ptr + i*w (guarded), len: j - i, cap: s.cap - i}
        if len(fields) != 3 or expr.bits != _SLICE_BITS:
            return None
        ptr, length, cap = fields
        base = None
        low = None
        if isinstance(cap, BinaryOp) and cap.op == "Sub":
            hit = self.values.field(cap.operands[0])
            if hit is None or hit[1] != _CAP:
                return None
            base, low = hit[0], cap.operands[1]
        else:
            hit = self.values.field(cap)
            if hit is None or hit[1] != _CAP:
                return None
            base = hit[0]
        if low is None:
            # s[:j]
            hit = self.values.field(ptr)
            if hit is None or hit[1] != _PTR or not hit[0].same(base) or self.values.is_len_of(length, base):
                return None
            high = length
        else:
            if not (isinstance(ptr, BinaryOp) and ptr.op == "Add"):
                return None
            p, advance = ptr.operands
            hit = self.values.field(p)
            if hit is None or hit[1] != _PTR or not hit[0].same(base):
                hit = self.values.field(advance)
                if hit is None or hit[1] != _PTR or not hit[0].same(base):
                    return None
                advance = p
            if not self._is_guarded_advance(advance, low):
                return None
            if not (isinstance(length, BinaryOp) and length.op == "Sub" and length.operands[1].likes(low)):
                return None
            high = None if self.values.is_len_of(length.operands[0], base) else length.operands[0]
        s = base.value(self.manager, self.project.arch, _SLICE_BITS // 8, expr.tags)
        if s is None:
            return None
        if low is None:
            shape, args = "[:j]", [s, high]
        elif high is None:
            shape, args = "[i:]", [s, low]
        else:
            shape, args = "[i:j]", [s, low, high]
        return Call(expr.idx, "[:]", args, bits=_SLICE_BITS, go_slice=shape, **expr.tags)

    @staticmethod
    def _is_guarded_advance(advance: Expression, low: Expression) -> bool:
        # i*w masked by (-(cap - i) >> 63) so an empty result does not point past the array
        def is_guard(e):
            return isinstance(e, BinaryOp) and e.op == "Sar" and _const(e.operands[1]) == 63

        def is_offset(e):
            if isinstance(e, BinaryOp) and e.op == "Mul":
                return any(o.likes(low) for o in e.operands)
            k = _const(low)
            return k is not None and isinstance(e, Const) and e.value_int in {k * w for w in (1, 2, 4, 8, 16)}

        return _has_node(advance, is_guard) and _has_node(advance, is_offset)

    #
    # growslice diamonds
    #

    def _fold_growslice(self) -> list[Block]:
        touched: list[Block] = []
        for block in list(self._graph.nodes):
            if block not in self._graph:
                continue
            match = self._match_growslice(block)
            if match is not None:
                self._apply_append(*match)
                touched += [block, match[5], match[7]]
        return touched

    def _match_growslice(self, block: Block):
        call_stmt = None
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                if call_stmt is not None or self.callee_name(stmt.src) != "runtime.growslice":
                    return None
                call_stmt = stmt
            elif isinstance(stmt, Assignment):
                if not isinstance(stmt.src, (VirtualVariable, Const)):
                    return None
            elif not isinstance(stmt, (Label, Jump)):
                return None
        if call_stmt is None or not isinstance(call_stmt.dst, VirtualVariable):
            return None
        args = list(call_stmt.src.args or [])
        if len(args) != 5:
            return None
        old_ptr, new_len, old_cap, num, et = args
        base = self.values.field(old_ptr)
        if base is None or base[1] != _PTR:
            return None
        base = base[0]
        cap_hit = self.values.field(old_cap)
        if cap_hit is None or cap_hit[1] != _CAP or not cap_hit[0].same(base):
            return None
        count = _const(num)
        if count is None or count <= 0:
            return None
        # newLen = len(s) + num
        grown = self.values.expand(new_len)
        if not (isinstance(grown, BinaryOp) and grown.op == "Add"):
            return None
        x, y = grown.operands
        if not (
            (self.values.is_len_of(x, base) and _const(y) == count)
            or (self.values.is_len_of(y, base) and _const(x) == count)
        ):
            return None

        succs = list(self._graph.successors(block))
        if len(succs) != 1:
            return None
        join = skip_jumps(self._graph, succs[0])
        cond_block = conditional_pred(self._graph, block)
        if cond_block is None or join is cond_block:
            return None
        cond_jump = cond_block.statements[-1]
        cond = cond_jump.condition
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpLT", "CmpLE", "CmpGT", "CmpGE")):
            return None
        operands = [self.values.resolve(o) for o in cond.operands]
        wanted = [self.values.resolve(old_cap), self.values.resolve(new_len)]
        if not (
            (operands[0].likes(wanted[0]) and operands[1].likes(wanted[1]))
            or (operands[0].likes(wanted[1]) and operands[1].likes(wanted[0]))
        ):
            return None
        other = [s for s in self._graph.successors(cond_block) if not leads_to(self._graph, s, block)]
        if len(other) != 1 or skip_jumps(self._graph, other[0]) is not join:
            return None
        other = other[0]
        pre_join = cond_block if other is join else block_before(self._graph, other, join)
        post_grow = block if succs[0] is join else block_before(self._graph, succs[0], join)
        if pre_join is None or post_grow is None:
            return None

        # element stores in the join block: ptr[newLen - num + i] = elem_i
        phis = self._phis(join)
        ptr_phi = len_phi = None
        for dst, phi in phis.values():
            entries = dict(phi.src_and_vvars)
            grown_side = entries.get((post_grow.addr, post_grow.idx))
            old_side = entries.get((pre_join.addr, pre_join.idx))
            if grown_side is None or old_side is None:
                continue
            grown_hit = self.values.combo_of.get(grown_side.varid)
            if grown_hit is None or grown_hit[0].varid != call_stmt.dst.varid:
                continue
            old_hit = self.values.field(old_side)
            if grown_hit[1] == _PTR and old_hit is not None and old_hit[1] == _PTR and old_hit[0].same(base):
                ptr_phi = dst
            elif grown_hit[1] == _LEN and self.values.resolve(old_side).likes(self.values.resolve(new_len)):
                len_phi = dst
        elems = None
        stores: list[Store] = []
        if ptr_phi is not None and len_phi is not None:
            found: dict[int, tuple[Store, Expression]] = {}
            for stmt in join.statements:
                if isinstance(stmt, Store):
                    parsed = self._parse_elem_store(stmt.addr, ptr_phi, len_phi)
                    if parsed is not None and 1 <= parsed <= count and parsed not in found:
                        found[parsed] = (stmt, stmt.data)
            if len(found) == count:
                elems = self._elements(join, phis, post_grow, [found[k][1] for k in range(count, 0, -1)])
                stores = [found[k][0] for k in found]
        return block, call_stmt, base, count, et, cond_block, other, join, pre_join, phis, elems, stores

    def _elements(self, join: Block, phis: dict, post_grow: Block, data: list) -> list | None:
        """The stored values as seen on the grow path; None when one is computed in the join block itself."""
        defined_in_join = {
            stmt.dst.varid
            for stmt in join.statements
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
        }
        elems = []
        for value in data:
            value = self.values.resolve(value)
            if isinstance(value, VirtualVariable) and value.varid in phis:
                value = dict(phis[value.varid][1].src_and_vvars).get((post_grow.addr, post_grow.idx))
                value = self.values.resolve(value) if value is not None else None
            if isinstance(value, Const) or (isinstance(value, VirtualVariable) and value.varid not in defined_in_join):
                elems.append(value)
            else:
                return None
        return elems

    @staticmethod
    def _phis(block: Block) -> dict[int, tuple[VirtualVariable, Phi]]:
        phis = {}
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and isinstance(stmt.dst, VirtualVariable):
                phis[stmt.dst.varid] = (stmt.dst, stmt.src)
        return phis

    def _parse_elem_store(self, addr: Expression, ptr_phi: VirtualVariable, len_phi: VirtualVariable) -> int | None:
        """``(ptr + len*w) - k*w`` or ``ptr + (len - k)*w`` -> k."""
        if not (isinstance(addr, BinaryOp) and addr.op in ("Sub", "Add")):
            return None
        lhs, rhs = addr.operands
        if addr.op == "Sub":
            back = _const(rhs)
            if back is None or not (isinstance(lhs, BinaryOp) and lhs.op == "Add"):
                return None
            p, scaled = lhs.operands
            if not self.values.resolve(p).likes(ptr_phi):
                return None
            width = self._scaled_len(scaled, len_phi)
            return back // width if width and back % width == 0 else None
        p, scaled = lhs, rhs
        if not self.values.resolve(p).likes(ptr_phi):
            p, scaled = rhs, lhs
            if not self.values.resolve(p).likes(ptr_phi):
                return None
        if isinstance(scaled, BinaryOp) and scaled.op == "Mul" and isinstance(scaled.operands[1], Const):
            inner = scaled.operands[0]
            if (
                isinstance(inner, BinaryOp)
                and inner.op == "Sub"
                and self.values.resolve(inner.operands[0]).likes(len_phi)
            ):
                return _const(inner.operands[1])
        elif (
            isinstance(scaled, BinaryOp)
            and scaled.op == "Sub"
            and self.values.resolve(scaled.operands[0]).likes(len_phi)
        ):
            return _const(scaled.operands[1])
        return None

    def _scaled_len(self, expr: Expression, len_phi: VirtualVariable) -> int | None:
        if self.values.resolve(expr).likes(len_phi):
            return 1
        if isinstance(expr, BinaryOp) and expr.op == "Mul":
            a, b = expr.operands
            if self.values.resolve(a).likes(len_phi) and isinstance(b, Const):
                return b.value_int
            if self.values.resolve(b).likes(len_phi) and isinstance(a, Const):
                return a.value_int
        return None

    def _apply_append(self, block, call_stmt, base, count, et, cond_block, other, join, pre_join, phis, elems, stores):
        call = call_stmt.src
        s = base.value(self.manager, self.project.arch, _SLICE_BITS // 8, call.tags)
        if s is None:
            return
        ty = self.type_name(et)
        extra = {"go_result_type": f"[]{ty}"} if ty else {}
        if elems is None:
            extra["go_comment"] = f"{count} element(s) not recovered"
        new_call = self.builtin(call, "append", [s, *(elems or [])], bits=_SLICE_BITS, **extra)
        block.statements = [
            Assignment(stmt.idx, stmt.dst, new_call, **stmt.tags) if stmt is call_stmt else stmt
            for stmt in block.statements
        ]

        # the grow path is now the only path: append itself decides whether to grow
        self.remove_jump_target(cond_block, other.addr, other.idx)
        dead = other
        while dead is not join and dead in self._graph and self._graph.in_degree(dead) == 0:
            succs = list(self._graph.successors(dead))
            self._graph.remove_node(dead)
            self._block_by_addr_and_idx.pop((dead.addr, dead.idx), None)
            if len(succs) != 1:
                break
            dead = succs[0]

        # the join no longer merges two paths
        replacements: dict[int, VirtualVariable] = {}
        new_stmts = []
        for stmt in join.statements:
            if stmt in stores:
                continue
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and stmt.dst.varid in phis:
                entries = [(src, v) for src, v in stmt.src.src_and_vvars if src != (pre_join.addr, pre_join.idx)]
                if len(entries) == 1 and entries[0][1] is not None:
                    replacements[stmt.dst.varid] = self.values.resolve(entries[0][1])
                    continue
                if len(entries) != len(stmt.src.src_and_vvars):
                    phi = Phi(stmt.src.idx, stmt.src.bits, entries, **stmt.src.tags)
                    stmt = Assignment(stmt.idx, stmt.dst, phi, **stmt.tags)
            new_stmts.append(stmt)
        join.statements = new_stmts
        if replacements:
            subst = _VVarSubstituter(replacements)
            for blk in self._graph.nodes:
                subst.walk(blk)
        l.debug("Folded growslice diamond at %#x of %s into append", block.addr, self._func.name)


_SWAPPED = {"CmpEQ": "CmpEQ", "CmpNE": "CmpNE", "CmpLT": "CmpGT", "CmpGT": "CmpLT", "CmpLE": "CmpGE", "CmpGE": "CmpLE"}

_CALL_RULES = {
    "runtime.newobject": GoBuiltinRewriter._rw_newobject,
    "runtime.mallocgc": GoBuiltinRewriter._rw_mallocgc,
    "runtime.makeslice": GoBuiltinRewriter._rw_makeslice,
    "runtime.makeslice64": GoBuiltinRewriter._rw_makeslice,
    "runtime.growslice": GoBuiltinRewriter._rw_growslice,
    "runtime.concatstring2": GoBuiltinRewriter._rw_concatstring,
    "runtime.concatstring3": GoBuiltinRewriter._rw_concatstring,
    "runtime.concatstring4": GoBuiltinRewriter._rw_concatstring,
    "runtime.concatstring5": GoBuiltinRewriter._rw_concatstring,
    "runtime.memequal": GoBuiltinRewriter._rw_memequal,
    "runtime.memequal8": lambda p, c, a: p._rw_memequal_n(c, a, 1),
    "runtime.memequal16": lambda p, c, a: p._rw_memequal_n(c, a, 2),
    "runtime.memequal32": lambda p, c, a: p._rw_memequal_n(c, a, 4),
    "runtime.memequal64": lambda p, c, a: p._rw_memequal_n(c, a, 8),
    "runtime.memequal128": lambda p, c, a: p._rw_memequal_n(c, a, 16),
    "internal/bytealg.Equal": lambda p, c, a: p._rw_rename(c, a, "bytes.Equal"),
    "internal/bytealg.Compare": lambda p, c, a: p._rw_rename(c, a, "bytes.Compare"),
    "runtime.slicebytetostring": GoBuiltinRewriter._rw_slicebytetostring,
    "runtime.stringtoslicebyte": lambda p, c, a: p._rw_conversion(c, a, "[]byte", _SLICE_BITS, "[]uint8"),
    "runtime.stringtoslicerune": lambda p, c, a: p._rw_conversion(c, a, "[]rune", _SLICE_BITS, "[]int32"),
    "runtime.slicerunetostring": lambda p, c, a: p._rw_conversion(c, a, "string", _STRING_BITS, "string"),
    "runtime.intstring": GoBuiltinRewriter._rw_intstring,
    "runtime.slicecopy": GoBuiltinRewriter._rw_slicecopy,
    "runtime.memmove": GoBuiltinRewriter._rw_memmove,
    "runtime.gopanic": GoBuiltinRewriter._rw_gopanic,
}


class _BuiltinRewriter(AILBlockRewriter):
    def __init__(self, pass_: GoBuiltinRewriter):
        super().__init__()
        self._pass = pass_
        self.changed = False

    def _apply(self, old, new):
        if new is None:
            return old
        self.changed = True
        return new

    def _handle_Call(self, expr_idx, expr: Call, stmt_idx, stmt, block):
        expr = super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)
        return self._apply(expr, self._pass.rewrite_call(expr))

    def _handle_BinaryOp(self, expr_idx, expr: BinaryOp, stmt_idx, stmt, block):
        expr = super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)
        return self._apply(expr, self._pass.rewrite_binop(expr) if isinstance(expr, BinaryOp) else None)

    def _handle_ITE(self, expr_idx, expr: ITE, stmt_idx, stmt, block):
        expr = super()._handle_ITE(expr_idx, expr, stmt_idx, stmt, block)
        return self._apply(expr, self._pass.rewrite_ite(expr) if isinstance(expr, ITE) else None)

    def _handle_Struct(self, expr_idx, expr: Struct, stmt_idx, stmt, block):
        expr = super()._handle_Struct(expr_idx, expr, stmt_idx, stmt, block)
        return self._apply(expr, self._pass.rewrite_struct(expr) if isinstance(expr, Struct) else None)

    def _handle_SideEffectStatement(self, stmt_idx, stmt: SideEffectStatement, block):
        stmt = super()._handle_SideEffectStatement(stmt_idx, stmt, block)
        if isinstance(stmt, SideEffectStatement):
            return self._apply(stmt, self._pass.rewrite_call_stmt(stmt))
        return stmt


class _VVarCounter(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.counts: Counter = Counter()

    def _handle_VirtualVariable(self, expr_idx, expr: VirtualVariable, stmt_idx, stmt, block):
        self.counts[expr.varid] += 1

    def _handle_Phi(self, expr_idx, expr: Phi, stmt_idx, stmt, block):
        for _, vvar in expr.src_and_vvars:
            if vvar is not None:
                self.counts[vvar.varid] += 1


class _VVarSubstituter(AILBlockRewriter):
    def __init__(self, replacements: dict[int, VirtualVariable]):
        super().__init__(replace_phi_stmt=True)
        self._replacements = replacements

    def _handle_VirtualVariable(self, expr_idx, expr: VirtualVariable, stmt_idx, stmt, block):
        new = self._replacements.get(expr.varid)
        return new if new is not None else expr
