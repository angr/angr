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
    Extract,
    Load,
    Phi,
    StringLiteral,
    Struct,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import (
    Assignment,
    ConditionalJump,
    Jump,
    Label,
    Return,
    SideEffectStatement,
    Statement,
    Store,
)
from angr.analyses.decompiler.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimTypeFunction, GoSimTypeMap, GoSimTypeTuple
from angr.go.utils.graph import conditional_pred, is_jump_only, leads_to, skip_jumps
from angr.go.utils.names import call_target_name
from angr.go.utils.types import go_type_at, go_type_name_at
from angr.utils.ail import find_call
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


def _looks_like_text(data: str) -> bool:
    """Printable text (a format string, a message), not a run of bytes that happens to decode."""
    if not data:
        return False
    printable = sum(1 for ch in data if ch.isprintable() or ch in "\n\t\r")
    return printable >= 0.9 * len(data)


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
    """
    Where a string/slice value lives: a combo-register variable, memory at ``addr + off``, or ``words`` (a header
    the compiler keeps in separate scalars; only a call that takes the header apart proves they belong together).
    """

    __slots__ = ("addr", "combo", "conv", "name", "off", "words")

    def __init__(
        self,
        combo: VirtualVariable | None = None,
        addr: Expression | None = None,
        off: int = 0,
        words: tuple[Expression, ...] | None = None,
        name: str | None = None,
    ):
        self.combo = combo
        self.addr = addr
        self.off = off
        self.words = words
        self.name = name
        self.conv: str | None = None  # a conversion applied to the value ([]byte of a string)

    def same(self, other: _Base) -> bool:
        if self.combo is not None:
            return other.combo is not None and other.combo.varid == self.combo.varid
        if self.addr is not None:
            return other.addr is not None and self.off == other.off and self.addr.likes(other.addr)
        if self.words is not None:
            return (
                other.words is not None
                and len(self.words) == len(other.words)
                and all(a.likes(b) for a, b in zip(self.words, other.words))
            )
        return False

    def address(self, manager, arch) -> Expression | None:
        if self.addr is None:
            return None
        if not self.off:
            return self.addr
        return BinaryOp(manager.next_atom(), "Add", [self.addr, Const(manager.next_atom(), self.off, arch.bits)], False)

    def value(self, manager, arch, size: int | None, tags, name: str | None = None) -> Expression | None:
        if self.conv is not None:
            inner = _Base(combo=self.combo, addr=self.addr, off=self.off).value(manager, arch, _STRING_BITS // 8, tags)
            if inner is None:
                return None
            return Call(manager.next_atom(), self.conv, [inner], bits=_SLICE_BITS, go_result_type="[]uint8", **tags)
        if self.combo is not None:
            return self.combo if size is None or self.combo.size == size else None
        if self.addr is not None:
            if size is None:
                return None
            return Load(manager.next_atom(), self.address(manager, arch), size, arch.memory_endness, **tags)
        if self.words is not None:
            ws = arch.bytes
            words = self.words if size is None else self.words[: size // ws]
            name = name or self.name or ("string" if len(words) == 2 else "[]byte")
            if all(_const(w) == 0 for w in words):
                # the nil slice
                return Struct(manager.next_atom(), name, OrderedDict(), OrderedDict(), len(words) * arch.bits, **tags)
            fields = OrderedDict((i * ws, w) for i, w in enumerate(words))
            names = OrderedDict((n, i * ws) for i, n in enumerate(("ptr", "len", "cap")[: len(words)]))
            return Struct(manager.next_atom(), name, fields, names, len(words) * arch.bits, **tags)
        return None


class _Values:
    """Map the pieces the ABI splits string/slice values into back to the values they belong to."""

    def __init__(self, pass_: GoBuiltinRewriter):
        self.project = pass_.project
        self.manager = pass_.manager
        self.combo_of: dict[int, tuple[VirtualVariable, int]] = {}
        self.defs: dict[int, Expression] = {}
        # phis that a pending rewrite will collapse: varid -> the value that survives
        self.aliases: dict[int, Expression] = {}

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

    def resolve(self, expr: Expression, seen: set | None = None) -> Expression:
        """Look through virtual-variable copies (register moves and spills) and phis of one value."""
        seen = set() if seen is None else seen
        while isinstance(expr, VirtualVariable) and expr.varid not in seen:
            seen.add(expr.varid)
            src = self.aliases.get(expr.varid, self.defs.get(expr.varid))
            if isinstance(src, VirtualVariable):
                expr = src
                continue
            if isinstance(src, Phi):
                sources = [self.resolve(v, seen) for _, v in src.src_and_vvars if v is not None]
                sources = [v for v in sources if not (isinstance(v, VirtualVariable) and v.varid == expr.varid)]
                if sources and all(v.likes(sources[0]) for v in sources[1:]):
                    expr = sources[0]
                    continue
            break
        return expr

    def expand(self, expr: Expression) -> Expression:
        """Like ``resolve`` but also returns the defining expression of the final variable when it has one."""
        expr = self.resolve(expr)
        if isinstance(expr, VirtualVariable):
            src = self.defs.get(expr.varid)
            if src is not None and not isinstance(src, Phi):
                return src
        return expr

    def same(self, a: Expression, b: Expression) -> bool:
        return self.expand(a).likes(self.expand(b))

    def load_of(self, expr: Expression) -> tuple[Expression | None, int] | None:
        """(base, offset) when ``expr`` is (a copy of) a word-sized load from ``base + offset``."""
        expr = self.expand(expr)
        if not (isinstance(expr, Load) and expr.size == self.project.arch.bytes):
            return None
        base, off = _addr_and_offset(expr.addr)
        return (self.resolve(base) if base is not None else None), off

    def base_of(self, expr: Expression, want: int) -> _Base | None:
        """The value ``expr`` is the piece at byte offset ``want`` of (a combo-register value or memory)."""
        resolved = self.resolve(expr)
        if isinstance(resolved, VirtualVariable):
            hit = self.combo_of.get(resolved.varid)
            if hit is not None:
                return _Base(combo=hit[0]) if hit[1] == want else None
        load = self.load_of(expr)
        if load is None:
            return None
        base, off = load
        if base is None:
            return _Base(addr=Const(self.manager.next_atom(), off - want, self.project.arch.bits))
        return _Base(addr=base, off=off - want)

    def base_of_value(self, expr: Expression) -> _Base | None:
        """The place a whole string/slice expression stands for."""
        resolved = self.resolve(expr)
        if isinstance(resolved, VirtualVariable):
            return _Base(combo=resolved) if resolved.varid not in self.combo_of else None
        if isinstance(expr, Load):
            base, off = _addr_and_offset(expr.addr)
            if base is None:
                return _Base(addr=Const(self.manager.next_atom(), off, self.project.arch.bits))
            return _Base(addr=self.resolve(base), off=off)
        if isinstance(expr, Struct):
            ws = self.project.arch.bytes
            fields = expr.fields
            if sorted(fields) in ([0, ws], [0, ws, 2 * ws]):
                return _Base(words=tuple(self.resolve(fields[k]) for k in sorted(fields)), name=expr.name)
        return None

    def piece(self, expr: Expression, base: _Base) -> int | None:
        """The byte offset at which ``expr`` sits inside ``base``, or None when it is not a piece of it."""
        resolved = self.resolve(expr)
        if base.combo is not None:
            if isinstance(resolved, VirtualVariable):
                hit = self.combo_of.get(resolved.varid)
                if hit is not None and hit[0].varid == base.combo.varid:
                    return hit[1]
            return None
        if base.addr is not None:
            load = self.load_of(expr)
            if load is None:
                return None
            b, off = load
            if b is None:
                if _const(base.addr) is None:
                    return None
                return off - base.addr.value_int - base.off
            return off - base.off if b.likes(base.addr) else None
        if base.words is not None:
            for i, word in enumerate(base.words):
                if self.same(expr, word):
                    return i * self.project.arch.bytes
        return None

    def field(self, expr: Expression) -> tuple[_Base, int] | None:
        """The (value, byte offset) a pointer-sized expression is a piece of, the value taken to start at the load base."""
        resolved = self.resolve(expr)
        if isinstance(resolved, VirtualVariable):
            hit = self.combo_of.get(resolved.varid)
            if hit is not None:
                return _Base(combo=hit[0]), hit[1]
        load = self.load_of(expr)
        if load is None:
            return None
        base, off = load
        if base is None:
            return _Base(addr=Const(self.manager.next_atom(), off, self.project.arch.bits)), 0
        return _Base(addr=base), off

    def header(self, ptr: Expression, cap: Expression, length: Expression | None, name: str | None) -> _Base | None:
        """
        The slice whose pointer and capacity words are ``ptr`` and ``cap``: a tracked value when the pointer word
        belongs to one, else the header made of the three scalars (``length`` is its length word).
        """
        base = self.base_of(ptr, _PTR)
        if base is not None:
            at = self.piece(cap, base)
            if at == _CAP:
                return base
            if at == _LEN and (base.combo is None or base.combo.size == _STRING_BITS // 8):
                # a string's bytes: []byte(s) has cap == len
                base.conv = "[]byte"
                return base
        if length is None:
            return None
        return _Base(words=(self.resolve(ptr), self.resolve(length), self.resolve(cap)), name=name)

    def whole(self, size: int | None, *pieces: tuple[Expression, int], tags=None) -> Expression | None:
        """The value whose pieces at the given byte offsets are ``pieces``; ``size`` None means any size."""
        base = self.base_of(pieces[0][0], pieces[0][1])
        if base is None:
            return None
        for expr, want in pieces[1:]:
            if self.piece(expr, base) != want:
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
        base = self.base_of(ptr, _PTR)
        size = None if base is not None and base.combo is not None else _SLICE_BITS // 8
        return self.whole(size, (ptr, _PTR), (length, _LEN))

    def is_len_of(self, expr: Expression, base: _Base) -> bool:
        return self.piece(expr, base) == _LEN


class GoBuiltinRewriter(OptimizationPass, CFGTransformationMixin):
    """
    Turn calls into the Go runtime back into the builtins and operators the compiler lowered them from: ``new``,
    ``make``, ``append``, ``copy``, ``panic``, string concatenation/comparison and the string/slice conversions.

    ``growslice`` is special: the compiler only calls it when the slice must grow, so the call sits under an
    ``if newLen > cap`` diamond whose join block stores the appended elements (go1.25+ nests a stack-buffer choice
    under the check). The diamond is folded into one unconditional ``append(s, elems...)`` (append grows on demand
    itself) and the element stores are dropped; a ``memmove``/``typedslicecopy`` of the new elements is
    ``append(s, t...)``. The slice may be a tracked value, a field of a struct in memory, a header the compiler keeps
    in three scalars, or an array (``arr[:n]``). When the elements cannot be matched the call still becomes
    ``append(s)`` with a comment giving the element count.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Rewrite Go runtime calls into builtins"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self.values: _Values | None = None
        self._cur_block: Block | None = None
        self._cur_stmt: Statement | None = None
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self.values = _Values(self)
        touched = self._fold_growslice()
        touched += self._fold_map_slots()
        touched += self._fold_move_slice()
        if touched:
            self._drop_dead_defs(touched)
            self.values = _Values(self)
        rewriter = _BuiltinRewriter(self)
        for block in list(self._graph.nodes):
            rewriter.walk(block)
        folded = self._fold_returns()
        dropped = self._drop_unused_call_results()
        if touched or rewriter.changed or folded or dropped:
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

    def _drop_unused_call_results(self) -> bool:
        """``v = f(...)`` with ``v`` never read becomes the call statement ``f(...)``."""
        counts = self._use_counts()
        changed = False
        for block in self._graph.nodes:
            for i, stmt in enumerate(block.statements):
                if not (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and isinstance(stmt.src, Call)
                    and not stmt.dst.was_stack
                ):
                    continue
                # a multi-register result is also used through its constituent registers
                uses = counts[stmt.dst.varid] - 1
                for rv in stmt.dst.reg_vvars or ():
                    uses += counts[rv.varid]
                if uses <= 0:
                    # the code generator reads render tags off the statement
                    tags = {**stmt.tags, **{k: v for k, v in stmt.src.tags.items() if k.startswith("go_")}}
                    block.statements[i] = SideEffectStatement(stmt.idx, stmt.src, **tags)
                    changed = True
        return changed

    def _fold_returns(self) -> bool:
        """``v = f(...)`` followed only by ``return v`` becomes ``return f(...)``."""
        counts = None
        folded = False
        for block in list(self._graph.nodes):
            if not block.statements or block not in self._graph:
                continue
            last = block.statements[-1]
            if not (isinstance(last, Assignment) and isinstance(last.dst, VirtualVariable)):
                continue
            src = last.src
            if not isinstance(src, Call) and not (
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
            folded = True
        return folded

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

    def builtin(
        self, call: Call, name: str, args: list, bits: int | None = None, arg_types: list[str] | None = None, **extra
    ) -> Call:
        tags = {k: v for k, v in call.tags.items() if not k.startswith("go_")}
        result_type = extra.get("go_result_type")
        if result_type is not None:
            tags["is_prototype_guessed"] = False
        new_call = Call(call.idx, name, args, bits=bits if bits is not None else call.bits, **tags, **extra)
        if result_type is not None:
            # lets type inference see the result type (and the argument types when given)
            with contextlib.suppress(Exception):
                returnty = self.kb.go_signatures.type(result_type)
                argtys = [self.kb.go_signatures.type(t) for t in arg_types] if arg_types else []
                proto = GoSimTypeFunction(argtys, returnty).with_arch(self.project.arch)
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

    def rewrite_call(self, call: Call, block: Block | None = None, stmt: Statement | None = None) -> Expression | None:
        name = self.callee_name(call)
        if name is None:
            return self._rw_itab_target(call)
        if name in ("mapindex", "mapassign") and block is not None:
            return self._rw_map_key_pointer(call, block, stmt)
        self._cur_block, self._cur_stmt = block, stmt
        rule = _CALL_RULES.get(name)
        if rule is None and name.startswith("runtime.mallocgc"):
            # go1.25+ inlines newobject into size-class specialized mallocgc variants
            rule = GoBuiltinRewriter._rw_mallocgc
        if rule is None:
            return self._rewrite_guessed_strings(call) or self._rewrite_descriptor_arg(call, name)
        args = list(call.args or [])
        try:
            return rule(self, call, args)
        except Exception:  # pylint:disable=broad-exception-caught
            l.debug("Rewriting %s failed", name, exc_info=True)
            return None

    def _rw_itab_target(self, call: Call) -> Expression | None:
        """``itab.fun[i](data, ...)`` through a constant itab is a direct call of the concrete method."""
        target = self.values.expand(call.target) if isinstance(call.target, VirtualVariable) else call.target
        if not (isinstance(target, Load) and target.size == self.project.arch.bytes):
            return None
        addr = _const(self.values.resolve(target.addr)) if not isinstance(target.addr, Const) else target.addr.value_int
        if addr is None:
            return None
        sym = self.project.loader.find_symbol(addr, fuzzy=True)
        if sym is None or not sym.name.startswith("go:itab."):
            return None
        with contextlib.suppress(KeyError):
            fun = self.project.loader.memory.unpack_word(addr, size=self.project.arch.bytes)
            if self.kb.functions.contains_addr(fun):
                return Call(
                    call.idx,
                    Const(self.manager.next_atom(), fun, self.project.arch.bits),
                    list(call.args or []),
                    bits=call.bits,
                    **call.tags,
                )
        return None

    def _rw_map_key_pointer(self, call: Call, block: Block, stmt: Statement) -> Expression | None:
        """``m[&slot]`` (a key the caller spilled to the stack for the generic runtime entry) -> ``m[key]``."""
        args = list(call.args or [])
        if len(args) < 2:
            return None
        key = args[1]
        slot = key.operand if isinstance(key, UnaryOp) and key.op == "Reference" else None
        if not isinstance(slot, VirtualVariable):
            return None
        map_name = self._map_type_name_of(args[0])
        ty = None
        with contextlib.suppress(Exception):
            ty = self.kb.go_signatures.type(map_name).with_arch(self.project.arch) if map_name else None
        if not isinstance(ty, GoSimTypeMap):
            return None
        key_ty = ty.key_type.with_arch(self.project.arch)
        size = self._type_size_bytes(key_ty)
        if not size:
            return None
        value = self._key_behind(key, size, key_ty.go_repr() if hasattr(key_ty, "go_repr") else "", block, stmt)
        return Call(call.idx, call.target, [args[0], value, *args[2:]], bits=call.bits, **call.tags)

    def _map_type_name_of(self, m: Expression) -> str | None:
        """The Go type of a map value: a typed struct field, a parameter, or a ``make`` result."""
        e = self.values.expand(m)
        if isinstance(e, Load):
            base, off = _addr_and_offset(e.addr)
            return self._field_type_name(base, off) if base is not None else None
        if isinstance(e, Call) and e.target == "make":
            type_args = list(e.tags.get("go_type_args", ()) or ())
            return type_args[0] if type_args else None
        resolved = self.values.resolve(m)
        proto = self._func.prototype
        if isinstance(resolved, VirtualVariable) and self._arg_vvars and isinstance(proto, GoSimTypeFunction):
            for (vvar, _), ty in zip(self._arg_vvars.values(), proto.args):
                if isinstance(vvar, VirtualVariable) and vvar.varid == resolved.varid and isinstance(ty, GoSimTypeMap):
                    return ty.go_repr()
        return None

    def _rewrite_descriptor_arg(self, call: Call, name: str) -> Expression | None:
        """A surviving runtime call whose first argument is a type descriptor: the type is spelled, not its address."""
        args = list(call.args or [])
        if not name.startswith(_DESCRIPTOR_CALLS) or not args:
            return None
        ty = self.type_name(args[0])
        if ty is None:
            return None
        return self.builtin(call, name, args[1:], go_type_args=[ty])

    def _rewrite_guessed_strings(self, call: Call) -> Expression | None:
        """
        A callee without a Go signature keeps its guessed prototype; two consecutive constant arguments that spell
        (read-only address, small length) of readable text are a string, passed as its two words.
        """
        if not call.tags.get("is_prototype_guessed", True):
            return None
        args = list(call.args or [])
        if len(args) < 2:
            return None
        out = []
        i = 0
        changed = False
        while i < len(args):
            if i + 1 < len(args) and isinstance(args[i], Const) and isinstance(args[i + 1], Const):
                n = _const(args[i + 1])
                literal = self.values.literal(args[i], args[i + 1]) if n and 0 < n <= 4096 else None
                if literal is not None and _looks_like_text(literal.data):
                    out.append(literal)
                    i += 2
                    changed = True
                    continue
            out.append(args[i])
            i += 1
        if not changed:
            return None
        return Call(call.idx, call.target, out, bits=call.bits, **call.tags)

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
        # the elements were not matched; keep the growth visible as append(s) with the missing elements in a comment
        if len(args) not in (5, 7):
            return None
        old_ptr, new_len, old_cap, num, et = args[:5]
        count = _const(num)
        old_len = self._old_length(new_len, old_cap, num, count)
        ty = self.type_name(et)
        s = self.values.header(old_ptr, old_cap, old_len, f"[]{ty}" if ty else None)
        if s is None:
            return None
        if s.words is None and old_len is not None and not self.values.is_len_of(old_len, s):
            s = _Base(
                words=(self.values.resolve(old_ptr), self.values.resolve(old_len), self.values.resolve(old_cap)),
                name=f"[]{ty}" if ty else None,
            )
        value = s.value(self.manager, self.project.arch, _SLICE_BITS // 8, call.tags)
        if value is None:
            return None
        comment = f"{count} element(s) not recovered" if count is not None else "elements not recovered"
        extra = {"go_result_type": f"[]{ty}"} if ty else {}
        return self.builtin(call, "append", [value], bits=_SLICE_BITS, go_comment=comment, **extra)

    def _rw_concatstring(self, call: Call, args: list) -> Expression | None:
        # a typed "+" call rather than an integer Add: type inference must see strings, not 128-bit integers
        parts = args[1:]
        if len(parts) < 2 or any(p.bits != _STRING_BITS for p in parts):
            return None
        variable_map = variable_map_of(self.manager)
        expr = parts[0]
        for part in parts[1:]:
            concat = self.builtin(
                call,
                "+",
                [expr, part],
                bits=_STRING_BITS,
                arg_types=["string", "string"],
                go_render="concat",
                go_result_type="string",
            )
            # each nested concatenation needs its own identity (the prototype is keyed by it)
            expr = Call(self.manager.next_atom(), concat.target, concat.args, bits=concat.bits, **concat.tags)
            variable_map.set_prototype(expr, variable_map.prototype(concat))
        return expr

    def _rw_memequal(self, call: Call, args: list) -> Expression | None:
        if len(args) != 3:
            return None
        a = self.values.base_of(args[0], _PTR)
        b = self.values.base_of(args[1], _PTR)
        size = args[2]
        lhs = rhs = None
        if a is not None:
            lhs = a.value(self.manager, self.project.arch, _STRING_BITS // 8, args[0].tags)
        if b is not None:
            rhs = b.value(self.manager, self.project.arch, _STRING_BITS // 8, args[1].tags)
        # the compared length must be the length of one of the operands (or of a literal)
        ok = (a is not None and self.values.is_len_of(size, a)) or (b is not None and self.values.is_len_of(size, b))
        if rhs is None and lhs is not None:
            rhs = self.values.literal(args[1], size)
            ok = ok or rhs is not None
        if lhs is None and rhs is not None:
            lhs = self.values.literal(args[0], size)
            ok = ok or lhs is not None
        if lhs is None or rhs is None or not ok:
            return self._memequal_fallback(call, args, a is None, b is None)
        return self.compare("CmpEQ", lhs, rhs, call.bits, call.tags)

    def _memequal_fallback(self, call: Call, args: list, a_untracked: bool, b_untracked: bool) -> Expression | None:
        """
        An operand that is not a tracked string: a word-sized compare becomes a load compared with the literal's
        value; anything else keeps the call, with the rodata pointer spelled as the literal of the compared length.
        """
        size = args[2]
        n = _const(size)
        lit_a = self.values.literal(args[0], size) if a_untracked else None
        lit_b = self.values.literal(args[1], size) if b_untracked else None
        if lit_a is None and lit_b is None:
            return None
        if n in (1, 2, 4, 8) and (lit_a is None) != (lit_b is None):
            lit, other = (lit_a, args[1]) if lit_a is not None else (lit_b, args[0])
            value = int.from_bytes(
                lit.data.encode("utf-8"), "little" if self.project.arch.memory_endness == "Iend_LE" else "big"
            )
            load = Load(self.manager.next_atom(), other, n, self.project.arch.memory_endness, **other.tags)
            return self.compare("CmpEQ", load, Const(self.manager.next_atom(), value, n * 8), call.bits, call.tags)
        return self.builtin(call, "runtime.memequal", [lit_a or args[0], lit_b or args[1], size], bits=call.bits)

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
        if len(args) != 3:
            return None
        b = self._slice_from_pair(args[1], args[2], "[]uint8")
        if b is None:
            return None
        return self.builtin(call, "string", [b], bits=_STRING_BITS, go_result_type="string")

    def _slice_from_pair(self, ptr: Expression, length: Expression, name: str) -> Expression | None:
        """
        The slice with the given pointer and length words: a tracked value, a slicing of one (``s[i:]``), an array
        (``arr[:n]``), or the two words spelled as a literal.
        """
        value = self.values.slice(ptr, length)
        if value is not None:
            return value
        p = self.values.expand(ptr) if isinstance(ptr, VirtualVariable) else ptr
        if isinstance(p, BinaryOp) and p.op == "Add":
            for base_word, advance in (p.operands, p.operands[::-1]):
                base = self.values.base_of(base_word, _PTR)
                if base is None:
                    continue
                low = self._advance_index(advance)
                l_expr = self.values.expand(length) if isinstance(length, VirtualVariable) else length
                if (
                    low is not None
                    and isinstance(l_expr, BinaryOp)
                    and l_expr.op == "Sub"
                    and self.values.is_len_of(l_expr.operands[0], base)
                    and self.values.same(l_expr.operands[1], low)
                ):
                    whole = base.value(self.manager, self.project.arch, _SLICE_BITS // 8, ptr.tags)
                    if whole is not None:
                        return Call(
                            self.manager.next_atom(), "[:]", [whole, low], bits=_SLICE_BITS, go_slice="[i:]", **ptr.tags
                        )
        if isinstance(ptr, UnaryOp) and ptr.op == "Reference" and _const(length) is not None:
            return Call(
                self.manager.next_atom(), "[:]", [ptr.operand, length], bits=_SLICE_BITS, go_slice="[:j]", **ptr.tags
            )
        return self._struct_of(name, [(0, ptr), (self.project.arch.bytes, length)])

    def _advance_index(self, advance: Expression) -> Expression | None:
        """``i*w & ((i - cap) >> 63)`` / ``i*w`` / ``i`` -> ``i``."""
        e = self.values.expand(advance) if isinstance(advance, VirtualVariable) else advance
        if isinstance(e, BinaryOp) and e.op == "And":
            a, b = e.operands
            for x, y in ((a, b), (b, a)):
                if _has_node(y, lambda n: isinstance(n, BinaryOp) and n.op == "Sar"):
                    e = self.values.expand(x) if isinstance(x, VirtualVariable) else x
                    break
        if isinstance(e, BinaryOp) and e.op == "Mul":
            a, b = e.operands
            if _const(b) is not None:
                return a
            if _const(a) is not None:
                return b
        if isinstance(e, BinaryOp) and e.op == "Shl" and _const(e.operands[1]) is not None:
            return e.operands[0]
        return e if isinstance(e, (VirtualVariable, Const)) else None

    def _rw_makeslicecopy(self, call: Call, args: list) -> Expression | None:
        """``makeslicecopy(T, tolen, fromlen, from)`` with equal lengths -> ``append([]T{}, from...)``."""
        if len(args) != 4 or not self.values.same(args[1], args[2]):
            return None
        ty = self.type_name(args[0])
        name = f"[]{ty}" if ty else "[]byte"
        src = self._slice_from_pair(args[3], args[2], name)
        if src is None:
            return None
        empty = Struct(self.manager.next_atom(), name, OrderedDict(), OrderedDict(), _SLICE_BITS, **args[3].tags)
        # the compiler keeps the pointer word; the length words are the ones it passed
        return self.builtin(call, "append", [empty, src], go_ellipsis=True, go_result_type="unsafe.Pointer")

    def _rw_typedslicecopy(self, call: Call, args: list) -> Expression | None:
        if len(args) != 5:
            return None
        ty = self.type_name(args[0])
        name = f"[]{ty}" if ty else "[]byte"
        dst = self._slice_from_pair(args[1], args[2], name)
        src = self._slice_from_pair(args[3], args[4], name)
        if dst is None or src is None:
            return None
        return self.builtin(call, "copy", [dst, src], bits=self.project.arch.bits, go_result_type="int")

    def _rw_ifaceeq(self, call: Call, args: list) -> Expression | None:
        """``ifaceeq(x.tab, x.data, y.data)`` (the tabs compared equal by the caller) -> ``x == y``."""
        size = _STRING_BITS // 8
        if len(args) == 2 and args[0].bits == _STRING_BITS:
            x = args[0]
        elif len(args) == 3:
            x = self.values.whole(size, (args[0], 0), (args[1], self.project.arch.bytes))
        else:
            return None
        y_base = self.values.base_of(args[-1], self.project.arch.bytes)
        y = y_base.value(self.manager, self.project.arch, size, args[-1].tags) if y_base is not None else None
        if x is None or y is None:
            return None
        return self.compare("CmpEQ", x, y, call.bits, call.tags)

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
        dst = self.values.base_of(args[0], _PTR)
        src = self.values.base_of(args[1], _PTR)
        if dst is None or src is None:
            return None
        count = args[2]
        if isinstance(count, BinaryOp) and count.op == "Mul" and isinstance(count.operands[1], Const):
            count = count.operands[0]
        if not self._is_min_len(count, dst, src):
            return None
        arch = self.project.arch
        dst_val = dst.value(self.manager, arch, _SLICE_BITS // 8, args[0].tags)
        src_val = src.value(self.manager, arch, None if src.combo else _SLICE_BITS // 8, args[1].tags)
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
        lhs, rhs = expr.operands
        if expr.op == "Xor" and _const(rhs) == 1:
            # !(a == b) as the compiler spells it
            inner = _strip_converts(lhs)
            if isinstance(inner, BinaryOp) and inner.op in ("CmpEQ", "CmpNE") and inner.bits == 1:
                return self.compare(_NEGATED[inner.op], inner.operands[0], inner.operands[1], expr.bits, expr.tags)
            return None
        # cmpstring(a, b) <op> 0  ->  a <op> b
        if expr.op not in _COMPARISONS:
            return None
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
        # len(a) == len(b) ? a == b : false  ->  a == b   (also the tab words of two interface values)
        cond = _strip_converts(expr.cond)
        eq = _strip_converts(expr.iftrue)
        iffalse = _strip_converts(expr.iffalse)
        if not (isinstance(cond, BinaryOp) and cond.op == "CmpEQ"):
            return None
        if not (_const(iffalse) == 0 or iffalse.likes(cond)):
            return None
        if isinstance(eq, Call) and self.callee_name(eq) == "runtime.memequal":
            eq = self._loose_memequal(cond, eq)
            return self.to_bits(eq, expr.bits) if eq is not None else None
        if not (isinstance(eq, BinaryOp) and eq.op == "CmpEQ"):
            return None
        a, b = eq.operands
        if a.bits != _STRING_BITS or b.bits != _STRING_BITS:
            return None
        if not (
            all(self._is_len_check(operand, a, b) for operand in cond.operands)
            or self._is_tab_check(cond.operands, a, b)
        ):
            return None
        return self.to_bits(eq, expr.bits)

    def _is_tab_check(self, operands, a: Expression, b: Expression) -> bool:
        """The compared words are the type words of the two interface values ``a`` and ``b``."""
        bases = [self.values.base_of_value(v) for v in (a, b)]
        if any(base is None for base in bases):
            return False
        for x, y in ((operands[0], operands[1]), (operands[1], operands[0])):
            if self.values.piece(x, bases[0]) == 0 and self.values.piece(y, bases[1]) == 0:
                return True
        return False

    def _loose_memequal(self, cond: BinaryOp, call: Call) -> Expression | None:
        """``la == lb ? memequal(pa, pb, la) : 0`` with untracked words -> ``string{pa, la} == string{pb, lb}``."""
        args = list(call.args or [])
        if len(args) != 3:
            return None
        pa, pb, n = args
        la, lb = cond.operands
        if not (self.values.same(n, la) or self.values.same(n, lb)):
            return None
        a = self.values.string(pa, la) or self._struct_of("string", [(0, pa), (self.project.arch.bytes, la)])
        b = self.values.string(pb, lb) or self._struct_of("string", [(0, pb), (self.project.arch.bytes, lb)])
        return self.compare("CmpEQ", a, b, call.bits, call.tags)

    def _is_len_check(self, operand: Expression, a: Expression, b: Expression) -> bool:
        for value in (a, b):
            if isinstance(value, StringLiteral):
                if _const(operand) == len(value.data.encode("utf-8")):
                    return True
                continue
            base = self.values.base_of_value(value)
            if base is not None and self.values.is_len_of(operand, base):
                return True
        return False

    def rewrite_struct(self, expr: Struct) -> Expression | None:
        fields = [expr.fields[off] for off in sorted(expr.fields)]
        if not fields:
            return None
        # the pieces of one combo-register value, in order: the value itself
        first = self.values.base_of(fields[0], 0)
        if first is not None and first.combo is not None:
            combo = first.combo
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
            base = self.values.base_of(cap.operands[0], _CAP)
            low = cap.operands[1]
        else:
            base = self.values.base_of(cap, _CAP)
        if base is None:
            return None
        if low is None:
            # s[:j]
            if self.values.piece(ptr, base) != _PTR or self.values.is_len_of(length, base):
                return None
            high = length
        else:
            if not (isinstance(ptr, BinaryOp) and ptr.op == "Add"):
                return None
            p, advance = ptr.operands
            if self.values.piece(p, base) != _PTR:
                if self.values.piece(advance, base) != _PTR:
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
            growth = self._match_growslice(block)
            if growth is not None:
                touched += self._apply_append(growth)
        return touched

    def _match_growslice(self, block: Block) -> _Growth | None:
        call_stmt = None
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                if call_stmt is not None or self.callee_name(stmt.src) not in _GROWSLICE_NAMES:
                    return None
                call_stmt = stmt
            elif isinstance(stmt, (Assignment, Store)):
                # copies, stores and values re-read after the call (registers the call clobbered)
                if find_call(stmt) is not None:
                    return None
            elif not isinstance(stmt, (Label, Jump)):
                return None
        if call_stmt is None or not isinstance(call_stmt.dst, VirtualVariable) or not call_stmt.dst.reg_vvars:
            return None
        args = list(call_stmt.src.args or [])
        if len(args) not in (5, 7):
            return None
        old_ptr, new_len, old_cap, num, et = args[:5]
        count = _const(num)
        if count is not None and count <= 0:
            return None
        old_len = self._old_length(new_len, old_cap, num, count)
        if old_len is None:
            return None
        ty = self.type_name(et)
        base = self.values.header(old_ptr, old_cap, old_len, f"[]{ty}" if ty else None)
        if base is None or (base.words is None and not self.values.is_len_of(old_len, base)):
            base = self.values.header(old_ptr, old_cap, old_len, None) if base is None else None
            if base is None or base.words is None:
                return None
        ws = self.project.arch.bytes
        g = _Growth(block, call_stmt, base, count, num, et, old_len, new_len, self.type_size(et) or ws)
        g.ptrs = [call_stmt.dst.reg_vvars[0]]
        g.len_new = [call_stmt.dst.reg_vvars[1], self.values.resolve(new_len)]
        g.len_old = [self.values.resolve(old_len)]
        self._match_diamond(g, base, old_cap, new_len)
        if g.join is not None:
            g.phis = self._phis(g.join)
            gone = {(pre_join.addr, pre_join.idx) for _, _, pre_join in g.arms}
            for dst, phi in g.phis.values():
                survivors = [v for src, v in phi.src_and_vvars if src not in gone and v is not None]
                if survivors and all(v.varid == survivors[0].varid for v in survivors[1:]):
                    self.values.aliases[dst.varid] = survivors[0]
            for dst, phi in g.phis.values():
                entries = dict(phi.src_and_vvars)
                grown_side = entries.get((g.post_grow.addr, g.post_grow.idx))
                old_side = entries.get((g.arms[-1][2].addr, g.arms[-1][2].idx))
                if grown_side is None or old_side is None:
                    continue
                grown_side = self.values.resolve(grown_side)
                grown_hit = (
                    self.values.combo_of.get(grown_side.varid) if isinstance(grown_side, VirtualVariable) else None
                )
                if grown_hit is None or grown_hit[0].varid != call_stmt.dst.varid:
                    if self._is_alias(grown_side, g.len_old) and self._is_alias(old_side, g.len_old):
                        g.len_old.append(dst)
                    continue
                old_piece = self.values.piece(old_side, base)
                if grown_hit[1] == _PTR and old_piece == _PTR:
                    g.ptrs.append(dst)
                elif grown_hit[1] == _LEN and self.values.same(old_side, new_len):
                    g.len_new.append(dst)
        self._match_elements(g)
        if g.elems is None and g.src is None:
            # nothing folded: the phis stay
            for dst, _ in g.phis.values():
                self.values.aliases.pop(dst.varid, None)
        return g

    def _old_length(self, new_len, old_cap, num, count: int | None) -> Expression | None:
        """The old length word: ``new_len`` is ``old_len + num``."""
        grown = self.values.expand(new_len)
        if isinstance(grown, BinaryOp) and grown.op == "Add":
            x, y = grown.operands
            for a, b in ((x, y), (y, x)):
                if (count is not None and _const(b) == count) or (count is None and self.values.same(b, num)):
                    return a
        bits = self.project.arch.bits
        n = _const(new_len)
        if count is not None and n is not None and n >= count:
            return Const(self.manager.next_atom(), n - count, bits)
        if self.values.same(new_len, num):
            return Const(self.manager.next_atom(), 0, bits)
        return BinaryOp(self.manager.next_atom(), "Sub", [new_len, num], False, bits=bits, **new_len.tags)

    def _match_diamond(self, g: _Growth, base: _Base, old_cap, new_len) -> None:
        """
        ``if newLen > cap { growslice }`` around the call block; the join is where both paths meet. go1.25+ nests
        further choices under the check (a small result lives in a stack buffer); every arm joins the same block.
        """
        # the grow path: the call block and its copy-only successors up to the join
        chain = self._copy_chain(g.block)
        if chain is None:
            return
        join, post_grow = chain
        # the conditions above the call block, up to the capacity check; their other arms all reach the join
        region = {g.block}
        entry = None
        arms: list[tuple[Block, Block, Block]] = []
        changed = True
        while changed and entry is None and len(region) < 8:
            changed = False
            preds = {p for b in region for p in self._graph.predecessors(b) if p not in region and p is not join}
            for pred in sorted(preds, key=lambda b: (b.addr, b.idx or 0), reverse=True):
                if is_jump_only(pred):
                    region.add(pred)
                    changed = True
                    continue
                if not (pred.statements and isinstance(pred.statements[-1], ConditionalJump)):
                    continue
                pred_succs = list(self._graph.successors(pred))
                if len(pred_succs) != 2:
                    continue
                new_arms = []
                for succ in pred_succs:
                    if succ in region:
                        continue
                    if succ in preds:
                        # an inner condition: it joins the region first
                        new_arms = None
                        break
                    pre_join = pred if succ is join else self._arm_end(succ, join)
                    if pre_join is None:
                        new_arms = None
                        break
                    new_arms.append((pred, succ, pre_join))
                if new_arms is None:
                    continue
                region.add(pred)
                arms += new_arms
                changed = True
                if self._is_grow_check(pred.statements[-1].condition, base, old_cap, new_len):
                    entry = pred
                    break
        if entry is None or not arms:
            return
        for block in region:
            if block is not entry and any(p not in region for p in self._graph.predecessors(block)):
                return
        g.cond_block, g.join, g.post_grow, g.arms = entry, join, post_grow, arms

    def _copy_chain(self, block: Block) -> tuple[Block, Block] | None:
        """(join, last block before it): ``block`` and its copy-only successors up to a block with several preds."""
        chain = [block]
        while True:
            succs = list(self._graph.successors(chain[-1]))
            if len(succs) != 1 or succs[0] in chain:
                return None
            if self._graph.in_degree(succs[0]) > 1:
                return succs[0], chain[-1]
            if not self._copies_only(succs[0]):
                return None
            chain.append(succs[0])

    def _arm_end(self, arm: Block, join: Block) -> Block | None:
        """The last block of a path that skips the growth: copy-only blocks straight to the join."""
        if arm is join:
            return None
        cur = arm
        seen = set()
        while cur not in seen:
            seen.add(cur)
            if self._graph.in_degree(cur) != 1 or not self._copies_only(cur):
                return None
            succs = list(self._graph.successors(cur))
            if len(succs) != 1:
                return None
            if succs[0] is join:
                return cur
            cur = succs[0]
        return None

    @staticmethod
    def _copies_only(block: Block) -> bool:
        return all(
            isinstance(st, (Label, Jump, Store)) or (isinstance(st, Assignment) and find_call(st.src) is None)
            for st in block.statements
        ) and not any(find_call(st) is not None for st in block.statements)

    def _is_grow_check(self, cond, base: _Base, old_cap, new_len) -> bool:
        if not isinstance(cond, BinaryOp) or cond.op not in ("CmpLT", "CmpLE", "CmpGT", "CmpGE", "CmpEQ", "CmpNE"):
            return False
        a, b = cond.operands
        if cond.op in ("CmpEQ", "CmpNE"):
            # a nil slice grows unless the new length is zero
            return _const(old_cap) == 0 and (
                (_const(b) == 0 and self.values.same(a, new_len)) or (_const(a) == 0 and self.values.same(b, new_len))
            )

        def is_cap(x):
            return self.values.piece(x, base) == _CAP or self.values.same(x, old_cap)

        return (is_cap(a) and self.values.same(b, new_len)) or (is_cap(b) and self.values.same(a, new_len))

    #
    # The appended elements: stores past the old end, or a copy of a whole slice
    #

    def _is_alias(self, expr, aliases: list) -> bool:
        resolved = self.values.resolve(expr)
        return any(resolved.likes(a) for a in aliases)

    def _after_barrier(self, block: Block) -> Block | None:
        """
        ``if runtime.writeBarrier.enabled { gcWriteBarrier(); buf fills }`` ends ``block``: the block where both arms
        meet again (the pointer store the barrier guards sits there), or None when ``block`` ends otherwise.
        """
        if not (block.statements and isinstance(block.statements[-1], ConditionalJump)):
            return None
        cond = _strip_converts(block.statements[-1].condition)
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None
        flag = next((o for o in cond.operands if isinstance(o, Load) and isinstance(o.addr, Const)), None)
        if flag is None:
            return None
        sym = self.project.loader.find_symbol(flag.addr.value_int)
        named = sym is not None and sym.name == "runtime.writeBarrier"
        succs = list(self._graph.successors(block))
        if len(succs) != 2:
            return None
        if skip_jumps(self._graph, succs[0]) is skip_jumps(self._graph, succs[1]):
            # the barrier arm is already gone; both arms fall through to the store
            return skip_jumps(self._graph, succs[0])
        for fast, slow in ((succs[0], succs[1]), (succs[1], succs[0])):
            join = skip_jumps(self._graph, fast)
            cur = slow
            seen = set()
            barrier = named
            while cur is not join and cur not in seen and len(seen) < 4:
                seen.add(cur)
                names = [self.callee_name(c) or "" for c in (find_call(st) for st in cur.statements) if c is not None]
                barrier = barrier or any(n.startswith(("runtime.gcWriteBarrier", "runtime.wbBufFlush")) for n in names)
                nxt = list(self._graph.successors(cur))
                if len(nxt) != 1:
                    break
                cur = nxt[0]
            if cur is join and barrier:
                return join
        return None

    def _window(self, g: _Growth) -> list[Statement]:
        """
        Statements that may hold the element stores: the rest of the call block and its straight-line successors up
        to the join, then the join and its straight-line successors. Stops at (and includes) the first other call.
        """
        stmts = list(g.block.statements)
        pos = next((i for i, st in enumerate(stmts) if st is g.call_stmt), len(stmts))
        out: list[Statement] = stmts[pos + 1 :]
        block = g.block
        seen = {block}
        while True:
            succs = list(self._graph.successors(block))
            join = self._after_barrier(block) if len(succs) == 2 else None
            if join is not None:
                block = join
            elif len(succs) != 1 or succs[0] in seen:
                return out
            else:
                block = succs[0]
            if block in seen:
                return out
            seen.add(block)
            if block is g.join:
                out += list(block.statements)
            elif self._graph.in_degree(block) != 1 and join is None:
                return out
            else:
                for stmt in block.statements:
                    out.append(stmt)
                    if find_call(stmt) is not None:
                        return out

    def _match_elements(self, g: _Growth) -> None:
        window = self._window(g)
        found: dict[int, dict[int, tuple[Store, Expression]]] = {}  # element k -> byte offset -> store
        for stmt in window:
            if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                if self._match_copy(g, stmt):
                    return
                continue
            if not isinstance(stmt, Store) or g.count is None:
                continue
            parsed = self._store_offset(stmt.addr, g)
            if parsed is None:
                continue
            hit = self._element_of(*parsed, g)
            if hit is None:
                continue
            k, at = hit
            if k == g.count and at == 0 and stmt.size == g.width * g.count and g.count > 1:
                # one wide store of every appended element: append(s, src...)
                src = self._wide_source(g, stmt.data)
                if src is not None:
                    g.src, g.stores = src, [stmt]
                    return
                continue
            if 1 <= k <= g.count and at + stmt.size <= g.width and at not in found.setdefault(k, {}):
                found[k][at] = (stmt, stmt.data)
        if g.count is None or len(found) != g.count:
            return
        elems = []
        elem_name = self.type_name(g.et) or ""
        for k in range(g.count, 0, -1):
            pieces = sorted((at, stmt.size, data) for at, (stmt, data) in found[k].items())
            if not self._covers(pieces, g.width, elem_name):
                return
            values = self._elements(g, [data for _, _, data in pieces])
            if values is None:
                return
            elems.append(self._element_value(g, [(at, v) for (at, _, _), v in zip(pieces, values)]))
        g.elems = elems
        g.stores = list({id(st): st for k in found for st, _ in found[k].values()}.values())

    def _covers(self, pieces: list, size: int, name: str) -> bool:
        """The (offset, size, ...) pieces fill ``size`` bytes, or every field of the struct ``name`` (padding aside)."""
        if self._covering(pieces, size):
            return True
        ty = None
        with contextlib.suppress(Exception):
            ty = self.kb.go_signatures.type(name).with_arch(self.project.arch) if name else None
        offsets = getattr(ty, "offsets", None)
        fields = getattr(ty, "fields", None)
        if not offsets or not fields:
            return False
        covered = bytearray(size)
        for at, piece_size, *_ in pieces:
            if at < 0 or at + piece_size > size or any(covered[at : at + piece_size]):
                return False
            covered[at : at + piece_size] = b"\x01" * piece_size
        for field, off in offsets.items():
            fsize = self._type_size_bytes(fields[field]) or 0
            if not all(covered[off : off + fsize]):
                return False
        return True

    @staticmethod
    def _covering(pieces: list, width: int) -> list:
        """The (offset, size) list that would cover ``width`` bytes without gaps or overlaps."""
        out = []
        pos = 0
        for at, size, _ in pieces:
            if at != pos:
                return []
            out.append((at, size))
            pos += size
        return out if pos == width else []

    def _fields_of(self, ty, pieces: list[tuple[int, Expression]]):
        """Group ``pieces`` by the struct field they fall in; a multi-piece field becomes a literal of its type."""
        out = []
        names = {}
        used = 0
        for field, off in ty.offsets.items():
            fty = ty.fields[field]
            size = self._type_size_bytes(fty)
            if not size:
                continue
            sub = [(at - off, v) for at, v in pieces if off <= at < off + size]
            if not sub:
                continue
            used += len(sub)
            if len(sub) == 1 and sub[0][0] == 0 and sub[0][1].bits == size * 8:
                value = sub[0][1]
            elif self._covering([(at, v.bits // 8, v) for at, v in sub], size):
                value = self._map_value(fty.go_repr() if hasattr(fty, "go_repr") else "", size, sub)
            else:
                return None
            out.append((off, value))
            names[off] = field
        return (out, names) if used == len(pieces) else None

    def _element_value(self, g: _Growth, pieces: list[tuple[int, Expression]]) -> Expression:
        """The stored pieces (byte offset, value) of one element as a value of the element type."""
        if len(pieces) == 1:
            return pieces[0][1]
        elem_name = self.type_name(g.et) or ""
        ws = self.project.arch.bytes
        if (elem_name == "string" or elem_name.startswith("[]")) and all(at % ws == 0 for at, _ in pieces):
            value = self.values.whole(g.width, *pieces)
            if value is None and elem_name == "string" and len(pieces) == 2:
                value = self.values.literal(pieces[0][1], pieces[1][1])
            if value is not None:
                return value
        return self._struct_of(elem_name, pieces)

    def _struct_of(self, name: str, pieces: list[tuple[int, Expression]]) -> Struct:
        """A value spelled as a literal of its type, field by field (fields named by their offsets)."""
        names = None
        if name == "string" or name.startswith("[]"):
            names = {0: "ptr", self.project.arch.bytes: "len", 2 * self.project.arch.bytes: "cap"}
        else:
            ty = None
            with contextlib.suppress(Exception):
                ty = self.kb.go_signatures.type(name).with_arch(self.project.arch)
            offsets = getattr(ty, "offsets", None)
            if offsets:
                nested = self._fields_of(ty, pieces)
                if nested is not None:
                    pieces, names = nested
                else:
                    names = {off: field for field, off in offsets.items()}
        if names is None or any(at not in names for at, _ in pieces):
            names = {at: f"f{at}" for at, _ in pieces}
        bits = 0
        for at, value in pieces:
            bits = max(bits, at * 8 + value.bits)
        return Struct(
            self.manager.next_atom(),
            name or "struct",
            OrderedDict((at, value) for at, value in pieces),
            OrderedDict((names[at], at) for at, _ in pieces),
            bits,
            **pieces[0][1].tags,
        )

    def _match_copy(self, g: _Growth, stmt: SideEffectStatement) -> bool:
        """``memmove(end, src, n*w)`` / ``typedslicecopy(T, end, n, src, n)`` after the growth: ``append(s, src...)``."""
        call = stmt.expr
        name = self.callee_name(call)
        args = list(call.args or [])
        if name == "runtime.memmove" and len(args) == 3:
            dst, src, n = args
            if not self._is_count_bytes(n, g):
                return False
        elif name == "runtime.typedslicecopy" and len(args) == 5:
            _, dst, _, src, n = args
            if not self._is_num(n, g):
                return False
        else:
            return False
        if not self._is_end(dst, g):
            return False
        value = self.values.slice(src, g.num)
        if value is None:
            value = self._slice_literal(g, src, g.num)
        g.src, g.stores = value, [stmt]
        return True

    def _slice_literal(self, g: _Growth, ptr: Expression, length: Expression) -> Expression:
        return self._struct_of(g.base.name or "[]byte", [(0, ptr), (self.project.arch.bytes, length)])

    def _wide_source(self, g: _Growth, data: Expression) -> Expression | None:
        data = self.values.expand(data)
        if isinstance(data, Load):
            count = Const(self.manager.next_atom(), g.count, self.project.arch.bits)
            return Call(
                self.manager.next_atom(), "[:]", [data.addr, count], bits=_SLICE_BITS, go_slice="[:j]", **data.tags
            )
        return None

    def _is_num(self, expr, g: _Growth) -> bool:
        return self.values.same(expr, g.num) or (g.count is not None and _const(expr) == g.count)

    def _is_count_bytes(self, expr, g: _Growth) -> bool:
        if g.width == 1 and self._is_num(expr, g):
            return True
        if g.count is not None and _const(expr) == g.count * g.width:
            return True
        e = self.values.expand(expr)
        if isinstance(e, BinaryOp) and e.op == "Mul" and _const(e.operands[1]) == g.width:
            return self._is_num(e.operands[0], g)
        if isinstance(e, BinaryOp) and e.op == "Shl" and (1 << (_const(e.operands[1]) or 0)) == g.width:
            return self._is_num(e.operands[0], g)
        return False

    def _is_end(self, addr, g: _Growth) -> bool:
        """``ptr + oldLen*w``: where the appended elements start."""
        parsed = self._store_offset(addr, g)
        if parsed is None:
            return False
        kind, off = parsed
        if kind == "old":
            return off == 0
        if kind == "new":
            return g.count is not None and off == -g.count * g.width
        old = _const(g.old_len)
        return old is not None and off == old * g.width

    def _element_of(self, kind: str, off: int, g: _Growth) -> tuple[int, int] | None:
        """(k, byte offset) of the store at byte ``off`` past ``ptr + len*w``: element k counted back from the end."""
        w = g.width
        if kind == "old":
            off -= g.count * w
        elif kind == "abs":
            n = _const(g.new_len)
            if n is None:
                return None
            off -= n * w
        if off >= 0:
            return None
        k = (-off + w - 1) // w
        return k, off + k * w

    def _terms(self, expr, g: _Growth, sign: int = 1) -> list[tuple[int, Expression]]:
        if self._is_alias(expr, g.ptrs) or self._is_alias(expr, g.len_new) or self._is_alias(expr, g.len_old):
            return [(sign, expr)]
        e = self.values.expand(expr) if isinstance(expr, VirtualVariable) else expr
        if isinstance(e, BinaryOp) and e.op == "Add":
            return self._terms(e.operands[0], g, sign) + self._terms(e.operands[1], g, sign)
        if isinstance(e, BinaryOp) and e.op == "Sub":
            return self._terms(e.operands[0], g, sign) + self._terms(e.operands[1], g, -sign)
        return [(sign, expr)]

    def _store_offset(self, addr, g: _Growth) -> tuple[str, int] | None:
        """
        Decompose a store address into the pointer word plus an offset: ("new", c) for ``ptr + newLen*w + c``,
        ("old", c) for ``ptr + oldLen*w + c`` and ("abs", c) for ``ptr + c``.
        """
        terms = self._terms(addr, g)
        rest = []
        found_ptr = False
        for sign, term in terms:
            if sign > 0 and not found_ptr and self._is_alias(term, g.ptrs):
                found_ptr = True
                continue
            rest.append((sign, term))
        if not found_ptr:
            return None
        bits = self.project.arch.bits
        const = 0
        var = None
        for sign, term in rest:
            c = _const(term)
            if c is not None:
                c = c - (1 << bits) if c >= 1 << (bits - 1) else c
                const += sign * c
            elif var is None and sign > 0:
                var = term
            else:
                return None
        if var is not None and _const(self._strip_guard(var, g)) is not None:
            const += _const(self._strip_guard(var, g))
            var = None
        if var is None:
            return "abs", const
        var = self._strip_guard(var, g)
        factor, inner = self._scale(var, g)
        if factor != g.width:
            return None
        inner = self._strip_guard(inner, g)
        if self._is_alias(inner, g.len_new):
            return "new", const
        if self._is_alias(inner, g.len_old):
            return "old", const
        e = self._expand_non_alias(inner, g)
        if isinstance(e, BinaryOp) and e.op in ("Add", "Sub") and _const(e.operands[1]) is not None:
            delta = _const(e.operands[1]) * (1 if e.op == "Add" else -1)
            if self._is_alias(e.operands[0], g.len_new):
                return "new", delta * g.width + const
            if self._is_alias(e.operands[0], g.len_old):
                return "old", delta * g.width + const
        return None

    def _scale(self, expr, g: _Growth) -> tuple[int, Expression]:
        """``(x * a) * b`` / ``x << s`` -> (a*b, x)."""
        factor = 1
        while True:
            e = self._expand_non_alias(expr, g)
            if isinstance(e, BinaryOp) and e.op == "Mul" and _const(e.operands[1]) is not None:
                factor, expr = factor * _const(e.operands[1]), e.operands[0]
            elif isinstance(e, BinaryOp) and e.op == "Mul" and _const(e.operands[0]) is not None:
                factor, expr = factor * _const(e.operands[0]), e.operands[1]
            elif isinstance(e, BinaryOp) and e.op == "Shl" and _const(e.operands[1]) is not None:
                factor, expr = factor << _const(e.operands[1]), e.operands[0]
            else:
                return factor, expr

    def _expand_non_alias(self, expr, g: _Growth) -> Expression:
        if self._is_alias(expr, g.ptrs) or self._is_alias(expr, g.len_new) or self._is_alias(expr, g.len_old):
            return expr
        return self.values.expand(expr)

    def _strip_guard(self, expr, g: _Growth) -> Expression:
        """``x & ((a - b) >> 63)`` (the mask that keeps an empty result inside the array) -> ``x``."""
        e = self._expand_non_alias(expr, g)
        if isinstance(e, BinaryOp) and e.op == "And":
            a, b = e.operands
            for x, y in ((a, b), (b, a)):
                if _has_node(self._expand_non_alias(y, g), lambda n: isinstance(n, BinaryOp) and n.op == "Sar"):
                    return x
        return expr

    def _elements(self, g: _Growth, data: list) -> list | None:
        """The stored values as seen on the grow path; None when one is computed in the join block itself."""
        defined_in_join = (
            {
                stmt.dst.varid
                for stmt in g.join.statements
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
            }
            if g.join is not None
            else set()
        )
        grow_side: dict[int, Expression] = {}
        for varid, (_, phi) in g.phis.items():
            value = dict(phi.src_and_vvars).get((g.post_grow.addr, g.post_grow.idx))
            if value is not None:
                grow_side[varid] = self.values.resolve(value)
        elems = []
        for value in data:
            value = self.values.resolve(value)
            if isinstance(value, VirtualVariable):
                value = grow_side.get(value.varid, value)
            elif not isinstance(value, (Const, StringLiteral, Struct)):
                # computed at the store: fine when its variables are known on the grow path
                counter = _VVarCounter()
                counter.walk_expression(value)
                subst = {v: grow_side[v] for v in counter.counts if v in grow_side}
                if any(v in defined_in_join and v not in subst for v in counter.counts):
                    return None
                if subst:
                    value = _VVarSubstituter(subst).walk_expression(value)
            if isinstance(value, VirtualVariable) and value.varid in defined_in_join:
                return None
            elems.append(value)
        return elems

    @staticmethod
    def _phis(block: Block) -> dict[int, tuple[VirtualVariable, Phi]]:
        phis = {}
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and isinstance(stmt.dst, VirtualVariable):
                phis[stmt.dst.varid] = (stmt.dst, stmt.src)
        return phis

    def _apply_append(self, g: _Growth) -> list[Block]:
        call = g.call_stmt.src
        s = g.base.value(self.manager, self.project.arch, _SLICE_BITS // 8, call.tags)
        if s is None:
            return []
        s = self._array_slice(g, s)
        ty = self.type_name(g.et)
        extra = {"go_result_type": f"[]{ty}"} if ty else {}
        if g.src is not None:
            args = [s, g.src]
            extra["go_ellipsis"] = True
        elif g.elems is not None:
            args = [s, *g.elems]
        else:
            args = [s]
            num = g.count if g.count is not None else "n"
            extra["go_comment"] = f"{num} element(s) not recovered"
        new_call = self.builtin(call, "append", args, bits=_SLICE_BITS, **extra)
        g.block.statements = [
            Assignment(stmt.idx, stmt.dst, new_call, **stmt.tags) if stmt is g.call_stmt else stmt
            for stmt in g.block.statements
        ]
        touched = [g.block]
        store_ids = {id(st) for st in g.stores}
        for other_block in list(self._graph.nodes):
            if any(id(st) in store_ids for st in other_block.statements):
                other_block.statements = [st for st in other_block.statements if id(st) not in store_ids]
                touched.append(other_block)
        if g.join is not None:
            touched += self._collapse_diamond(g)
        if g.base.addr is not None:
            touched += self._fold_header_writeback(g)
        l.debug("Folded growslice at %#x of %s into append", g.block.addr, self._func.name)
        return touched

    def _array_slice(self, g: _Growth, s: Expression) -> Expression:
        """A constant header over an array (``&arr``/``new([N]T)``, len, cap) is the slicing ``arr[:len]``."""
        base = g.base
        if base.words is None or len(base.words) != 3 or not isinstance(s, Struct) or not s.fields:
            return s
        ptr, length, cap = base.words
        n, c = _const(length), _const(cap)
        if c == 0:
            return Struct(self.manager.next_atom(), s.name, OrderedDict(), OrderedDict(), s.bits, **s.tags)
        if _const(ptr) is not None or n is None or c is None:
            return s
        array = ptr.operand if isinstance(ptr, UnaryOp) and ptr.op == "Reference" else ptr
        high = Const(self.manager.next_atom(), n, self.project.arch.bits)
        return Call(self.manager.next_atom(), "[:]", [array, high], bits=_SLICE_BITS, go_slice="[:j]", **s.tags)

    def _collapse_diamond(self, g: _Growth) -> list[Block]:
        """The grow path is now the only path: append itself decides whether to grow."""
        gone = set()
        for cond, other, pre_join in g.arms:
            self.remove_jump_target(cond, other.addr, other.idx)
            gone.add((pre_join.addr, pre_join.idx))
            dead = other
            while dead is not g.join and dead in self._graph and self._graph.in_degree(dead) == 0:
                succs = list(self._graph.successors(dead))
                self._graph.remove_node(dead)
                self._block_by_addr_and_idx.pop((dead.addr, dead.idx), None)
                if len(succs) != 1:
                    break
                dead = succs[0]
        # the join no longer merges the paths
        replacements: dict[int, VirtualVariable] = {}
        new_stmts = []
        for stmt in g.join.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and stmt.dst.varid in g.phis:
                entries = [(src, v) for src, v in stmt.src.src_and_vvars if src not in gone]
                values = [v for _, v in entries]
                if values and all(v is not None for v in values) and all(v.varid == values[0].varid for v in values):
                    replacements[stmt.dst.varid] = self.values.resolve(values[0])
                    continue
                if len(entries) != len(stmt.src.src_and_vvars):
                    phi = Phi(stmt.src.idx, stmt.src.bits, entries, **stmt.src.tags)
                    stmt = Assignment(stmt.idx, stmt.dst, phi, **stmt.tags)
            new_stmts.append(stmt)
        g.join.statements = new_stmts
        if replacements:
            subst = _VVarSubstituter(replacements)
            for blk in self._graph.nodes:
                subst.walk(blk)
        return [cond for cond, _, _ in g.arms] + [g.join]

    def _fold_header_writeback(self, g: _Growth) -> list[Block]:
        """``p.s.ptr = t.array; p.s.cap = t.cap; p.s.len = t.len`` after the growth -> ``p.s = t``."""
        ws = self.project.arch.bytes
        result = g.call_stmt.dst
        pieces = {i * ws: rv.varid for i, rv in enumerate(result.reg_vvars)}
        found: dict[int, tuple[Block, Store]] = {}
        for block in self._chain(g):
            for stmt in block.statements:
                if not isinstance(stmt, Store) or stmt.size != ws:
                    continue
                addr_base, off = _addr_and_offset(stmt.addr)
                if addr_base is None or not self.values.resolve(addr_base).likes(g.base.addr):
                    continue
                k = off - g.base.off
                data = self.values.resolve(stmt.data)
                if k in pieces and isinstance(data, VirtualVariable) and data.varid == pieces[k] and k not in found:
                    found[k] = (block, stmt)
        if len(found) != len(pieces):
            return []
        _, last = list(found.values())[-1]
        wide = Store(
            last.idx,
            g.base.address(self.manager, self.project.arch),
            result,
            len(pieces) * ws,
            self.project.arch.memory_endness,
            **last.tags,
        )
        dropped = {id(st) for _, st in found.values()}
        touched = []
        for block, _ in found.values():
            block.statements = [
                wide if st is last else st for st in block.statements if st is last or id(st) not in dropped
            ]
            touched.append(block)
        return touched

    def _chain(self, g: _Growth) -> list[Block]:
        """The call block, its straight-line successors up to the join, the join and its straight-line successors."""
        out = [g.block]
        block = g.block
        seen = {block}
        while True:
            succs = list(self._graph.successors(block))
            join = self._after_barrier(block) if len(succs) == 2 else None
            if join is not None:
                block = join
            elif len(succs) != 1 or (succs[0] is not g.join and self._graph.in_degree(succs[0]) != 1):
                return out
            else:
                block = succs[0]
            if block in seen:
                return out
            seen.add(block)
            out.append(block)
            if any(find_call(st) is not None for st in block.statements):
                return out

    #
    # moveSliceNoCap: a slice backed by a stack buffer is copied to the heap when it escapes; the reader sees
    # the same slice, so the `if ptr - &buf < N { copy }` diamond goes
    #

    def _fold_move_slice(self) -> list[Block]:
        touched: list[Block] = []
        for block in list(self._graph.nodes):
            if block not in self._graph:
                continue
            calls = [st for st in block.statements if find_call(st) is not None]
            if len(calls) != 1:
                continue
            call = calls[0].src if isinstance(calls[0], Assignment) else getattr(calls[0], "expr", None)
            if not isinstance(call, Call) or (
                isinstance(calls[0], SideEffectStatement) and calls[0].ret_expr is not None
            ):
                continue
            name = self.callee_name(call) or ""
            rest = [st for st in block.statements if st is not calls[0]]
            if not name.startswith("runtime.moveSliceNoCap") or not all(
                isinstance(st, (Label, Jump)) or (isinstance(st, Assignment) and find_call(st.src) is None)
                for st in rest
            ):
                continue
            result = calls[0].dst if isinstance(calls[0], Assignment) else None
            if result is not None and not (isinstance(result, VirtualVariable) and result.reg_vvars):
                continue
            cond_block = conditional_pred(self._graph, block)
            chain = self._copy_chain(block)
            if cond_block is None or chain is None:
                continue
            join, post = chain
            others = [s for s in self._graph.successors(cond_block) if not leads_to(self._graph, s, block)]
            if len(others) != 1 or skip_jumps(self._graph, others[0]) is not join or join is cond_block:
                continue
            pieces = {rv.varid for rv in result.reg_vvars} if result is not None else set()
            phis = self._phis(join)
            ok = True
            for _, phi in phis.values():
                entries = dict(phi.src_and_vvars)
                grown = entries.pop((post.addr, post.idx), None)
                if grown is None:
                    continue
                grown = self.values.resolve(grown)
                # the copy's pieces, or a spill the other arm made as well
                if not (
                    (isinstance(grown, VirtualVariable) and grown.varid in pieces)
                    or all(v is not None and self.values.resolve(v).likes(grown) for v in entries.values())
                ):
                    ok = False
            if not ok:
                continue
            self.remove_jump_target(cond_block, block.addr, block.idx)
            dead = block
            while dead is not join and dead in self._graph and self._graph.in_degree(dead) == 0:
                nxt = list(self._graph.successors(dead))
                self._graph.remove_node(dead)
                self._block_by_addr_and_idx.pop((dead.addr, dead.idx), None)
                if len(nxt) != 1:
                    break
                dead = nxt[0]
            replacements: dict[int, VirtualVariable] = {}
            new_stmts = []
            for stmt in join.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and stmt.dst.varid in phis:
                    entries = [(src, v) for src, v in stmt.src.src_and_vvars if src != (post.addr, post.idx)]
                    values = [v for _, v in entries]
                    if (
                        values
                        and all(v is not None for v in values)
                        and all(v.varid == values[0].varid for v in values)
                    ):
                        replacements[stmt.dst.varid] = self.values.resolve(values[0])
                        continue
                    if len(entries) != len(stmt.src.src_and_vvars):
                        stmt = Assignment(
                            stmt.idx, stmt.dst, Phi(stmt.src.idx, stmt.src.bits, entries, **stmt.src.tags), **stmt.tags
                        )
                new_stmts.append(stmt)
            join.statements = new_stmts
            if replacements:
                subst = _VVarSubstituter(replacements)
                for blk in self._graph.nodes:
                    subst.walk(blk)
            touched += [cond_block, join]
            l.debug("Dropped %s at %#x of %s", name, block.addr, self._func.name)
        return touched

    #
    # Map slots: mapassign/mapaccess results that are written or read through offsets (multi-word values)
    #

    def _fold_map_slots(self) -> list[Block]:
        touched: list[Block] = []
        counts = None
        candidates = [
            (block, stmt)
            for block in list(self._graph.nodes)
            for stmt in list(block.statements)
            if isinstance(stmt, (Assignment, SideEffectStatement)) and find_call(stmt) is not None
        ]
        for block, stmt in candidates:
            call = stmt.src if isinstance(stmt, Assignment) else stmt.expr
            if not isinstance(call, Call) or block not in self._graph or stmt not in block.statements:
                continue
            name = self.callee_name(call) or ""
            if name.startswith(("runtime.mapassign", "runtime.mapaccess")):
                if counts is None:
                    counts = self._use_counts()
                if name.startswith("runtime.mapassign"):
                    done = self._fold_mapassign(block, stmt, call, name, counts)
                elif isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    done = self._fold_mapaccess(block, stmt, call, name, counts)
                else:
                    done = []
                touched += done
        return touched

    def _map_types(self, call: Call):
        """(map type name, key type, elem type) from the descriptor argument, sizes in bytes."""
        args = list(call.args or [])
        addr = _const(args[0]) if args else None
        ty = go_type_at(self.project, addr) if addr is not None else None
        if not isinstance(ty, GoSimTypeMap):
            return None
        arch = self.project.arch
        key, elem = ty.key_type.with_arch(arch), ty.elem_type.with_arch(arch)
        return ty.go_repr(), key, elem

    def _type_size_bytes(self, ty) -> int | None:
        size = getattr(ty, "size", None)
        return size // self.project.arch.byte_width if isinstance(size, int) else None

    def _map_key(self, name: str, call: Call, block: Block, stmt: Statement, key_ty) -> Expression | None:
        """The key of a map call: passed by value (fast variants) or through a pointer to a stack slot."""
        args = list(call.args or [])
        if len(args) < 3:
            return None
        key = args[2]
        if "_fast" in name:
            return key
        size = self._type_size_bytes(key_ty)
        if size is None:
            return None
        return self._key_behind(key, size, key_ty.go_repr() if hasattr(key_ty, "go_repr") else "", block, stmt)

    def _key_behind(self, key: Expression, size: int, key_name: str, block: Block, stmt: Statement) -> Expression:
        """The value a pointer argument points at: a whole stack-resident value, its pieces, or a load."""
        slot = key.operand if isinstance(key, UnaryOp) and key.op == "Reference" else None
        if isinstance(slot, VirtualVariable):
            # the spilled home of a register-passed value: the value itself
            hit = self.values.combo_of.get(slot.varid)
            if hit is not None and hit[1] == 0 and hit[0].size == size:
                return hit[0]
            if slot.size == size and (slot.category == VVC.PARAMETER or slot.was_reg):
                return slot
        if isinstance(slot, VirtualVariable) and (slot.was_stack or slot.category == VVC.PARAMETER):
            if slot.was_stack:
                pieces = self._stack_pieces(block, stmt, slot.stack_offset, size, key_name)
                if pieces is not None:
                    if len(pieces) == 1:
                        return pieces[0][1]
                    return self._map_value(key_name, size, pieces)
            if slot.size == size:
                return slot
        return Load(self.manager.next_atom(), key, size, self.project.arch.memory_endness, **key.tags)

    def _stack_pieces(self, block: Block, stmt: Statement, base: int, size: int, name: str = "") -> list | None:
        """The stack stores covering ``size`` bytes at stack offset ``base`` that reach ``stmt``, as (offset, value)."""
        found: dict[int, tuple[int, Expression]] = {}
        cur = block
        stmts = list(cur.statements)
        end = next((i for i, st in enumerate(stmts) if st is stmt), len(stmts))
        seen = set()
        while True:
            for st in reversed(stmts[:end]):
                if not (isinstance(st, Assignment) and isinstance(st.dst, VirtualVariable) and st.dst.was_stack):
                    continue
                dst = st.dst
                if dst.stack_offset >= base + size or dst.stack_offset + dst.size <= base:
                    continue
                at = dst.stack_offset - base
                if at < 0 or at + dst.size > size or any(a <= at < a + s for a, (s, _) in found.items()):
                    return None
                found[at] = (dst.size, st.src)
                pieces = sorted((at, s, v) for at, (s, v) in found.items())
                if self._covers(pieces, size, name):
                    return [(at, v) for at, _, v in pieces]
            seen.add(cur)
            preds = list(self._graph.predecessors(cur))
            if len(preds) != 1 or preds[0] in seen:
                return None
            cur = preds[0]
            stmts = list(cur.statements)
            end = len(stmts)

    def _slot_window(self, block: Block, stmt: Statement) -> list[tuple[Block, Statement]]:
        """The statements after ``stmt``: the rest of its block, then straight-line successors up to a call."""
        stmts = list(block.statements)
        pos = next((i for i, st in enumerate(stmts) if st is stmt), len(stmts))
        out = [(block, st) for st in stmts[pos + 1 :]]
        if any(find_call(st) is not None for _, st in out):
            return out
        cur = block
        seen = {block}
        while True:
            succs = list(self._graph.successors(cur))
            join = self._after_barrier(cur) if len(succs) == 2 else None
            if join is not None:
                cur = join
            elif len(succs) != 1 or self._graph.in_degree(succs[0]) != 1:
                return out
            else:
                cur = succs[0]
            if cur in seen:
                return out
            seen.add(cur)
            for st in cur.statements:
                out.append((cur, st))
                if find_call(st) is not None:
                    return out

    def _slot_offset(self, addr: Expression, slot: VirtualVariable) -> int | None:
        base, off = _addr_and_offset(addr)
        if base is None:
            return None
        base = self.values.resolve(base)
        return off if isinstance(base, VirtualVariable) and base.varid == slot.varid else None

    def _fold_mapassign(self, block: Block, stmt, call: Call, name: str, counts: Counter) -> list[Block]:
        types = self._map_types(call)
        if types is None:
            return []
        _, key_ty, elem_ty = types
        elem_size = self._type_size_bytes(elem_ty)
        key = self._map_key(name, call, block, stmt, key_ty)
        if key is None or elem_size is None:
            return []
        elem_name = elem_ty.go_repr() if hasattr(elem_ty, "go_repr") else ""
        m = list(call.args)[1]
        stores: list[tuple[Block, Store, int]] = []
        slot = stmt.dst if isinstance(stmt, Assignment) else None
        if slot is not None:
            if elem_size == 0:
                return []
            found: dict[int, tuple[int, Expression]] = {}
            for blk, st in self._slot_window(block, stmt):
                if not isinstance(st, Store):
                    continue
                at = self._slot_offset(st.addr, slot)
                if at is None or at < 0 or at + st.size > elem_size or at in found:
                    continue
                found[at] = (st.size, st.data)
                stores.append((blk, st, at))
            pieces = sorted((at, s, v) for at, (s, v) in found.items())
            if not self._covers(pieces, elem_size, elem_name) or counts[slot.varid] != len(stores) + 1:
                return []
            values = [(at, v) for at, _, v in pieces]
            value = values[0][1] if len(values) == 1 else self._map_value(elem_name, elem_size, values)
        elif elem_size == 0:
            value = Struct(self.manager.next_atom(), elem_name or "struct{}", OrderedDict(), OrderedDict(), 0)
        else:
            return []
        tags = {k: v for k, v in stmt.tags.items() if not k.startswith("go_")}
        assign = Call(self.manager.next_atom(), "mapassign", [m, key, value], bits=None, go_render="assign", **tags)
        new_stmt = SideEffectStatement(stmt.idx, assign, **dict(assign.tags))
        block.statements = [new_stmt if st is stmt else st for st in block.statements]
        dropped = {id(st) for _, st, _ in stores}
        touched = [block]
        for blk, _, _ in stores:
            blk.statements = [st for st in blk.statements if id(st) not in dropped]
            if blk not in touched:
                touched.append(blk)
        return touched

    def _map_value(self, elem_name: str, size: int, pieces: list[tuple[int, Expression]]) -> Expression:
        ws = self.project.arch.bytes
        if (elem_name == "string" or elem_name.startswith("[]")) and all(at % ws == 0 for at, _ in pieces):
            value = self.values.whole(size, *pieces)
            if value is None and elem_name == "string" and len(pieces) == 2:
                value = self.values.literal(pieces[0][1], pieces[1][1])
            if value is not None:
                return value
        return self._struct_of(elem_name, pieces)

    def _fold_mapaccess(self, block: Block, stmt: Assignment, call: Call, name: str, counts: Counter) -> list[Block]:
        """``t = mapaccess*(...)`` whose result is only read through offsets: one typed value ``m[k]``."""
        types = self._map_types(call)
        if types is None:
            return []
        map_name, key_ty, elem_ty = types
        elem_size = self._type_size_bytes(elem_ty)
        key = self._map_key(name, call, block, stmt, key_ty)
        if key is None or not elem_size:
            return []
        dst = stmt.dst
        two = name.startswith("runtime.mapaccess2")
        if two:
            if not (dst.was_combo_reg and dst.reg_vvars and len(dst.reg_vvars) == 2):
                return []
            slot, ok = dst.reg_vvars
        else:
            slot, ok = dst, None
        loads = self._count_slot_loads(slot, elem_size)
        # the use count includes the definition of a plain result, not of a combo's register piece
        if loads < 0 or counts[slot.varid] - loads not in (0, 1):
            return []
        m = list(call.args)[1]
        bits = self.project.arch.bits
        rax, rbx = self._result_registers()
        val = VirtualVariable(
            self.manager.next_atom(), self._new_varid(), max(elem_size * 8, bits), VVC.REGISTER, oident=rax
        )
        tags = {k: v for k, v in stmt.tags.items() if not k.startswith("go_") and k != "is_prototype_guessed"}
        index = Call(
            self.manager.next_atom(),
            "mapindex",
            [m, key],
            bits=val.bits + (ok.bits if ok is not None else 0),
            go_render="index",
            is_prototype_guessed=False,
            **tags,
        )
        map_ty = self.kb.go_signatures.type(map_name)
        returnty = GoSimTypeTuple([elem_ty, self.kb.go_signatures.type("bool")]) if two else elem_ty
        with contextlib.suppress(Exception):
            proto = GoSimTypeFunction([map_ty, key_ty], returnty).with_arch(self.project.arch)
            variable_map_of(self.manager).set_prototype(index, proto)
        if two:
            result = VirtualVariable(
                self.manager.next_atom(),
                self._new_varid(),
                val.bits + ok.bits,
                VVC.COMBO_REGISTER,
                oident=(rax, rbx),
                reg_vvars=[val, ok],
            )
        else:
            result = val
        block.statements = [
            SideEffectStatement(stmt.idx, index, ret_expr=result, **dict(index.tags)) if st is stmt else st
            for st in block.statements
        ]
        rewriter = _SlotLoadRewriter(self, slot, val, elem_size)
        touched = [block]
        for blk in self._graph.nodes:
            rewriter.walk(blk)
            if rewriter.changed and blk not in touched:
                touched.append(blk)
            rewriter.changed = False
        return touched

    def _count_slot_loads(self, slot: VirtualVariable, elem_size: int) -> int:
        counter = _SlotLoadCounter(self, slot, elem_size)
        for blk in self._graph.nodes:
            counter.walk(blk)
        return counter.count if counter.ok else -1

    def _result_registers(self) -> tuple[int, int]:
        regs = self.project.arch.registers
        names = ("rax", "rbx") if "rax" in regs else ("x0", "x1") if "x0" in regs else ("eax", "ebx")
        return regs[names[0]][0], regs[names[1]][0]

    def _new_varid(self) -> int:
        varid = self.vvar_id_start
        self.vvar_id_start += 1
        return varid

    def _rw_makemap_small(self, call: Call, args: list) -> Expression | None:
        """``makemap_small()`` is ``make(map[K]V)`` of the typed struct field it is stored into."""
        stmt = self._cur_stmt
        name = None
        if isinstance(stmt, Store) and isinstance(stmt.data, Call) and stmt.data.idx == call.idx:
            base, off = _addr_and_offset(stmt.addr)
            name = self._field_type_name(base, off) if base is not None else None
        elif isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
            dst = self.values.resolve(stmt.dst)
            for blk in self._graph.nodes:
                for st in blk.statements:
                    if isinstance(st, Store) and self.values.resolve(st.data).likes(dst):
                        base, off = _addr_and_offset(st.addr)
                        name = self._field_type_name(base, off) if base is not None else None
                        if name is not None:
                            break
                if name is not None:
                    break
        ty = None
        with contextlib.suppress(Exception):
            ty = self.kb.go_signatures.type(name) if name is not None else None
        if not isinstance(ty, GoSimTypeMap):
            return None
        return self.builtin(call, "make", [], go_type_args=[name], go_result_type=name)

    def _pointee_type_name(self, expr: Expression) -> str | None:
        """The Go type ``*T`` points to when ``expr`` is a typed pointer: a ``new(T)`` result or a parameter."""
        e = self.values.expand(expr)
        if isinstance(e, Call):
            if e.target == "new":
                type_args = list(e.tags.get("go_type_args", ()) or ())
                return type_args[0] if type_args else None
            name = self.callee_name(e)
            args = list(e.args or [])
            if name == "runtime.newobject" and len(args) == 1:
                return self.type_name(args[0])
            if name is not None and name.startswith("runtime.mallocgc") and len(args) == 3:
                return self.type_name(args[1])
            return None
        resolved = self.values.resolve(expr)
        proto = self._func.prototype
        if isinstance(resolved, VirtualVariable) and self._arg_vvars and isinstance(proto, GoSimTypeFunction):
            for (vvar, _), ty in zip(self._arg_vvars.values(), proto.args):
                if isinstance(vvar, VirtualVariable) and vvar.varid == resolved.varid:
                    pts_to = getattr(ty, "pts_to", None)
                    return pts_to.go_repr() if pts_to is not None and hasattr(pts_to, "go_repr") else None
        return None

    def _field_type_name(self, base: Expression, off: int) -> str | None:
        type_name = self._pointee_type_name(base)
        if type_name is None:
            return None
        try:
            ty = self.kb.go_signatures.type(type_name)
        except Exception:  # pylint:disable=broad-exception-caught
            return None
        offsets = getattr(ty, "offsets", None)
        fields = getattr(ty, "fields", None)
        if not offsets or not fields:
            return None
        for field, at in offsets.items():
            if at == off and hasattr(fields[field], "go_repr"):
                return fields[field].go_repr()
        return None


class _Growth:
    """One growslice call and what was matched around it."""

    __slots__ = (
        "arms",
        "base",
        "block",
        "call_stmt",
        "cond_block",
        "count",
        "elems",
        "et",
        "join",
        "len_new",
        "len_old",
        "new_len",
        "num",
        "old_len",
        "phis",
        "post_grow",
        "ptrs",
        "src",
        "stores",
        "width",
    )

    def __init__(self, block, call_stmt, base, count, num, et, old_len, new_len, width):
        self.block = block
        self.call_stmt = call_stmt
        self.base = base
        self.count = count
        self.num = num
        self.et = et
        self.old_len = old_len
        self.new_len = new_len
        self.width = width
        self.cond_block = self.join = None
        self.arms: list = []  # (conditional block, its arm that skips the growth, that arm's last block)
        self.post_grow = block
        self.phis: dict = {}
        self.ptrs: list = []
        self.len_new: list = []
        self.len_old: list = []
        self.elems: list | None = None
        self.src = None
        self.stores: list = []


_GROWSLICE_NAMES = frozenset({"runtime.growslice", "runtime.growsliceBuf"})

# runtime calls nothing downstream matches by argument position: a surviving one spells its descriptor as a type
_DESCRIPTOR_CALLS = (
    "runtime.mapassign",
    "runtime.mapaccess",
    "runtime.mapdelete",
    "runtime.mapclear",
    "runtime.mapclone",
    "runtime.makemap",
    "runtime.makeslice",
    "runtime.growslice",
    "runtime.typedslicecopy",
    "runtime.typedmemclr",
    "runtime.moveSliceNoCap",
    "runtime.assertE2I",
)


_SWAPPED = {"CmpEQ": "CmpEQ", "CmpNE": "CmpNE", "CmpLT": "CmpGT", "CmpGT": "CmpLT", "CmpLE": "CmpGE", "CmpGE": "CmpLE"}
_NEGATED = {"CmpEQ": "CmpNE", "CmpNE": "CmpEQ"}

_CALL_RULES = {
    "runtime.newobject": GoBuiltinRewriter._rw_newobject,
    "runtime.mallocgc": GoBuiltinRewriter._rw_mallocgc,
    "runtime.makeslice": GoBuiltinRewriter._rw_makeslice,
    "runtime.makeslice64": GoBuiltinRewriter._rw_makeslice,
    "runtime.growslice": GoBuiltinRewriter._rw_growslice,
    "runtime.growsliceBuf": GoBuiltinRewriter._rw_growslice,
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
    "runtime.typedslicecopy": GoBuiltinRewriter._rw_typedslicecopy,
    "runtime.makeslicecopy": GoBuiltinRewriter._rw_makeslicecopy,
    "runtime.ifaceeq": GoBuiltinRewriter._rw_ifaceeq,
    "runtime.efaceeq": GoBuiltinRewriter._rw_ifaceeq,
    "runtime.memmove": GoBuiltinRewriter._rw_memmove,
    "runtime.gopanic": GoBuiltinRewriter._rw_gopanic,
    "runtime.makemap_small": GoBuiltinRewriter._rw_makemap_small,
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
        return self._apply(expr, self._pass.rewrite_call(expr, block, stmt))

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
            new_stmt = self._pass.rewrite_call_stmt(stmt)
            if new_stmt is None and isinstance(stmt.expr, Call):
                # the code generator reads render tags off the statement
                extra = {k: v for k, v in stmt.expr.tags.items() if k.startswith("go_") and k not in stmt.tags}
                if extra:
                    new_stmt = SideEffectStatement(stmt.idx, stmt.expr, ret_expr=stmt.ret_expr, **stmt.tags, **extra)
            return self._apply(stmt, new_stmt)
        return stmt


class _SlotLoadCounter(AILBlockViewer):
    """Uses of a map slot pointer: ok when every use is a load of a piece inside the element."""

    def __init__(self, pass_: GoBuiltinRewriter, slot: VirtualVariable, size: int):
        super().__init__()
        self._pass = pass_
        self._slot = slot
        self._size = size
        self.count = 0
        self.ok = True

    def _handle_Load(self, expr_idx, expr: Load, stmt_idx, stmt, block):
        at = self._pass._slot_offset(expr.addr, self._slot)
        if at is not None and at >= 0 and at + expr.size <= self._size:
            self.count += 1
            return
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr: VirtualVariable, stmt_idx, stmt, block):
        if expr.varid == self._slot.varid:
            self.ok = False

    def _handle_Assignment(self, stmt_idx, stmt, block):
        # the definition itself is not a use
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)


class _SlotLoadRewriter(AILBlockRewriter):
    """``Load(slot + k, n)`` -> the piece of the map value at ``k``."""

    def __init__(self, pass_: GoBuiltinRewriter, slot: VirtualVariable, val: VirtualVariable, size: int):
        super().__init__()
        self._pass = pass_
        self._slot = slot
        self._val = val
        self._size = size
        self.changed = False

    def _handle_Load(self, expr_idx, expr: Load, stmt_idx, stmt, block):
        at = self._pass._slot_offset(expr.addr, self._slot)
        if at is not None and at >= 0 and at + expr.size <= self._size:
            self.changed = True
            if at == 0 and expr.size * 8 == self._val.bits:
                return self._val
            offset = Const(self._pass.manager.next_atom(), at, self._pass.project.arch.bits)
            return Extract(self._pass.manager.next_atom(), expr.size * 8, self._val, offset, expr.endness, **expr.tags)
        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)


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
