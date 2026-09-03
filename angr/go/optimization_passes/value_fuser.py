from __future__ import annotations

import contextlib
import logging
from collections import OrderedDict

from angr.ailment import AILBlockRewriter
from angr.ailment.expression import BinaryOp, Call, Const, Load, StringLiteral, Struct, UnaryOp, VirtualVariable
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, Return
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.calling_conventions import SimArrayArg, SimComboArg, SimStructArg
from angr.go.sim_type import GoSimStruct, GoSimTypeFunction, GoSimTypeString, GoSimTypeTuple
from angr.go.utils.names import call_target_name
from angr.sim_type import SimType

l = logging.getLogger(__name__)


def _leaf_count(ty: SimType) -> int:
    if isinstance(ty, GoSimStruct):
        return sum(_leaf_count(f) for f in ty.fields.values()) or 1
    return 1


def _flatten_locs(loc) -> list:
    if isinstance(loc, SimStructArg):
        return [x for sub in loc.locs.values() for x in _flatten_locs(sub)]
    if isinstance(loc, SimArrayArg):
        return [x for sub in loc.locs for x in _flatten_locs(sub)]
    if isinstance(loc, SimComboArg):
        return [x for sub in loc.locations for x in _flatten_locs(sub)]
    return [loc]


def _load_base_and_offset(expr) -> tuple | None:
    """``Load(base + k)`` -> (base, k); ``Load(Const c)`` -> (None, c)."""
    if not isinstance(expr, Load):
        return None
    addr = expr.addr
    if isinstance(addr, Const):
        return None, addr.value_int
    if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[1], Const):
        return addr.operands[0], addr.operands[1].value_int
    if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[0], Const):
        return addr.operands[1], addr.operands[0].value_int
    return addr, 0


class GoValueFuser(OptimizationPass):
    """
    Re-assemble string, slice, interface and multi-result values that the ABI splits across several registers.

    Call arguments and return values are grouped by the callee's (or the function's) Go prototype. A group that is a
    contiguous slice of one combo-register value becomes a load from that value, contiguous loads become one wider
    load, a constant (pointer, length) pair in read-only memory becomes a string literal, and anything else becomes a
    ``Struct`` expression.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Fuse Go values split across registers"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self._varid_to_combo: dict[int, VirtualVariable] = {}
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self._collect_combo_vvars()
        rewriter = _FusingRewriter(self)
        for block in list(self._graph.nodes):
            rewriter.walk(block)
        if rewriter.changed:
            self.out_graph = self._graph

    def _collect_combo_vvars(self) -> None:
        def note(vvar):
            if vvar.category == VVC.COMBO_REGISTER and vvar.reg_vvars:
                for reg_vvar in vvar.reg_vvars:
                    self._varid_to_combo[reg_vvar.varid] = vvar

        if self._arg_vvars:
            for arg_vvar, _ in self._arg_vvars.values():
                if isinstance(arg_vvar, VirtualVariable):
                    note(arg_vvar)
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    note(stmt.dst)

    #
    # Grouping
    #

    def callee_prototype(self, call: Call) -> GoSimTypeFunction | None:
        name = call_target_name(self.project, call)
        if name is None:
            return None
        if isinstance(call.target, Const) and self.kb.functions.contains_addr(call.target.value_int):
            func = self.kb.functions.get_by_addr(call.target.value_int)
            proto = func.prototype
            if isinstance(proto, GoSimTypeFunction):
                return proto
        return self.kb.go_signatures.prototype(name)

    def fuse_args(self, call: Call, proto: GoSimTypeFunction) -> list | None:
        if not call.args or proto.variadic:
            return None
        cc = self.project.factory.cc()
        try:
            arg_locs = cc.arg_locs(proto)
        except Exception:  # pylint:disable=broad-exception-caught
            return None
        counts = [len(_flatten_locs(loc)) for loc in arg_locs]
        if sum(counts) != len(call.args) or all(c == 1 for c in counts):
            return None
        new_args = []
        pos = 0
        for ty, n in zip(proto.args, counts):
            leaves = list(call.args[pos : pos + n])
            pos += n
            new_args.append(self.fuse(ty, leaves) if n > 1 else leaves[0])
        return new_args

    def fuse_results(self, ret_exprs: list, proto: GoSimTypeFunction) -> list | None:
        results = proto.results
        counts = [_leaf_count(t) for t in results]
        if sum(counts) != len(ret_exprs) or all(c == 1 for c in counts):
            return None
        out = []
        pos = 0
        for ty, n in zip(results, counts):
            leaves = list(ret_exprs[pos : pos + n])
            pos += n
            out.append(self.fuse(ty, leaves) if n > 1 else leaves[0])
        return out

    def fuse(self, ty: SimType, leaves: list):
        """Turn the leaf expressions making up one value of type ``ty`` into a single expression."""
        if len(leaves) == 1:
            return leaves[0]
        if not isinstance(ty, GoSimStruct):
            return self._struct_expr(ty, leaves)
        size = ty.size // self.project.arch.byte_width if ty.size else None

        fused = self._fuse_combo_slice(leaves, size)
        if fused is None:
            fused = self._fuse_contiguous_loads(leaves)
        if fused is None and isinstance(ty, GoSimTypeString):
            fused = self._string_literal(leaves)
        if fused is not None:
            return fused
        return self._struct_expr(ty, leaves)

    def _fuse_combo_slice(self, leaves: list, size: int | None):
        combo = None
        for leaf in leaves:
            if not isinstance(leaf, VirtualVariable):
                return None
            c = self._varid_to_combo.get(leaf.varid)
            if c is None or (combo is not None and c.varid != combo.varid):
                return None
            combo = c
        assert combo is not None and combo.reg_vvars is not None
        ids = [rv.varid for rv in combo.reg_vvars]
        try:
            first = ids.index(leaves[0].varid)
        except ValueError:
            return None
        if [leaf.varid for leaf in leaves] != ids[first : first + len(leaves)]:
            return None
        if first == 0 and len(leaves) == len(ids):
            return combo
        offset = sum(rv.size for rv in combo.reg_vvars[:first])
        width = sum(leaf.size for leaf in leaves)
        if size is not None and width != size:
            width = size
        addr = UnaryOp(self.manager.next_atom(), "Reference", combo, bits=self.project.arch.bits)
        if offset:
            addr = BinaryOp(
                self.manager.next_atom(),
                "Add",
                [addr, Const(self.manager.next_atom(), offset, self.project.arch.bits)],
                bits=self.project.arch.bits,
            )
        return Load(self.manager.next_atom(), addr, width, self.project.arch.memory_endness, **leaves[0].tags)

    def _fuse_contiguous_loads(self, leaves: list):
        parsed = [_load_base_and_offset(leaf) for leaf in leaves]
        if any(p is None for p in parsed):
            return None
        base0, off0 = parsed[0]
        expected = off0
        for (base, off), leaf in zip(parsed, leaves):
            same_base = (base is None and base0 is None) or (
                base is not None and base0 is not None and base.likes(base0)
            )
            if not same_base or off != expected:
                return None
            expected += leaf.size
        width = expected - off0
        bits = self.project.arch.bits
        if base0 is None:
            addr = Const(self.manager.next_atom(), off0, bits)
        elif off0:
            addr = BinaryOp(
                self.manager.next_atom(), "Add", [base0, Const(self.manager.next_atom(), off0, bits)], bits=bits
            )
        else:
            addr = base0
        return Load(self.manager.next_atom(), addr, width, self.project.arch.memory_endness, **leaves[0].tags)

    def _string_literal(self, leaves: list):
        if len(leaves) != 2 or not all(isinstance(x, Const) for x in leaves):
            return None
        ptr, length = leaves[0].value_int, leaves[1].value_int
        if length < 0 or length > 0x10000:
            return None
        if length == 0:
            return StringLiteral(self.manager.next_atom(), "", 128, **leaves[0].tags)
        section = self.project.loader.find_section_containing(ptr)
        if section is None or not section.is_readable or section.is_writable:
            return None
        with contextlib.suppress(KeyError, UnicodeDecodeError):
            data = self.project.loader.memory.load(ptr, length).decode("utf-8")
            return StringLiteral(self.manager.next_atom(), data, 128, **leaves[0].tags)
        return None

    def _struct_expr(self, ty: SimType, leaves: list):
        if isinstance(ty, GoSimStruct) and ty.fields:
            fields = OrderedDict()
            field_offsets = OrderedDict()
            offsets = ty.offsets
            pos = 0
            for fname, fty in ty.fields.items():
                n = _leaf_count(fty)
                sub = leaves[pos : pos + n]
                pos += n
                if not sub:
                    break
                off = offsets.get(fname, 0)
                fields[off] = self.fuse(fty, sub) if n > 1 else sub[0]
                field_offsets[fname] = off
            bits = ty.size or sum(leaf.bits for leaf in leaves)
            name = ty.go_repr()
        else:
            fields = OrderedDict((i * 8, leaf) for i, leaf in enumerate(leaves))
            field_offsets = OrderedDict((f"f{i}", i * 8) for i in range(len(leaves)))
            bits = sum(leaf.bits for leaf in leaves)
            name = ty.go_repr() if hasattr(ty, "go_repr") else str(ty)
        return Struct(self.manager.next_atom(), name, fields, field_offsets, bits, **leaves[0].tags)


class _FusingRewriter(AILBlockRewriter):
    def __init__(self, fuser: GoValueFuser):
        super().__init__()
        self._fuser = fuser
        self.changed = False

    def _handle_Call(self, expr_idx: int, expr: Call, stmt_idx: int, stmt, block):
        expr = super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)
        proto = self._fuser.callee_prototype(expr)
        if proto is None:
            return expr
        new_args = self._fuser.fuse_args(expr, proto)
        if new_args is None:
            return expr
        new_expr = expr.copy()
        new_expr.args = new_args
        self.changed = True
        return new_expr

    def _handle_Return(self, stmt_idx: int, stmt: Return, block):
        proto = self._fuser._func.prototype
        if isinstance(proto, GoSimTypeFunction) and isinstance(proto.returnty, GoSimTypeTuple) and stmt.ret_exprs:
            fused = self._fuser.fuse_results(list(stmt.ret_exprs), proto)
            if fused is not None:
                self.changed = True
                return Return(stmt.idx, fused, **stmt.tags)
        return super()._handle_Return(stmt_idx, stmt, block)
