from __future__ import annotations

import logging
from collections import Counter

from angr.ailment import Block, Statement
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Expression,
    Load,
    Phi,
    StringLiteral,
    Struct,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, ConditionalJump, Return, SideEffectStatement
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import (
    GoSimTypeChan,
    GoSimTypeFunc,
    GoSimTypeInterface,
    GoSimTypeMap,
    GoSimTypePointer,
    GoSimTypeString,
    GoSimTypeUnsafePointer,
)
from angr.go.utils.names import call_target_name, normalize_go_func_name
from angr.go.utils.types import go_type_name_at

l = logging.getLogger(__name__)

# runtime.convT*(x) allocates a copy of x and returns its address: the data word of the boxed value
_CONVT_VALUE = frozenset(
    {"runtime.convT16", "runtime.convT32", "runtime.convT64", "runtime.convTstring", "runtime.convTslice"}
)
# runtime.convT(typ, ptr) / convTnoptr(typ, ptr) copy *ptr
_CONVT_POINTER = frozenset({"runtime.convT", "runtime.convTnoptr"})
_ANY_SLICE_NAMES = frozenset({"[]any", "[]interface {}", "[]interface{}"})


class GoBoxingRewriter(OptimizationPass):
    """
    Recover the values behind interface conversions.

    A value converted to an interface is a (type descriptor or itab, data pointer) pair. Passed directly, the pair is
    already fused into an interface-typed struct literal; the literal becomes ``box(x)`` tagged with the dynamic type.
    A variadic ``...any`` argument is a stack array of such pairs referenced through a ``[]any`` header; its element
    stores are folded into one ``[]any{...}`` literal and dropped.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Recover boxed values behind interface conversions"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self._ws = self.project.arch.bytes
        self._string_bits = 2 * self.project.arch.bits
        self._stack_defs: dict[int, tuple[Block, Assignment]] = {}
        self._defs: dict[int, Assignment] = {}
        self._uses: Counter = Counter()
        self._dead: set[int] = set()  # varids of slot definitions folded into literals
        self._static_ints: tuple[int, int] | None = None
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self._index()
        rewriter = _BoxingRewriter(self)
        for block in list(self._graph.nodes):
            rewriter.walk(block)
        changed = rewriter.changed
        if self._dead:
            self._drop_dead_slots()
            self._drop_dead_defs()
            changed = True
        if changed:
            self.out_graph = self._graph

    #
    # Indexing
    #

    def _index(self) -> None:
        counter = _UseCounter()
        for block in self._graph.nodes:
            counter.walk(block)
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    self._defs[stmt.dst.varid] = stmt
                    if stmt.dst.was_stack:
                        self._stack_defs[stmt.dst.varid] = (block, stmt)
        self._uses = counter.counts

    def _drop_dead_slots(self) -> None:
        for block in self._graph.nodes:
            block.statements = [
                stmt
                for stmt in block.statements
                if not (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and stmt.dst.varid in self._dead
                )
            ]

    def _drop_dead_defs(self) -> None:
        """Drop side-effect-free definitions (phis and loads included) left without uses by the folding."""
        while True:
            counter = _UseCounter()
            for block in self._graph.nodes:
                counter.walk(block)
            counts = counter.counts
            dropped = False
            for block in self._graph.nodes:
                kept = []
                for stmt in block.statements:
                    if (
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and not stmt.dst.was_stack  # stack slots may be read through memory
                        and not isinstance(stmt.src, Call)
                        and counts[stmt.dst.varid] <= 1
                    ):
                        dropped = True
                        continue
                    kept.append(stmt)
                block.statements = kept
            if not dropped:
                return

    #
    # Rewrites
    #

    def rewrite_struct(self, expr: Struct, block: Block, stmt: Statement) -> Expression | None:
        if expr.name in _ANY_SLICE_NAMES:
            return self._rewrite_variadic(expr, block, stmt)
        if expr.name.startswith("[]"):
            return self._rewrite_slice_literal(expr, block, stmt)
        ty = self._type_named(expr.name)
        if isinstance(ty, GoSimTypeInterface) and sorted(expr.fields) == [0, self._ws]:
            return self._box(expr.fields[0], expr.fields[self._ws], expr.name)
        return None

    def _rewrite_variadic(self, expr: Struct, block: Block, stmt: Statement) -> Expression | None:
        fields = expr.fields
        if sorted(fields) != [0, self._ws, 2 * self._ws]:
            return None
        ref, length, cap = fields[0], fields[self._ws], fields[2 * self._ws]
        if not (isinstance(length, Const) and isinstance(cap, Const) and length.value == cap.value):
            return None
        n = length.value
        if not isinstance(n, int) or n <= 0 or n > 64:
            return None
        if not (
            isinstance(ref, UnaryOp)
            and ref.op == "Reference"
            and isinstance(ref.operand, VirtualVariable)
            and ref.operand.was_stack
        ):
            return None
        base_vvar = ref.operand
        base = base_vvar.stack_offset
        offsets = [base + word * self._ws for word in range(2 * n)]
        defs = self._reaching_slot_defs(block, stmt, offsets)
        if defs is None:
            return None
        elems = []
        slots = []
        for i in range(n):
            pair = [defs[offsets[2 * i]], defs[offsets[2 * i + 1]]]
            for assignment in pair:
                # the base slot is referenced by the header; every other slot may only be read through memory
                # (the count includes the definition itself)
                allowed = 2 if assignment.dst.varid == base_vvar.varid else 1
                if self._uses[assignment.dst.varid] > allowed:
                    return None
            box = self._box(pair[0].src, pair[1].src, "any")
            if box is None:
                return None
            elems.append(box)
            slots += pair
        for slot in slots:
            self._dead.add(slot.dst.varid)
        # zero-initialization of the array before the element stores
        end = base + 2 * n * self._ws
        for varid, (_, assignment) in self._stack_defs.items():
            dst = assignment.dst
            if (
                base <= dst.stack_offset
                and dst.stack_offset + dst.size <= end
                and self._uses[varid] <= 1
                and isinstance(assignment.src, Const)
                and assignment.src.value == 0
            ):
                self._dead.add(varid)
        literal = Call(
            self.manager.next_atom(),
            "[]any",
            elems,
            bits=expr.bits,
            go_render="slice_literal",
            go_elem_type="any",
            **{k: v for k, v in expr.tags.items() if not k.startswith("go_")},
        )
        self._set_result_type(literal, "[]any")
        return literal

    def _reaching_slot_defs(self, block: Block, stmt: Statement, offsets: list[int]) -> dict[int, Assignment] | None:
        """
        The word-sized stack stores at ``offsets`` that reach ``stmt``, found by walking back over the straight-line
        predecessors. None when a store cannot be pinned down (a merge point, or an overlapping store of another size).
        """
        wanted = set(offsets)
        found: dict[int, Assignment] = {}
        cur = block
        end = next((i for i, st in enumerate(cur.statements) if st is stmt or st == stmt), len(cur.statements))
        visited = set()
        while True:
            for st in reversed(cur.statements[:end]):
                if not (isinstance(st, Assignment) and isinstance(st.dst, VirtualVariable) and st.dst.was_stack):
                    continue
                dst = st.dst
                for off in list(wanted):
                    if off in found:
                        continue
                    if dst.stack_offset == off and dst.size == self._ws:
                        found[off] = st
                    elif dst.stack_offset < off + self._ws and off < dst.stack_offset + dst.size:
                        return None
            if len(found) == len(wanted):
                return found
            visited.add((cur.addr, cur.idx))
            preds = list(self._graph.predecessors(cur))
            if len(preds) != 1 or (preds[0].addr, preds[0].idx) in visited:
                return None
            cur = preds[0]
            end = len(cur.statements)

    def _rewrite_slice_literal(self, expr: Struct, block: Block, stmt: Statement) -> Expression | None:
        """``[]T{ptr: &array, len: n, cap: n}`` over a stack array of word-sized elements -> ``[]T{e0, ..., en-1}``."""
        fields = expr.fields
        if sorted(fields) != [0, self._ws, 2 * self._ws]:
            return None
        ref, length, cap = fields[0], fields[self._ws], fields[2 * self._ws]
        if not (isinstance(length, Const) and isinstance(cap, Const) and length.value == cap.value):
            return None
        n = length.value
        if not isinstance(n, int) or n <= 0 or n > 64:
            return None
        if not (
            isinstance(ref, UnaryOp)
            and ref.op == "Reference"
            and isinstance(ref.operand, VirtualVariable)
            and ref.operand.was_stack
        ):
            return None
        elem_name = expr.name[2:]
        elem = self._type_named(elem_name)
        if elem is None or not elem.size or elem.size != self.project.arch.bits:
            return None
        base_vvar = ref.operand
        base = base_vvar.stack_offset
        offsets = [base + i * self._ws for i in range(n)]
        defs = self._reaching_slot_defs(block, stmt, offsets)
        if defs is None:
            return None
        elems = []
        for off in offsets:
            assignment = defs[off]
            allowed = 2 if assignment.dst.varid == base_vvar.varid else 1
            if self._uses[assignment.dst.varid] > allowed or not _is_plain_value(assignment.src):
                return None
            elems.append(assignment.src)
        for off in offsets:
            self._dead.add(defs[off].dst.varid)
        end = base + n * self._ws
        for varid, (_, assignment) in self._stack_defs.items():
            dst = assignment.dst
            if (
                base <= dst.stack_offset
                and dst.stack_offset + dst.size <= end
                and self._uses[varid] <= 1
                and isinstance(assignment.src, Const)
                and assignment.src.value == 0
            ):
                self._dead.add(varid)
        literal = Call(
            self.manager.next_atom(),
            expr.name,
            elems,
            bits=expr.bits,
            go_render="slice_literal",
            go_elem_type=elem_name,
            **{k: v for k, v in expr.tags.items() if not k.startswith("go_")},
        )
        self._set_result_type(literal, expr.name)
        return literal

    def _box(self, type_word: Expression, data_word: Expression, iface_name: str) -> Expression | None:
        """``box(value)`` for the (type descriptor or itab, data pointer) pair, or None when it is not understood."""
        value = None
        concrete = None
        if isinstance(type_word, Const) and isinstance(type_word.value, int):
            concrete = self._concrete_type_name(type_word.value)
            if concrete is None:
                return None
            value = self._unbox_data(data_word, concrete)
        else:
            # eface from iface: the type word is itab.Type (nil when the itab is nil) and the data word is carried over
            tab_word = self._itab_of_type_word(type_word)
            if tab_word is not None:
                value = self._interface_value(tab_word, self._resolve_copies(data_word))
        if value is None:
            return None
        box = Call(
            self.manager.next_atom(),
            iface_name,
            [value],
            bits=2 * self._ws * self.project.arch.byte_width,
            go_render="box",
            go_box_type=concrete,
            **{k: v for k, v in data_word.tags.items() if not k.startswith("go_")},
        )
        self._set_result_type(box, iface_name)
        return box

    def _resolve_copies(self, expr: Expression) -> Expression:
        seen = set()
        while isinstance(expr, VirtualVariable) and expr.varid not in seen:
            seen.add(expr.varid)
            definition = self._defs.get(expr.varid)
            if definition is None or not isinstance(definition.src, VirtualVariable):
                break
            expr = definition.src
        return expr

    def _itab_type_load(self, expr: Expression) -> VirtualVariable | None:
        """``tab`` when ``expr`` is ``Load(tab + ws)``, the itab's type descriptor."""
        expr = self._resolve_copies(expr)
        if isinstance(expr, VirtualVariable):
            definition = self._defs.get(expr.varid)
            expr = definition.src if definition is not None else expr
        if not (isinstance(expr, Load) and expr.size == self._ws):
            return None
        addr = expr.addr
        if (
            isinstance(addr, BinaryOp)
            and addr.op == "Add"
            and isinstance(addr.operands[1], Const)
            and addr.operands[1].value == self._ws
        ):
            tab = self._resolve_copies(addr.operands[0])
            return tab if isinstance(tab, VirtualVariable) else None
        return None

    def _itab_of_type_word(self, type_word: Expression) -> VirtualVariable | None:
        """
        The itab word an eface type word was derived from: ``Load(tab + ws)`` directly, or the phi of that load with
        the nil itab itself (the compiler's ``if tab != nil { typ = tab.Type }``).
        """
        tab = self._itab_type_load(type_word)
        if tab is not None:
            return tab
        resolved = self._resolve_copies(type_word)
        definition = self._defs.get(resolved.varid) if isinstance(resolved, VirtualVariable) else None
        if definition is None or not isinstance(definition.src, Phi):
            return None
        sources = [self._resolve_copies(v) for _, v in definition.src.src_and_vvars if v is not None]
        if len(sources) != 2:
            return None
        for a, b in ((sources[0], sources[1]), (sources[1], sources[0])):
            tab = self._itab_type_load(a)
            if tab is not None and isinstance(b, VirtualVariable) and b.varid == tab.varid:
                return tab
        return None

    def _interface_value(self, tab_word: Expression, data_word: Expression) -> Expression | None:
        """
        The interface-typed value whose two register words are ``tab_word`` and ``data_word``: a parameter, or the
        result of a call.
        """
        if not (isinstance(tab_word, VirtualVariable) and isinstance(data_word, VirtualVariable)):
            return None
        wanted = [tab_word.varid, data_word.varid]
        if self._arg_vvars is not None:
            for arg_vvar, _ in self._arg_vvars.values():
                reg_vvars = getattr(arg_vvar, "reg_vvars", None)
                if reg_vvars and [v.varid for v in reg_vvars] == wanted:
                    return arg_vvar
        for definition in self._defs.values():
            dst = definition.dst
            if (
                isinstance(dst, VirtualVariable)
                and dst.was_combo_reg
                and dst.reg_vvars
                and [v.varid for v in dst.reg_vvars] == wanted
            ):
                return dst
        return None

    def _unbox_data(self, data_word: Expression, concrete: str) -> Expression | None:
        ty = self._type_named(concrete)
        if isinstance(data_word, Call):
            name = self._callee(data_word)
            args = list(data_word.args or [])
            if name in _CONVT_VALUE and len(args) == 1:
                return args[0]
            if name in _CONVT_POINTER and len(args) == 2 and ty is not None and ty.size:
                return Load(
                    self.manager.next_atom(),
                    args[1],
                    ty.size // self.project.arch.byte_width,
                    self.project.arch.memory_endness,
                    **data_word.tags,
                )
            return None
        if isinstance(data_word, Const) and isinstance(data_word.value, int):
            addr = data_word.value
            small = self._static_int(addr)
            if small is not None and ty is not None and ty.size and not _is_pointer_shaped(ty, concrete):
                return Const(self.manager.next_atom(), small, ty.size, **data_word.tags)
            zerobase = self.project.loader.find_symbol("runtime.zerobase")
            if zerobase is not None and addr == zerobase.rebased_addr:
                if isinstance(ty, GoSimTypeString):
                    return StringLiteral(self.manager.next_atom(), "", self._string_bits, **data_word.tags)
                return Const(self.manager.next_atom(), 0, ty.size if ty is not None and ty.size else 64)
            if isinstance(ty, GoSimTypeString):
                literal = self._static_string(addr)
                if literal is not None:
                    return StringLiteral(self.manager.next_atom(), literal, self._string_bits, **data_word.tags)
        if _is_pointer_shaped(ty, concrete):
            return data_word
        return None

    #
    # Helpers
    #

    def _callee(self, call: Call) -> str | None:
        name = call_target_name(self.project, call)
        return normalize_go_func_name(name) if name is not None else None

    def _type_named(self, name: str):
        try:
            return self.kb.go_signatures.type(name)
        except Exception:  # pylint:disable=broad-exception-caught
            return None

    def _concrete_type_name(self, addr: int) -> str | None:
        go_types = self.kb.go_types
        itab = go_types.itab_at(addr)
        if itab is not None:
            return itab[1]
        return go_type_name_at(self.project, addr)

    def _static_int(self, addr: int) -> int | None:
        """The value ``runtime.staticuint64s[i]`` at ``addr`` (used to box small integers without allocating)."""
        if self._static_ints is None:
            sym = self.project.loader.find_symbol("runtime.staticuint64s")
            self._static_ints = (sym.rebased_addr, 256 * 8) if sym is not None else (0, 0)
        start, size = self._static_ints
        if size and start <= addr < start + size and (addr - start) % 8 == 0:
            return (addr - start) // 8
        return None

    def _static_string(self, addr: int) -> str | None:
        """The literal behind a static ``string`` header at ``addr``."""
        try:
            ptr = self.project.loader.memory.unpack_word(addr, size=self._ws)
            length = self.project.loader.memory.unpack_word(addr + self._ws, size=self._ws)
            if not 0 < length < 4096 or self.project.loader.find_object_containing(ptr) is None:
                return None
            data = self.project.loader.memory.load(ptr, length)
        except Exception:  # pylint:disable=broad-exception-caught
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _set_result_type(self, call: Call, type_name: str) -> None:
        from angr.go.sim_type import GoSimTypeFunction  # pylint:disable=import-outside-toplevel

        ty = self._type_named(type_name)
        if ty is None:
            return
        proto = GoSimTypeFunction([], ty).with_arch(self.project.arch)
        variable_map_of(self.manager).set_prototype(call, proto)


def _is_plain_value(expr: Expression) -> bool:
    """Constants, variables and string literals: values a literal can spell without a statement."""
    return isinstance(expr, (Const, VirtualVariable, StringLiteral))


def _is_pointer_shaped(ty, name: str) -> bool:
    if isinstance(ty, (GoSimTypePointer, GoSimTypeMap, GoSimTypeChan, GoSimTypeFunc, GoSimTypeUnsafePointer)):
        return True
    if ty is not None:
        return False
    return name.startswith(("*", "map[", "chan ", "<-chan ", "chan<- ", "func(")) or name == "unsafe.Pointer"


class _UseCounter:
    """Counts the uses of each virtual variable (references inside expressions, plus phi sources)."""

    def __init__(self):
        from angr.go.optimization_passes.builtin_rewriter import _VVarCounter  # pylint:disable=import-outside-toplevel

        self._counter = _VVarCounter()

    def walk(self, block: Block) -> None:
        self._counter.walk(block)

    @property
    def counts(self) -> Counter:
        return self._counter.counts


class _BoxingRewriter:
    """Rewrites interface-typed struct literals and ``[]any`` headers inside statements."""

    def __init__(self, pass_: GoBoxingRewriter):
        self._pass = pass_
        self.changed = False
        self._block: Block | None = None
        self._stmt: Statement | None = None

    def walk(self, block: Block):
        self._block = block
        for stmt_idx, stmt in enumerate(list(block.statements)):
            self._stmt = stmt
            new_stmt = self._rewrite_stmt(stmt)
            if new_stmt is not None and new_stmt is not stmt:
                block.statements[stmt_idx] = new_stmt
                self.changed = True

    def _rewrite_stmt(self, stmt: Statement) -> Statement | None:
        # attribute access returns fresh wrapper objects: read each child once and compare against that
        if isinstance(stmt, Assignment):
            src = stmt.src
            new_src = self._rewrite_expr(src)
            return Assignment(stmt.idx, stmt.dst, new_src, **stmt.tags) if new_src is not src else None
        if isinstance(stmt, SideEffectStatement):
            expr = stmt.expr
            new_expr = self._rewrite_expr(expr)
            return SideEffectStatement(stmt.idx, new_expr, **stmt.tags) if new_expr is not expr else None
        if isinstance(stmt, Return) and stmt.ret_exprs:
            exprs = list(stmt.ret_exprs)
            new_exprs = [self._rewrite_expr(e) for e in exprs]
            if any(a is not b for a, b in zip(exprs, new_exprs)):
                return Return(stmt.idx, new_exprs, **stmt.tags)
            return None
        if isinstance(stmt, ConditionalJump):
            cond = stmt.condition
            new_cond = self._rewrite_expr(cond)
            if new_cond is not cond:
                return ConditionalJump(
                    stmt.idx,
                    new_cond,
                    stmt.true_target,
                    stmt.false_target,
                    true_target_idx=stmt.true_target_idx,
                    false_target_idx=stmt.false_target_idx,
                    **stmt.tags,
                )
            return None
        return None

    def _rewrite_expr(self, expr: Expression) -> Expression:
        if isinstance(expr, Struct):
            new = self._pass.rewrite_struct(expr, self._block, self._stmt)
            if new is not None:
                return new
            return expr
        if isinstance(expr, Call):
            args = list(expr.args or [])
            new_args = [self._rewrite_expr(a) for a in args]
            if any(a is not b for a, b in zip(args, new_args)):
                return Call(expr.idx, expr.target, new_args, bits=expr.bits, **expr.tags)
            return expr
        return expr
