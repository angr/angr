from __future__ import annotations

import logging
from collections import Counter

import networkx

from angr.ailment import AILBlockRewriter, Block, Statement
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
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
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, Return, SideEffectStatement, Store
from angr.analyses.decompiler.mixins.cfg_transformation_mixin import CFGTransformationMixin
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
from angr.go.utils.graph import conditional_pred
from angr.go.utils.names import call_target_name, normalize_go_func_name
from angr.go.utils.types import go_type_name_at
from angr.utils.ail import get_terminal_call
from angr.utils.go_runtime import GO_ASSERT_PANIC_NAMES

l = logging.getLogger(__name__)

# runtime.convT*(x) allocates a copy of x and returns its address: the data word of the boxed value
_CONVT_VALUE = frozenset(
    {"runtime.convT16", "runtime.convT32", "runtime.convT64", "runtime.convTstring", "runtime.convTslice"}
)
# runtime.convT(typ, ptr) / convTnoptr(typ, ptr) copy *ptr
_CONVT_POINTER = frozenset({"runtime.convT", "runtime.convTnoptr"})
_ANY_SLICE_NAMES = frozenset({"[]any", "[]interface {}", "[]interface{}"})
# callees whose descriptor arguments are not interface values
_NO_PAIR_CALLEES = ("runtime.", "internal/", "reflect.", "unsafe.")


class GoBoxingRewriter(OptimizationPass, CFGTransformationMixin):
    """
    Recover the values behind interface conversions and type assertions.

    A value converted to an interface is a (type descriptor or itab, data pointer) pair. Passed directly, the pair is
    already fused into an interface-typed struct literal; the literal becomes ``box(x)`` tagged with the dynamic type.
    A variadic ``...any`` argument is a stack array of such pairs referenced through a ``[]any`` header; its element
    stores are folded into one ``[]any{...}`` literal and dropped.

    A panicking assertion ``x.(T)`` is ``if x.tab != T { panicdottype*() }`` followed by reads of ``x.data``; the
    sink and the branch are dropped and the data reads become the assertion.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Recover boxed values behind interface conversions"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self._ws = self.project.arch.bytes
        self._string_bits = 2 * self.project.arch.bits
        self._stack_defs: dict[int, tuple[Block, Assignment]] = {}
        self._defs: dict[int, Assignment] = {}
        self._combo_of: dict[int, tuple[VirtualVariable, int]] = {}
        self._uses: Counter = Counter()
        self._dead: set[int] = set()  # varids of slot definitions folded into literals
        self._static_ints: tuple[int, int] | None = None
        self._stmt_tags: dict = {}
        self._idoms: dict | None = None
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self._index()
        changed = self._recover_assertions()
        if changed:
            self._index()
        rewriter = _BoxingRewriter(self)
        for block in list(self._graph.nodes):
            rewriter.walk(block)
        changed = changed or rewriter.changed
        if self._dead:
            self._drop_dead_slots()
        if changed:
            self._drop_dead_defs()
        if changed:
            self.out_graph = self._graph

    #
    # Indexing
    #

    def _index(self) -> None:
        counter = _UseCounter()
        self._defs, self._stack_defs, self._combo_of = {}, {}, {}

        def note(vvar: VirtualVariable):
            is_combo = vvar.category == VVC.COMBO_REGISTER or (
                vvar.category == VVC.PARAMETER and vvar.parameter_category == VVC.COMBO_REGISTER
            )
            if is_combo and vvar.reg_vvars:
                offset = 0
                for reg_vvar in vvar.reg_vvars:
                    self._combo_of[reg_vvar.varid] = (vvar, offset)
                    offset += reg_vvar.size

        if self._arg_vvars:
            for arg_vvar, _ in self._arg_vvars.values():
                if isinstance(arg_vvar, VirtualVariable):
                    note(arg_vvar)
        for block in self._graph.nodes:
            counter.walk(block)
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    self._defs[stmt.dst.varid] = stmt
                    note(stmt.dst)
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

    def _is_box_alloc(self, expr: Expression) -> bool:
        """``convT*``: an allocation whose only effect is the data word it returns."""
        if not isinstance(expr, Call):
            return False
        name = self._callee(expr)
        return name in _CONVT_VALUE or name in _CONVT_POINTER

    def _drop_dead_defs(self) -> None:
        """Drop side-effect-free definitions (phis, loads and box allocations) left without uses by the folding."""
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
                        and (not isinstance(stmt.src, Call) or self._is_box_alloc(stmt.src))
                        and counts[stmt.dst.varid] <= 1
                    ):
                        dropped = True
                        continue
                    kept.append(stmt)
                block.statements = kept
            if not dropped:
                return

    #
    # Type assertions
    #

    def _recover_assertions(self) -> bool:
        changed = False
        for block in list(self._graph.nodes):
            if block not in self._graph or self._graph.out_degree(block) != 0:
                continue
            call = get_terminal_call(block)
            name = self._callee(call) if call is not None else None
            if name not in GO_ASSERT_PANIC_NAMES or not _only_spills(block):
                continue
            cond_block = conditional_pred(self._graph, block)
            if cond_block is None:
                continue
            check = self._match_assertion(cond_block.statements[-1].condition, name, list(call.args or []))
            preds = list(self._graph.predecessors(block))
            if not self.remove_block(block):
                continue
            for pred in preds:
                self._prune_dead_end(pred)
            changed = True
            if check is not None:
                self._substitute_assertion(cond_block, *check)
            l.debug("Removed assertion sink at %#x of %s", block.addr, self._func.name)
        return changed

    def _prune_dead_end(self, block: Block) -> None:
        while (
            block in self._graph
            and self._graph.out_degree(block) == 0
            and all(isinstance(stmt, Label) for stmt in block.statements)
        ):
            preds = list(self._graph.predecessors(block))
            if not self.remove_block(block) or len(preds) != 1:
                return
            block = preds[0]

    def _match_assertion(self, cond, name: str, args: list):
        """(holder, its data word, concrete type, interface type) for ``x.tab == T`` guarding a panicdottype* sink."""
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None
        iface = (
            go_type_name_at(self.project, args[2].value_int) if len(args) == 3 and isinstance(args[2], Const) else None
        )
        lhs, rhs = cond.operands
        for word, desc in ((lhs, rhs), (rhs, lhs)):
            addr = desc.value_int if isinstance(desc, Const) and isinstance(desc.value, int) else None
            if addr is None or addr == 0:
                continue
            itab = self.kb.go_types.itab_at(addr)
            concrete = itab[1] if itab is not None else go_type_name_at(self.project, addr)
            if concrete is None:
                continue
            holder = self._holder_of(word)
            if holder is None:
                return None
            return holder[0], holder[1], concrete, (itab[0] if itab is not None else iface) or "any"
        return None

    def _holder_of(self, word: Expression) -> tuple[Expression, Expression] | None:
        """The two-word interface value whose type word ``word`` is, and its data word: (holder, data)."""
        resolved = self._resolve_copies(word)
        if isinstance(resolved, VirtualVariable):
            hit = self._combo_of.get(resolved.varid)
            if hit is not None and hit[1] == 0 and hit[0].reg_vvars and len(hit[0].reg_vvars) == 2:
                return hit[0], hit[0].reg_vvars[1]
            definition = self._defs.get(resolved.varid)
            resolved = definition.src if definition is not None and isinstance(definition.src, Load) else resolved
        if isinstance(resolved, Load) and resolved.size == self._ws:
            base = self._resolve_copies(resolved.addr)
            holder = Load(self.manager.next_atom(), base, 2 * self._ws, resolved.endness, **resolved.tags)
            data_addr = BinaryOp(
                self.manager.next_atom(), "Add", [base, Const(self.manager.next_atom(), self._ws, base.bits)], False
            )
            return holder, Load(self.manager.next_atom(), data_addr, self._ws, resolved.endness, **resolved.tags)
        return None

    def _substitute_assertion(self, cond_block: Block, holder, data, concrete: str, iface: str) -> None:
        """Define ``val = holder.(T)`` at the check and read it where the data word was read after the check."""
        ty = self._type_named(concrete)
        pointer_shaped = _is_pointer_shaped(ty, concrete)
        size = self._ws if pointer_shaped or ty is None or not ty.size else ty.size // self.project.arch.byte_width
        oident = data.oident if isinstance(data, VirtualVariable) and data.was_reg else self._result_register()
        val = VirtualVariable(self.manager.next_atom(), self._new_varid(), size * 8, VVC.REGISTER, oident=oident)
        assertion = Call(
            self.manager.next_atom(),
            "typeassert",
            [holder],
            bits=size * 8,
            go_render="assert",
            go_assert_type=concrete,
            **self._stmt_tags_of(cond_block),
        )
        self._set_result_type(assertion, concrete, arg_type=iface)
        subst = _AssertionSubstituter(self, cond_block, data, val, pointer_shaped, size)
        for block in list(self._graph.nodes):
            # reads are guarded when their block is; a phi's entry when the block it comes from is
            subst.guarded = block is not cond_block and self._dominates(cond_block, block)
            subst.walk(block)
        if not subst.count:
            return
        stmts = list(cond_block.statements)
        pos = len(stmts) - 1 if stmts and isinstance(stmts[-1], (Jump, ConditionalJump)) else len(stmts)
        stmts.insert(pos, Assignment(self.manager.next_atom(), val, assertion, **self._stmt_tags_of(cond_block)))
        cond_block.statements = stmts

    @staticmethod
    def _stmt_tags_of(block: Block) -> dict:
        last = block.statements[-1] if block.statements else None
        return {k: v for k, v in (last.tags.items() if last is not None else ()) if not k.startswith("go_")}

    def _result_register(self) -> int:
        regs = self.project.arch.registers
        for name in ("rbx", "x1", "ebx"):
            if name in regs:
                return regs[name][0]
        return 16

    def _new_varid(self) -> int:
        varid = self.vvar_id_start
        self.vvar_id_start += 1
        return varid

    def _dominates(self, a: Block, b: Block) -> bool:
        if self._idoms is None:
            entry = next((n for n in self._graph.nodes if (n.addr, n.idx) == self.entry_node_addr), None)
            if entry is None:
                entry = next(iter(self._graph.nodes))
            self._idoms = networkx.immediate_dominators(self._graph, entry)
        node = b
        while True:
            if node is a:
                return True
            parent = self._idoms.get(node)
            if parent is None or parent is node:
                return False
            node = parent

    def _same_data_addr(self, addr: Expression, data: Load) -> bool:
        """``addr`` is the data word's address ``base + ws`` of a memory holder."""
        if not (isinstance(addr, BinaryOp) and addr.op == "Add"):
            return False
        a, b = addr.operands
        want = data.addr.operands[0]
        for x, y in ((a, b), (b, a)):
            if isinstance(y, Const) and y.value_int == self._ws and self._resolve_copies(x).likes(want):
                return True
        return False

    #
    # Rewrites
    #

    def rewrite_struct(self, expr: Struct, block: Block, stmt: Statement) -> Expression | None:
        self._stmt_tags = {k: v for k, v in stmt.tags.items() if not k.startswith("go_")}
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

    def fuse_pairs(self, exprs: list, stmt: Statement) -> list:
        """
        Adjacent (type descriptor or itab, data word) words in an argument or result list are one interface value:
        the register pair of a boxed value passed to a callee without a Go prototype, or returned.
        """
        self._stmt_tags = {k: v for k, v in stmt.tags.items() if not k.startswith("go_")}
        out = []
        i = 0
        while i < len(exprs):
            expr = exprs[i]
            if i + 1 < len(exprs) and isinstance(expr, Const) and isinstance(expr.value, int) and expr.value:
                iface = self._iface_name_at(expr.value)
                data = exprs[i + 1]
                if iface is not None and data.bits == self.project.arch.bits:
                    box = self._box(expr, data, iface)
                    if box is not None:
                        out.append(box)
                        i += 2
                        continue
            out.append(expr)
            i += 1
        return out

    def _iface_name_at(self, addr: int) -> str | None:
        """The interface a type word at ``addr`` stands for: the itab's interface, or ``any`` for a descriptor."""
        itab = self.kb.go_types.itab_at(addr)
        if itab is not None:
            return itab[0]
        return "any" if go_type_name_at(self.project, addr) is not None else None

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
            **{**{k: v for k, v in data_word.tags.items() if not k.startswith("go_")}, **self._stmt_tags},
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
        expr = definition.src if definition is not None else resolved
        if isinstance(expr, ITE):
            cond = expr.cond
            if isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE"):
                nil_side, load_side = (expr.iftrue, expr.iffalse) if cond.op == "CmpEQ" else (expr.iffalse, expr.iftrue)
                tab = self._itab_type_load(load_side)
                if tab is not None and isinstance(nil_side, Const) and nil_side.value_int == 0:
                    return tab
            return None
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
            if not (isinstance(dst, VirtualVariable) and dst.was_combo_reg and dst.reg_vvars):
                continue
            ids = [v.varid for v in dst.reg_vvars]
            if ids == wanted:
                return dst
            for i in range(len(ids) - 1):
                if ids[i : i + 2] == wanted:
                    # the pair is one result among several: the piece of the tuple at its offset
                    offset = sum(v.size for v in dst.reg_vvars[:i])
                    return Extract(
                        self.manager.next_atom(),
                        2 * self.project.arch.bits,
                        dst,
                        Const(self.manager.next_atom(), offset, self.project.arch.bits),
                        self.project.arch.memory_endness,
                    )
        return None

    def _unbox_data(self, data_word: Expression, concrete: str) -> Expression | None:
        ty = self._type_named(concrete)
        resolved = self._resolve_copies(data_word)
        if isinstance(resolved, VirtualVariable):
            # a variable holding a convT* result: the box is the call's argument
            definition = self._defs.get(resolved.varid)
            src = definition.src if definition is not None else None
            if isinstance(src, Call) and self._callee(src) in _CONVT_VALUE | _CONVT_POINTER:
                data_word = src
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
        if ty is not None and ty.size:
            size = ty.size // self.project.arch.byte_width
            # the value sits in memory: its address is the data word
            if isinstance(data_word, UnaryOp) and data_word.op == "Reference":
                operand = data_word.operand
                if isinstance(operand, VirtualVariable) and operand.size == size:
                    return operand
            if not isinstance(data_word, Const):
                return Load(
                    self.manager.next_atom(), data_word, size, self.project.arch.memory_endness, **data_word.tags
                )
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

    def _set_result_type(self, call: Call, type_name: str, arg_type: str | None = None) -> None:
        from angr.go.sim_type import GoSimTypeFunction  # pylint:disable=import-outside-toplevel

        ty = self._type_named(type_name)
        if ty is None:
            return
        args = [self._type_named(arg_type)] if arg_type is not None else []
        if any(a is None for a in args):
            args = []
        proto = GoSimTypeFunction(args, ty).with_arch(self.project.arch)
        variable_map_of(self.manager).set_prototype(call, proto)


def _only_spills(block: Block) -> bool:
    """Register moves and non-global stores only before the terminal call."""
    for stmt in block.statements[:-1]:
        if isinstance(stmt, (Label, Assignment, Jump)):
            continue
        if isinstance(stmt, Store) and not isinstance(stmt.addr, Const):
            continue
        return False
    return True


class _AssertionSubstituter(AILBlockRewriter):
    """Reads of an interface value's data word after the check become the asserted value."""

    def __init__(self, pass_: GoBoxingRewriter, cond_block: Block, data, val: VirtualVariable, pointer: bool, size):
        super().__init__(replace_phi_stmt=True)
        self._pass = pass_
        self._cond_block = cond_block
        self._data = data
        self._data_ids: set[int] = set()
        self._val = val
        self._pointer = pointer
        self._size = size
        self.count = 0
        self.guarded = False
        if isinstance(data, VirtualVariable):
            self._data_ids.add(data.varid)
        # copies of the data word, and loads of it when the holder is in memory
        for varid, definition in pass_._defs.items():
            src = definition.src
            if isinstance(src, VirtualVariable) and pass_._resolve_copies(src) is not None:
                resolved = pass_._resolve_copies(src)
                if isinstance(resolved, VirtualVariable) and resolved.varid in self._data_ids:
                    self._data_ids.add(varid)
            elif isinstance(data, Load) and isinstance(src, Load) and src.size == pass_._ws:
                if pass_._same_data_addr(src.addr, data):
                    self._data_ids.add(varid)

    def _word(self) -> Expression:
        """The data word itself: the value for pointer-shaped types, else the address of the value."""
        self.count += 1
        if self._pointer:
            return self._val
        return UnaryOp(self._pass.manager.next_atom(), "Reference", self._val, bits=self._pass.project.arch.bits)

    def _handle_VirtualVariable(self, expr_idx, expr: VirtualVariable, stmt_idx, stmt, block):
        if self.guarded and expr.varid in self._data_ids:
            return self._word()
        return expr

    def _handle_Assignment(self, stmt_idx, stmt: Assignment, block):
        # a copy of the data word is itself an alias: rewrite what it reads, never the variable it defines
        src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        if src is not stmt.src and src != stmt.src:
            return Assignment(stmt.idx, stmt.dst, src, **stmt.tags)
        return stmt

    def _handle_Phi(self, expr_idx, expr: Phi, stmt_idx, stmt, block):
        entries = []
        changed = False
        for src, vvar in expr.src_and_vvars:
            if vvar is not None and vvar.varid in self._data_ids and self._pointer:
                src_block = self._pass._block_by_addr_and_idx.get(src)
                if src_block is not None and self._pass._dominates(self._cond_block, src_block):
                    entries.append((src, self._val))
                    changed = True
                    self.count += 1
                    continue
            entries.append((src, vvar))
        return Phi(expr.idx, expr.bits, entries, **expr.tags) if changed else expr

    def _handle_Load(self, expr_idx, expr: Load, stmt_idx, stmt, block):
        if not self.guarded:
            return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
        addr = expr.addr
        # the value behind the data word: *(*T)(x.data)
        if not self._pointer and expr.size == self._size:
            inner = self._pass._resolve_copies(addr)
            if (isinstance(inner, VirtualVariable) and inner.varid in self._data_ids) or (
                isinstance(self._data, Load)
                and isinstance(inner, Load)
                and self._pass._same_data_addr(inner.addr, self._data)
            ):
                self.count += 1
                return self._val
        # the data word of a holder in memory
        if (
            isinstance(self._data, Load)
            and expr.size == self._pass._ws
            and self._pass._same_data_addr(addr, self._data)
        ):
            return self._word()
        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)


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
            new_exprs = self._pass.fuse_pairs([self._rewrite_expr(e) for e in exprs], stmt)
            if len(new_exprs) != len(exprs) or any(a is not b for a, b in zip(exprs, new_exprs)):
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
            callee = self._pass._callee(expr) or ""
            if not callee.startswith(_NO_PAIR_CALLEES):
                new_args = self._pass.fuse_pairs(new_args, self._stmt)
            if len(new_args) != len(args) or any(a is not b for a, b in zip(args, new_args)):
                return Call(expr.idx, expr.target, new_args, bits=expr.bits, **expr.tags)
            return expr
        return expr
