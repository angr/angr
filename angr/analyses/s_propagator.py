from __future__ import annotations

import contextlib
import threading
from collections import defaultdict
from collections.abc import Mapping
from typing import TYPE_CHECKING

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Insert,
    Load,
    Phi,
    Reinterpret,
    StackBaseOffset,
    Tmp,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.manager import Manager
from angr.ailment.statement import CAS, Assignment, ConditionalJump, Jump, Return, SideEffectStatement, Statement, Store
from angr.analyses.analysis import Analysis, register_analysis
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.functions import Function
from angr.utils.ail import dirty_has_side_effects, has_call
from angr.utils.ssa import (
    CONST_VVAR_LOAD_DIRTY_WHITELIST,
    CONST_VVAR_LOAD_WHITELIST,
    CONST_VVAR_TMP_WHITELIST,
    CONST_VVAR_WHITELIST,
    AILWhitelistExprTypeWalker,
    get_dirty_exprs,
    get_uses_defs,
    has_ite_expr,
    has_ite_stmt,
    has_reference_to_vvar,
    has_store_stmt_in_between_stmts,
    has_tmp_expr,
    is_const_and_vvar_assignment,
    is_const_assignment,
    is_const_vvar_load_assignment,
    is_const_vvar_load_dirty_assignment,
    is_const_vvar_tmp_assignment,
    is_phi_assignment,
    is_stack_address_expr,
    is_vvar_propagatable,
)

if TYPE_CHECKING:
    from angr.project import Project

# The cache of reusable AILBlockWalker instances, which are used by is_const_*(). The cache dict itself is
# owned by the corresponding Decompiler instance (so it is released when the Decompiler is gone). This thread-local
# points at the active Decompiler's walker cache for the duration of its run, which allows all SPropagator instances
# created during the same decompilation run share walkers.
# Make sure all walkers added to this cache are properly reset before using.
_tls = threading.local()


@contextlib.contextmanager
def sprop_cache_scope(cache: dict[tuple[type, ...], AILWhitelistExprTypeWalker]):
    """
    Install ``cache`` as the active AILBlockWalker cache for the current thread.
    """
    prev = getattr(_tls, "walker_cache", None)
    _tls.walker_cache = cache
    try:
        yield
    finally:
        _tls.walker_cache = prev


def _whitelist_walker(whitelist: tuple[type, ...]) -> AILWhitelistExprTypeWalker:
    cache = getattr(_tls, "walker_cache", None)
    if cache is None:
        # no active Decompiler scope (e.g. standalone SPropagator use); fall back to a throwaway walker
        return AILWhitelistExprTypeWalker(whitelist)
    walker = cache.get(whitelist)
    if walker is None:
        walker = AILWhitelistExprTypeWalker(whitelist)
        cache[whitelist] = walker
    return walker


_INF = float("inf")

# flag computations the ccall rewriters emit as calls; they touch no memory
_FLAG_HELPER_CALLS = frozenset({"__CFADD__", "__OFADD__", "__OFSUB__", "__OFUMUL__", "__OFSMUL__", "__readeflags"})

# functions whose result points into the heap (or is NULL), never into a global object
_ALLOCATOR_CALLS = frozenset(
    {
        "malloc",
        "calloc",
        "realloc",
        "reallocarray",
        "strdup",
        "strndup",
        "xmalloc",
        "xzalloc",
        "xcalloc",
        "xrealloc",
        "xnmalloc",
        "xnrealloc",
        "x2realloc",
        "x2nrealloc",
        "xcharalloc",
        "xmemdup",
        "xstrdup",
        "xstrndup",
        "ximalloc",
        "xicalloc",
        "xirealloc",
        "_Znwm",
        "_Znam",
        "_Znwj",
        "_Znaj",
    }
)


def _frame_addr(expr: Expression, sp_offsets: tuple[int, ...], sbo_vvars: Mapping[int, int] | None = None):
    """
    (offset, base) when `expr` is an address into the frame: offset is None when it is not a known constant, base is the
    frame offset it is indexed from (None: unknown). None when `expr` is not a frame address.
    """
    if isinstance(expr, StackBaseOffset):
        return expr.offset, expr.offset
    if isinstance(expr, Convert):
        return _frame_addr(expr.operand, sp_offsets, sbo_vvars)
    if isinstance(expr, UnaryOp):
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack:
            return expr.operand.stack_offset, expr.operand.stack_offset
        return None
    if isinstance(expr, VirtualVariable):
        if expr.was_reg and expr.reg_offset in sp_offsets:
            return None, None
        if sbo_vvars is not None and expr.varid in sbo_vvars:
            off = sbo_vvars[expr.varid]
            return off, off
        return None
    if isinstance(expr, BinaryOp) and expr.op in ("Add", "Sub"):
        op0, op1 = expr.operands
        a0 = _frame_addr(op0, sp_offsets, sbo_vvars)
        if a0 is not None:
            if isinstance(op1, Const) and isinstance(op1.value, int) and a0[0] is not None:
                delta = op1.value if expr.op == "Add" else -op1.value
                if op1.value >= 1 << (op1.bits - 1):
                    delta = delta - (1 << op1.bits) if expr.op == "Add" else delta + (1 << op1.bits)
                return a0[0] + delta, a0[1]
            return None, a0[1]
        if expr.op == "Add":
            a1 = _frame_addr(op1, sp_offsets, sbo_vvars)
            if a1 is not None:
                if isinstance(op0, Const) and isinstance(op0.value, int) and a1[0] is not None:
                    delta = op0.value - (1 << op0.bits) if op0.value >= 1 << (op0.bits - 1) else op0.value
                    return a1[0] + delta, a1[1]
                return None, a1[1]
    return None


def _addr_region(addr: tuple[int | None, int | None], size: int | None) -> tuple[float, float]:
    """
    The frame bytes an access (size given) or an escaped address (size None) may touch. An escaped address reaches up to
    the end of its object; no object straddles the frame base, which separates locals from incoming arguments.
    """
    offset, base = addr
    if offset is not None:
        if size is not None:
            return offset, offset + size
        return (offset, 0) if offset < 0 else (offset, _INF)
    if base is None:
        return -_INF, _INF
    return (-_INF, 0) if base < 0 else (0, _INF)


class _FrameEscapeCollector(AILBlockViewer):
    """
    Collects the frame addresses a statement lets escape (every one that is not the address of a memory access or a
    stack or frame pointer update), and whether it may write memory: a call (other than to a pure helper) may write any
    global or heap location and any frame slot it was given the address of.
    """

    def __init__(self, sp_offsets: tuple[int, ...], pure_calls: frozenset[str] = frozenset()):
        super().__init__()
        self.sp_offsets = sp_offsets
        self.pure_calls = pure_calls
        self.escaped: list[tuple[int | None, int | None]] = []
        self.writes = False
        self._in_addr = 0

    def reset(self) -> None:
        self.escaped.clear()
        self.writes = False
        self._in_addr = 0

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if not self._in_addr:
            addr = _frame_addr(expr, self.sp_offsets)
            if addr is not None:
                self.escaped.append(addr)
                return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _walk_addr(self, addr, stmt_idx, stmt, block):
        self._in_addr += 1
        self._handle_expr(0, addr, stmt_idx, stmt, block)
        self._in_addr -= 1

    def _handle_Assignment(self, stmt_idx, stmt, block):
        if isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg and stmt.dst.reg_offset in self.sp_offsets:
            self._walk_addr(stmt.src, stmt_idx, stmt, block)
        else:
            self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx, stmt, block):
        self._walk_addr(stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        if stmt.guard is not None:
            self._handle_expr(2, stmt.guard, stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx, stmt, block):
        self._walk_addr(stmt.addr, stmt_idx, stmt, block)
        for idx, e in enumerate((stmt.data_lo, stmt.data_hi, stmt.expd_lo, stmt.expd_hi)):
            if e is not None:
                self._handle_expr(idx + 1, e, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        self._walk_addr(expr.addr, stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op.startswith("Cmp"):
            # a comparison result does not carry the address
            self._in_addr += 1
            super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)
            self._in_addr -= 1
        else:
            super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        # flag computations are pure and do not carry the address
        self._in_addr += 1
        super()._handle_VEXCCallExpression(expr_idx, expr, stmt_idx, stmt, block)
        self._in_addr -= 1

    def _handle_SideEffectStatement(self, stmt_idx, stmt, block):
        self.writes = True
        super()._handle_SideEffectStatement(stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if not (isinstance(expr.target, str) and expr.target in self.pure_calls):
            self.writes = True
        in_addr, self._in_addr = self._in_addr, 0
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)
        self._in_addr = in_addr

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if dirty_has_side_effects(expr):
            self.writes = True
        in_addr, self._in_addr = self._in_addr, 0
        super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)
        self._in_addr = in_addr


class _FrameReadCollector(AILBlockViewer):
    """Collects the Loads and stack-variable reads of an expression."""

    def __init__(self):
        super().__init__()
        self.loads: list[Load] = []
        self.stack_vvars: list[VirtualVariable] = []

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        self.loads.append(expr)
        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.was_stack:
            self.stack_vvars.append(expr)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op == "Reference":
            # an address, not a read
            return None
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)


def is_const_arm_ite(expr: Expression) -> bool:
    """``c ? K1 : K2``: a devirtualized VM's branch select; duplicating it into one statement is what lets the
    constant arithmetic around it fold."""
    return isinstance(expr, ITE) and isinstance(expr.iftrue, Const) and isinstance(expr.iffalse, Const)


class SPropagatorModel:
    """
    The SPropagator model that stores replacements for virtual variables.
    """

    def __init__(self):
        self.replacements: Mapping[AILCodeLocation, Mapping[Expression, Expression]] = {}
        # store vvars that are definitely dead (but usually not removed by default because they are stack variables)
        self.dead_vvar_ids: set[int] = set()
        # (use location, varid) of replacements that ignore the expression-depth guard: a definition moving into its
        # only use, or a shallow VM definition copied into the one statement that uses it
        self.depth_exempt: set[tuple[AILCodeLocation, int]] = set()


class SPropagator:
    """
    Constant and expression propagation that only supports SSA AIL graphs.

    Deliberately not an :class:`Analysis` for better speed.
    """

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        project: Project,
        subject: Block | Function,
        *,
        ail_manager: Manager,
        func_graph: networkx.DiGraph | None = None,
        only_consts: bool = True,
        stack_pointer_tracker=None,
        func_args: set[VirtualVariable] | None = None,
        func_addr: int | None = None,
        stack_arg_offsets: set[int] | None = None,
        call_sp_adjustments: Mapping[int, int | None] | None = None,
    ):
        self.project = project
        self.kb = project.kb

        if isinstance(subject, Block):
            self.block = subject
            self.func = None
            self.mode = "block"
        elif isinstance(subject, Function):
            self.block = None
            self.func = subject
            self.mode = "function"
        else:
            raise TypeError(f"Unsupported subject type {type(subject)}")

        self.func_graph = func_graph
        self.func_addr = func_addr
        self.func_args = func_args
        self.only_consts = only_consts
        self._sp_tracker = stack_pointer_tracker
        if call_sp_adjustments is None and stack_pointer_tracker is not None:
            call_sp_adjustments = getattr(stack_pointer_tracker, "call_sp_adjustments", None)
        # call instruction -> sp change from the end of the instruction to its return site (None: unknown)
        self._call_sp_adjustments = call_sp_adjustments or {}
        self._ail_manager = ail_manager
        self.stack_arg_offsets = stack_arg_offsets
        # a devirtualized VM body keeps its operand-stack pointer in a stack slot; nothing
        # downstream can see the slots it addresses until that pointer is folded into its uses
        self._propagate_stack_addresses = getattr(project, "vm_deobfuscation", False)

        bp_as_gpr = False
        the_func = None
        if self.func is not None:
            the_func = self.func
        else:
            if self.func_addr is not None:
                with contextlib.suppress(KeyError):
                    the_func = self.kb.functions.get_by_addr(self.func_addr)
        if the_func is not None:
            bp_as_gpr = the_func.info.get("bp_as_gpr", False)
        self._bp_as_gpr = bp_as_gpr
        # registers whose values are frame addresses by construction
        self._frame_reg_offsets: tuple[int, ...] = tuple(
            off
            for off in (project.arch.sp_offset, None if bp_as_gpr else project.arch.bp_offset)
            if off is not None
        )
        self._frame_escape_sites: dict[tuple[int, int], list] | None = None
        self._frame_writers: dict[tuple[int, int], list[int]] = {}
        self._sbo_vvars: dict[int, int] | None = None
        self._nonglobal_ptr_vvars: set[int] | None = None
        self._stack_slot_defs: dict[tuple[int, int | None], list[tuple[int, float, float]]] | None = None

        # output
        self.model = SPropagatorModel()

        self._analyze()

    @property
    def replacements(self):
        return self.model.replacements

    @property
    def dead_vvar_ids(self):
        return self.model.dead_vvar_ids

    def _stack_base_offset_at_use(
        self,
        vvar_id: int,
        useloc: AILCodeLocation,
        reg_offset: int,
        vvar_deflocs: Mapping[int, tuple[VirtualVariable, AILCodeLocation]],
        blocks: Mapping[tuple[int, int], Block],
    ) -> int | None:
        """
        Stack offset held by an sp/bp vvar at one of its uses. An SSA vvar holds what its definition wrote, which is
        not necessarily the offset before the use's instruction: the use may have been propagated past a later sp
        update (`test byte [esp+1], 0x41; lea esp, [esp+4]; jne`). So take the offset after the defining instruction,
        at the entry of the defining block for a phi, or at the entry of the use's block (or function) when the vvar is
        defined outside the analyzed blocks. An unknown offset after the defining instruction or at the entry of a
        phi's block stays unknown. Phi sources and definitions that do not end their instruction's writes of the
        register (`leave` writes esp twice) fall back to the offset before the use's instruction.
        """
        assert self._sp_tracker is not None
        use_ins = useloc.ins_addr
        use_block = blocks.get((useloc.block_addr, useloc.block_idx))
        if use_block is None or is_phi_assignment(use_block.statements[useloc.stmt_idx]):
            return self._sp_tracker.offset_before(use_ins, reg_offset)

        sb_offset = None
        def_entry = vvar_deflocs.get(vvar_id)
        if def_entry is None or def_entry[1].is_extern:
            if self.mode == "function" and self.func_addr is not None:
                # live-in at function entry
                sb_offset = self._sp_tracker.offset_before(self.func_addr, reg_offset)
            else:
                # defined in another block: live-in at the entry of the use's block
                entry_ins = next(
                    (stmt.tags["ins_addr"] for stmt in use_block.statements if "ins_addr" in stmt.tags), None
                )
                if entry_ins is not None:
                    sb_offset = self._sp_tracker.offset_before(entry_ins, reg_offset)
        else:
            defloc = def_entry[1]
            def_ins = defloc.ins_addr
            def_block = blocks.get((defloc.block_addr, defloc.block_idx))
            if def_block is not None and is_phi_assignment(def_block.statements[defloc.stmt_idx]):
                # a phi holds the offset at the entry of its block, wherever the use was propagated to
                entry_ins = next(
                    (stmt.tags["ins_addr"] for stmt in def_block.statements if "ins_addr" in stmt.tags), None
                )
                return None if entry_ins is None else self._sp_tracker.offset_before(entry_ins, reg_offset)
            if (
                def_block is not None
                and def_ins is not None
                and def_ins != use_ins
                and self._is_last_reg_write_in_insn(def_block, defloc.stmt_idx, def_ins, reg_offset)
            ):
                # an unknown offset stays unknown: a later instruction may hold another version of the register
                return self._sp_tracker.offset_after(def_ins, reg_offset)
        if sb_offset is not None:
            return sb_offset
        return self._sp_tracker.offset_before(use_ins, reg_offset)

    def _find_call_sp_defs(
        self,
        vvar_deflocs: Mapping[int, tuple[VirtualVariable, AILCodeLocation]],
        blocks: Mapping[tuple[int, int], Block],
    ) -> dict[int, tuple[int, int | None]]:
        """
        sp variables defined by the last sp write of a call instruction (the return-address push), mapped to that
        instruction and the sp change until the call returns (ret pop + callee cleanup; None if unknown). SSA gives a
        call no sp definition, so uses after the call read such a variable although the callee has moved sp since.
        """
        sp_offset = self.project.arch.sp_offset
        out: dict[int, tuple[int, int | None]] = {}
        for vvar_id, (vvar, defloc) in vvar_deflocs.items():
            if defloc.is_extern or not vvar.was_reg or vvar.oident != sp_offset:
                continue
            block = blocks.get((defloc.block_addr, defloc.block_idx))
            if block is None:
                continue
            stmt = block.statements[defloc.stmt_idx]
            ins = stmt.tags.get("ins_addr")
            if ins is None or not self._is_last_reg_write_in_insn(block, defloc.stmt_idx, ins, sp_offset):
                continue
            if stmt.tags.get("sp_after_call"):
                # already holds sp after the call (StackDeadStoreEliminator)
                continue
            if ins in self._call_sp_adjustments:
                out[vvar_id] = ins, self._call_sp_adjustments[ins]
                continue
            for later in block.statements[defloc.stmt_idx + 1 :]:
                if later.tags.get("ins_addr") != ins:
                    break
                if has_call(later):
                    out[vvar_id] = ins, None
                    break
        return out

    @staticmethod
    def _ins_addr_at(blocks: Mapping[tuple[int, int], Block], loc: AILCodeLocation) -> int | None:
        block = blocks.get((loc.block_addr, loc.block_idx))
        if block is None:
            return None
        return block.statements[loc.stmt_idx].tags.get("ins_addr")

    def _value_after_call(self, value: Expression, adjustment: int | None) -> Expression | None:
        if adjustment is None:
            return None
        if adjustment == 0:
            return value
        if isinstance(value, StackBaseOffset):
            return StackBaseOffset(self._ail_manager.next_atom(), value.bits, value.offset + adjustment, **value.tags)
        if isinstance(value, Const) and isinstance(value.value, int):
            mask = (1 << value.bits) - 1
            return Const(self._ail_manager.next_atom(), (value.value + adjustment) & mask, value.bits, **value.tags)
        return BinaryOp(
            self._ail_manager.next_atom(),
            "Add",
            [value, Const(self._ail_manager.next_atom(), adjustment, value.bits)],
            False,
            bits=value.bits,
            **value.tags,
        )

    @staticmethod
    def _is_last_reg_write_in_insn(block: Block, stmt_idx: int, ins_addr: int, reg_offset: int) -> bool:
        stmt = block.statements[stmt_idx]
        if not isinstance(stmt, Assignment) or isinstance(stmt.src, Phi):
            return False
        for later in block.statements[stmt_idx + 1 :]:
            if later.tags.get("ins_addr") != ins_addr:
                break
            if (
                isinstance(later, Assignment)
                and isinstance(later.dst, VirtualVariable)
                and later.dst.was_reg
                and later.dst.reg_offset == reg_offset
            ):
                return False
        return True

    @staticmethod
    def _address_taken(vvar: VirtualVariable, uselocs, blocks) -> bool:
        """Does a use take this stack variable's address? Then it may be written through that address."""
        return vvar.was_stack and any(
            has_reference_to_vvar(blocks[(loc.block_addr, loc.block_idx)].statements[loc.stmt_idx], vvar.varid)
            for loc in uselocs
        )

    def _propagate_const_stack_slot(
        self, vvar, defloc, blocks, vvar_deflocs, vvar_uselocs, replacements, vvarid_to_vvar, const_vvars
    ) -> None:
        """
        A devirtualized VM body: copy an integer constant held in a stack slot into every non-phi use. VM entries push
        the encrypted VIP onto the stack and duplicated entry blocks read it, so it has several uses.
        """
        stmt = blocks[(defloc.block_addr, defloc.block_idx)].statements[defloc.stmt_idx]
        r, v = is_const_assignment(stmt, only_consts=True)
        if not (
            r
            and isinstance(v, Const)
            and isinstance(v.value, int)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.varid == vvar.varid
        ):
            return
        uses = vvar_uselocs.get(vvar.varid)
        if not uses:
            return
        uselocs = {loc for _, loc in uses}
        if self._address_taken(vvar, uselocs, blocks):
            return
        slot_defs = self._slot_defs(vvar_deflocs, blocks)
        # a use is reached by the constant only if no call may write the slot through an escaped address and no other
        # frame write may reach it on the way (a loop update stack SSA did not route through a phi, a store through
        # another slot's address)
        reached = {
            loc
            for loc in uselocs
            if not self._call_may_clobber_frame_read(vvar.varid, stmt.dst, defloc, loc, blocks, const_vvars)
            and not self._slot_redefined_between(blocks, defloc, loc, vvar, slot_defs)
        }
        if not reached:
            return
        vvarid_to_vvar[vvar.varid] = vvar
        if reached == uselocs:
            const_vvars[vvar.varid] = v
        for vvar_at_use, useloc in uses:
            if useloc in reached and not is_phi_assignment(
                blocks[(useloc.block_addr, useloc.block_idx)].statements[useloc.stmt_idx]
            ):
                self.replace(replacements, useloc, vvar_at_use, v)

    def _slot_defs(self, vvar_deflocs, blocks) -> dict[tuple[int, int | None], list[tuple[int, float, float]]]:
        """
        Per block: (stmt idx, start, end) of every frame write -- a stack variable definition, or a store to a frame
        address stack SSA did not resolve (through another slot's address, or an unknown frame pointer).
        """
        if self._stack_slot_defs is None:
            defs = defaultdict(list)
            for v, loc in vvar_deflocs.values():
                if v.was_stack and not loc.is_extern:
                    key = (loc.block_addr, loc.block_idx)
                    defs[key].append((loc.stmt_idx, v.stack_offset, v.stack_offset + v.size))
            for key, block in blocks.items():
                for idx, stmt in enumerate(block.statements):
                    if isinstance(stmt, Store):
                        addr = _frame_addr(stmt.addr, self._frame_reg_offsets)
                        if addr is not None:
                            defs[key].append((idx, *_addr_region(addr, stmt.size)))
            self._stack_slot_defs = defs
        return self._stack_slot_defs

    def _slot_redefined_between(self, blocks, defloc, useloc, vvar, slot_defs) -> bool:
        """Whether some frame write overlapping `vvar` lies on a path from defloc to useloc."""
        assert self.func_graph is not None
        lo, hi = vvar.stack_offset, vvar.stack_offset + vvar.size
        def_block = blocks[(defloc.block_addr, defloc.block_idx)]
        queue = [(blocks[(useloc.block_addr, useloc.block_idx)], True)]
        visited = set()
        while queue:
            block, initial = queue.pop()
            if not initial:
                if block in visited:
                    continue
                visited.add(block)
            end = useloc.stmt_idx if initial else len(block.statements)
            start = defloc.stmt_idx + 1 if block is def_block else 0
            for idx, dlo, dhi in slot_defs.get((block.addr, block.idx), ()):
                if start <= idx < end and dlo < hi and lo < dhi:
                    return True
            if block is def_block:
                continue
            queue.extend((pred, False) for pred in self.func_graph.predecessors(block) if pred not in visited)
        return False

    def _frame_info(self, blocks: Mapping[tuple[int, int], Block]):
        """
        Per block: [(stmt idx, frame region)] of the frame addresses that escape there, and the indices of the
        statements that may write memory (calls other than pure intrinsics, dirty helpers with side effects). Computed
        once.
        """
        if self._frame_escape_sites is None:
            sites = defaultdict(list)
            writers = {}
            from angr.analyses.decompiler.block_walkers import PURE_INTRINSIC_CALLS  # pylint:disable=import-outside-toplevel

            collector = _FrameEscapeCollector(self._frame_reg_offsets, PURE_INTRINSIC_CALLS | _FLAG_HELPER_CALLS)
            for key, block in blocks.items():
                idxs = []
                for idx, stmt in enumerate(block.statements):
                    collector.reset()
                    collector.walk_statement(stmt, block, idx)
                    for addr in collector.escaped:
                        sites[key].append((idx, _addr_region(addr, None)))
                    if collector.writes:
                        idxs.append(idx)
                if idxs:
                    writers[key] = idxs
            self._frame_escape_sites = sites
            self._frame_writers = writers
        return self._frame_escape_sites, self._frame_writers

    def _ranges_between(
        self, blocks: Mapping[tuple[int, int], Block], defloc: AILCodeLocation, useloc: AILCodeLocation, varid: int
    ):
        """
        (block, start, end): the statement ranges on some path from defloc to useloc, including those after the use
        when a loop re-executes it.
        """
        assert self.func_graph is not None
        use_block = blocks[(useloc.block_addr, useloc.block_idx)]
        def_block = blocks[(defloc.block_addr, defloc.block_idx)]
        visited = set()
        use_stmt = use_block.statements[useloc.stmt_idx]
        if is_phi_assignment(use_stmt):
            # a phi reads the variable at the end of the predecessors it comes from
            assert isinstance(use_stmt, Assignment) and isinstance(use_stmt.src, Phi)
            queue = [
                (blocks[src], False)
                for src, vvar in use_stmt.src.src_and_vvars
                if vvar is not None and vvar.varid == varid and src in blocks
            ]
        else:
            queue = [(use_block, True)]
        while queue:
            block, initial = queue.pop()
            if initial:
                end = useloc.stmt_idx
            else:
                if block in visited:
                    continue
                visited.add(block)
                end = len(block.statements)
            start = defloc.stmt_idx + 1 if block is def_block else 0
            yield block, start, end
            if block is def_block:
                continue
            for pred in self.func_graph.predecessors(block):
                if pred not in visited:
                    queue.append((pred, False))

    def _memory_writers_between(
        self, blocks: Mapping[tuple[int, int], Block], defloc: AILCodeLocation, useloc: AILCodeLocation, varid: int
    ) -> list[tuple[Block, int]]:
        """Calls on some path from defloc to useloc, including those after the use when a loop re-executes it."""
        _, writers = self._frame_info(blocks)
        out = []
        for block, start, end in self._ranges_between(blocks, defloc, useloc, varid):
            for i in writers.get((block.addr, block.idx), ()):
                if start <= i < end:
                    out.append((block, i))
        return out

    def _drop_clobbered_memory_reads(self, replacements, vvar_deflocs, blocks, const_vvars) -> None:
        """A moved memory read must not cross a call that may write what it reads."""
        if not self._frame_info(blocks)[1]:
            return
        for useloc, use_reps in replacements.items():
            for vvar_at_use, value in list(use_reps.items()):
                if isinstance(value, (Const, StackBaseOffset)) or not isinstance(vvar_at_use, VirtualVariable):
                    continue
                varid = vvar_at_use.varid
                def_entry = vvar_deflocs.get(varid)
                if def_entry is None or def_entry[1].is_extern:
                    continue
                if self._call_may_clobber_read(varid, value, def_entry[1], useloc, blocks, const_vvars):
                    del use_reps[vvar_at_use]

    def _call_may_clobber_read(self, varid, src, defloc, useloc, blocks, const_vvars) -> bool:
        args = varid, src, defloc, useloc, blocks, const_vvars
        return self._call_may_clobber_nonframe_read(*args) or self._call_may_clobber_frame_read(*args)

    def _frame_addr_vvars(self, const_vvars: Mapping[int, Expression]) -> dict[int, int]:
        """vvars holding a frame address"""
        if self._sbo_vvars is None:
            self._sbo_vvars = {k: v.offset for k, v in const_vvars.items() if isinstance(v, StackBaseOffset)}
        return self._sbo_vvars

    def _call_may_clobber_nonframe_read(
        self,
        varid: int,
        src: Expression,
        defloc: AILCodeLocation,
        useloc: AILCodeLocation,
        blocks: Mapping[tuple[int, int], Block],
        const_vvars: Mapping[int, Expression],
    ) -> bool:
        """
        Whether moving `src` from defloc to useloc lets a Load outside the frame (a global, the heap) cross a call: any
        call may write any such location.
        """
        reads = _FrameReadCollector()
        reads.walk_expression(src)
        if not reads.loads:
            return False
        sbo_vvars = self._frame_addr_vvars(const_vvars)
        if all(_frame_addr(load.addr, self._frame_reg_offsets, sbo_vvars) is not None for load in reads.loads):
            return False
        return bool(self._memory_writers_between(blocks, defloc, useloc, varid))

    def _call_may_clobber_frame_read(
        self,
        varid: int,
        src: Expression,
        defloc: AILCodeLocation,
        useloc: AILCodeLocation,
        blocks: Mapping[tuple[int, int], Block],
        const_vvars: Mapping[int, Expression],
    ) -> bool:
        """
        Whether moving `src`, the definition of `varid`, from defloc to useloc lets one of its frame reads (a Load, or
        a stack variable whose single SSA version does not see writes through its address) cross a call that may write
        the slot: one reached by an escaped address of the slot's object.
        """
        reads = _FrameReadCollector()
        reads.walk_expression(src)
        if not reads.loads and not reads.stack_vvars:
            return False
        regions = [(v.stack_offset, v.stack_offset + v.size) for v in reads.stack_vvars]
        if reads.loads:
            sbo_vvars = self._frame_addr_vvars(const_vvars)
            for load in reads.loads:
                addr = _frame_addr(load.addr, self._frame_reg_offsets, sbo_vvars)
                if addr is not None:
                    regions.append(_addr_region(addr, load.size))
        if not regions:
            return False
        escape_sites = {}
        for key, sites in self._frame_info(blocks)[0].items():
            idxs = [idx for idx, (lo, hi) in sites if any(lo < rhi and rlo < hi for rlo, rhi in regions)]
            if idxs:
                escape_sites[key] = min(idxs)
        if not escape_sites:
            return False
        writers = self._memory_writers_between(blocks, defloc, useloc, varid)
        if not writers:
            return False
        for block, idx in writers:
            first = escape_sites.get((block.addr, block.idx))
            if first is not None and first <= idx:
                return True
        # an escape in a block from which some writer is reachable
        assert self.func_graph is not None
        seen = set()
        queue = [pred for block, _ in writers for pred in self.func_graph.predecessors(block)]
        while queue:
            block = queue.pop()
            if block in seen:
                continue
            seen.add(block)
            if (block.addr, block.idx) in escape_sites:
                return True
            queue.extend(self.func_graph.predecessors(block))
        return False

    def _is_allocator_call(self, expr) -> bool:
        if not isinstance(expr, Call):
            return False
        target = expr.target
        if isinstance(target, Const) and isinstance(target.value, int):
            func = None
            with contextlib.suppress(KeyError):
                func = self.kb.functions.get_by_addr(target.value)
            target = func.name if func is not None else None
        return isinstance(target, str) and target in _ALLOCATOR_CALLS

    def _ptr_alternatives(self, expr: Expression, sbo_vvars: Mapping[int, int]) -> list[frozenset[int]]:
        """
        Ways `expr` may be a pointer into the frame or the heap: each alternative is a set of vvars that must all hold
        such pointers (empty: a frame address). Pointer arithmetic is assumed to stay within its object.
        """
        if _frame_addr(expr, self._frame_reg_offsets, sbo_vvars) is not None:
            return [frozenset()]
        if isinstance(expr, VirtualVariable):
            # a stack variable's SSA value may miss writes through its escaped address
            return [] if expr.was_stack else [frozenset((expr.varid,))]
        if isinstance(expr, Convert):
            return self._ptr_alternatives(expr.operand, sbo_vvars)
        if isinstance(expr, BinaryOp) and expr.op in ("Add", "Sub"):
            alts = self._ptr_alternatives(expr.operands[0], sbo_vvars)
            if expr.op == "Add":
                alts = alts + self._ptr_alternatives(expr.operands[1], sbo_vvars)
            return alts
        return []

    def _nonglobal_ptrs(self, vvar_deflocs, blocks, const_vvars) -> set[int]:
        """
        vvars that hold a pointer into the frame or into memory returned by an allocator (greatest fixpoint, so that
        loop-carried pointers qualify). Neither ever points into a global object.
        """
        if self._nonglobal_ptr_vvars is not None:
            return self._nonglobal_ptr_vvars
        sbo_vvars = self._frame_addr_vvars(const_vvars)
        alts: dict[int, list[frozenset[int]]] = {}
        for varid, (_, defloc) in vvar_deflocs.items():
            if defloc.is_extern:
                continue
            stmt = blocks[(defloc.block_addr, defloc.block_idx)].statements[defloc.stmt_idx]
            if isinstance(stmt, SideEffectStatement):
                if (
                    isinstance(stmt.ret_expr, VirtualVariable)
                    and stmt.ret_expr.varid == varid
                    and self._is_allocator_call(stmt.expr)
                ):
                    alts[varid] = [frozenset()]
                continue
            if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid == varid):
                continue
            if self._is_allocator_call(stmt.src):
                alts[varid] = [frozenset()]
            elif isinstance(stmt.src, Phi):
                srcs = [v.varid if v is not None else None for _, v in stmt.src.src_and_vvars]
                if srcs and None not in srcs:
                    alts[varid] = [frozenset(srcs)]
            else:
                a = self._ptr_alternatives(stmt.src, sbo_vvars)
                if a:
                    alts[varid] = a
        result = set(alts)
        changed = True
        while changed:
            changed = False
            for varid in list(result):
                if not any(alt <= result for alt in alts[varid]):
                    result.discard(varid)
                    changed = True
        self._nonglobal_ptr_vvars = result
        return result

    def _global_may_be_written(
        self,
        blocks: Mapping[tuple[int, int], Block],
        varid: int,
        gv_addr: int,
        gv_size: int,
        defloc: AILCodeLocation,
        useloc: AILCodeLocation,
        vvar_deflocs,
        const_vvars,
    ) -> bool:
        """
        Whether a Store or CAS on some path from defloc to useloc may write the global [gv_addr, gv_addr + gv_size): one
        to an overlapping constant address, or through a pointer not proven to point into the frame or the heap.
        """
        for block, start, end in self._ranges_between(blocks, defloc, useloc, varid):
            for idx in range(start, end):
                stmt = block.statements[idx]
                if not isinstance(stmt, (Store, CAS)):
                    continue
                addr = stmt.addr
                if isinstance(addr, Const) and isinstance(addr.value, int):
                    if addr.value < gv_addr + gv_size and gv_addr < addr.value + stmt.size:
                        return True
                    continue
                ng = self._nonglobal_ptrs(vvar_deflocs, blocks, const_vvars)
                if not any(alt <= ng for alt in self._ptr_alternatives(addr, self._frame_addr_vvars(const_vvars))):
                    return True
        return False

    def _analyze(self):
        blocks: dict[tuple[int, int], Block]
        match self.mode:
            case "block":
                assert self.block is not None
                blocks = {(self.block.addr, self.block.idx): self.block}
            case "function":
                assert self.func_graph is not None
                blocks = {(block.addr, block.idx): block for block in self.func_graph}
            case _:
                raise NotImplementedError

        # Combined pass: vvar deflocs + vvar uselocs + tmp deflocs +
        # tmp uselocs in a single walker traversal per block (vs the
        # legacy 4 separate helper calls, two of which spun their own
        # AILBlockViewer to walk the same blocks).
        vvar_deflocs, vvar_uselocs, _tmp_deflocs_cached, _tmp_uselocs_cached = get_uses_defs(blocks.values())
        call_sp_defs = self._find_call_sp_defs(vvar_deflocs, blocks)

        # update vvar_deflocs using function arguments
        if self.func_args:
            for func_arg in self.func_args:
                vvar_deflocs[func_arg.varid] = func_arg, AILCodeLocation.make_extern(func_arg.varid)

        # find all ret sites and indirect jump sites
        retsites: set[tuple[int, int | None, int]] = set()
        jumpsites: set[tuple[int, int | None, int]] = set()
        for bb in blocks.values():
            if bb.statements:
                if isinstance(bb.statements[-1], Return):
                    retsites.add((bb.addr, bb.idx, len(bb.statements) - 1))
                elif isinstance(bb.statements[-1], Jump):
                    jumpsites.add((bb.addr, bb.idx, len(bb.statements) - 1))

        replacements = defaultdict(dict)

        # find constant and other propagatable assignments
        vvarid_to_vvar: dict[int, VirtualVariable] = {}
        const_vvars: dict[int, Const | StackBaseOffset] = {}
        phi_varids: dict[int, set[int | None]] = {}  # mapping from phi_varid to source var IDs
        for vvar_id, (vvar, defloc) in vvar_deflocs.items():
            if not vvar.was_reg and not vvar.was_parameter and not vvar.was_tmp:
                if (
                    self.mode == "function"
                    and self._propagate_stack_addresses
                    and vvar.was_stack
                    and not defloc.is_extern
                ):
                    self._propagate_const_stack_slot(
                        vvar, defloc, blocks, vvar_deflocs, vvar_uselocs, replacements, vvarid_to_vvar, const_vvars
                    )
                continue

            vvarid_to_vvar[vvar_id] = vvar

            if defloc.is_extern:
                continue

            assert defloc.block_addr is not None
            assert defloc.stmt_idx is not None

            block = blocks[(defloc.block_addr, defloc.block_idx)]
            stmt = block.statements[defloc.stmt_idx]
            if isinstance(stmt, Assignment) and not (
                isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid == vvar_id
            ):
                # come back later, this is not the def you're looking for
                continue
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Insert):
                # Do not propagate Inserts
                # if this is not acceptable, just make sure we don't proagate inserts into the base of other inserts...
                continue
            if is_phi_assignment(stmt):
                assert isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)
                phi_varids[vvar_id] = {
                    src_vvar.varid if src_vvar is not None else None for _, src_vvar in stmt.src.src_and_vvars
                }
            r, v = is_const_assignment(stmt)
            const_value = v
            if r and v is not None and v.tags.get("always_propagate", False):
                # constant propagation
                pass
            elif (
                self.stack_arg_offsets is not None
                and isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and stmt.dst.stack_offset in self.stack_arg_offsets
                and not isinstance(stmt.src, (Phi, Call))
            ):
                # force propagation of stack variables to callsites; we set v to stmt.src, but const_value stays None
                # (never a call: a result slot in the argument area must not re-issue the call at every use)
                r = True
                v = stmt.src
            elif not vvar.was_reg and not vvar.was_parameter and not (r and vvar.was_tmp):
                # a constant stays a constant wherever a former tmp is read
                continue

            vvarid_to_vvar[vvar_id] = vvar

            if r:
                # replace wherever it's used
                assert v is not None
                if const_value is not None:
                    const_vvars[vvar_id] = const_value
                for vvar_at_use, useloc in vvar_uselocs[vvar_id]:
                    self.replace(replacements, useloc, vvar_at_use, v)

        # function mode only
        if self.mode == "function":
            assert self.func_graph is not None
            # find phi assignments whose source vvars are all constants/stackptrs
            # iterate until it reaches a fixed point
            changed = True
            while changed:
                changed = False
                for vvar_id, src_varids in phi_varids.items():
                    vvar, defloc = vvar_deflocs[vvar_id]
                    if vvar_id in const_vvars:
                        continue
                    if defloc.is_extern:
                        continue

                    assert defloc.block_addr is not None
                    assert defloc.stmt_idx is not None

                    if not vvar.was_reg and not vvar.was_parameter:
                        continue
                    if None in src_varids:
                        continue

                    expanded_src_varids = self._nonphi_src_varids(src_varids, phi_varids)
                    if None not in expanded_src_varids and all(varid in const_vvars for varid in expanded_src_varids):
                        all_int_src_varids: set[int] = {varid for varid in expanded_src_varids if varid is not None}
                        # a phi reads its sources at the end of their blocks, i.e., after a call
                        src_consts = {
                            varid: self._value_after_call(const_vvars[varid], call_sp_defs[varid][1])
                            if varid in call_sp_defs
                            else const_vvars[varid]
                            for varid in all_int_src_varids
                        }
                        if any(v is None for v in src_consts.values()):
                            continue
                        src_values = {
                            (True, v.value) if isinstance(v, Const) else (False, v.offset) for v in src_consts.values()
                        }
                        if len(src_values) == 1:
                            # replace it!
                            const_value = src_consts[next(iter(all_int_src_varids))]
                            const_vvars[vvar.varid] = const_value
                            for vvar_at_use, useloc in vvar_uselocs[vvar.varid]:
                                self.replace(replacements, useloc, vvar_at_use, const_value)
                            changed = True

            ret_or_jump_sites = retsites | jumpsites
            for vvar_id, (vvar, defloc) in vvar_deflocs.items():
                if vvar_id not in vvar_uselocs:
                    continue
                if vvar_id in const_vvars:
                    continue
                if defloc.is_extern:
                    continue

                vvar_uselocs_set = set(vvar_uselocs[vvar_id])  # deduplicate
                vvar_useloc_to_count: defaultdict[AILCodeLocation, int] = defaultdict(int)
                for _, useloc in vvar_uselocs[vvar_id]:
                    vvar_useloc_to_count[useloc] += 1

                block = blocks[(defloc.block_addr, defloc.block_idx)]
                stmt = block.statements[defloc.stmt_idx]

                if not (
                    isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid == vvar_id
                ):
                    # come back later, this is not the def you're looking for
                    continue

                if (
                    (vvar.was_reg or vvar.was_parameter)
                    and sum(vvar_useloc_to_count.values()) <= 2
                    and isinstance(stmt.src, Load)
                    and not has_tmp_expr(stmt.src)
                ):
                    # do we want to propagate this Load expression if it's used for less than twice?
                    # it's often seen in the following pattern, where propagation will be beneficial:
                    #    v0 = Load(...)
                    #    if (!v0) {
                    #       v1 = v0 + 1;
                    #    }
                    can_replace = True
                    for vvar_useloc in vvar_useloc_to_count:
                        if has_store_stmt_in_between_stmts(self.func_graph, blocks, defloc, vvar_useloc):
                            can_replace = False

                    if can_replace:
                        # we can propagate this load because there is no store between its def and use
                        for vvar_used, vvar_useloc in vvar_uselocs_set:
                            self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                        continue

                if (vvar.was_reg or vvar.was_stack) and len(vvar_uselocs_set) == 2 and not is_phi_assignment(stmt):
                    # a special case: in a typical switch-case construct, a variable may be used once for comparison
                    # for the default case and then used again for constructing the jump target. we can propagate this
                    # variable for such cases.
                    uselocs = set(vvar_useloc_to_count)
                    if (
                        self.is_vvar_used_for_addr_loading_switch_case(uselocs, blocks)
                        and not has_tmp_expr(stmt.src)
                        and not any(
                            self._call_may_clobber_read(vvar_id, stmt.src, defloc, loc, blocks, const_vvars)
                            for loc in uselocs
                        )
                    ):
                        # the definition dies, so no use may be dropped below
                        for vvar_used, vvar_useloc in vvar_uselocs_set:
                            self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                        # mark the vvar as dead and should be removed
                        self.model.dead_vvar_ids.add(vvar.varid)
                        continue

                if vvar.was_reg and self._is_cmpf_status_word(stmt.src):
                    # each use tests the status word on its own (e.g., ZF in one block and PF in another); copy it to
                    # every use so that the peephole optimizer sees the comparison it tests
                    use_stmts = [
                        blocks[(loc.block_addr, loc.block_idx)].statements[loc.stmt_idx] for _, loc in vvar_uselocs_set
                    ]
                    if not any(is_phi_assignment(use_stmt) for use_stmt in use_stmts):
                        for vvar_used, vvar_useloc in vvar_uselocs_set:
                            self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                        continue

                if (
                    self._propagate_stack_addresses
                    and isinstance(stmt, Assignment)
                    and is_stack_address_expr(stmt.src)
                    and not has_tmp_expr(stmt.src)
                    and not self._address_taken(vvar, vvar_useloc_to_count, blocks)
                ):
                    # A devirtualized VM walks its operand stack through a pointer it keeps in a
                    # stack slot. The definition is a Reference plus a constant, so copying it into
                    # every use costs nothing, and it is the only way the slots that pointer
                    # addresses ever become statically known.
                    for vvar_used, vvar_useloc in vvar_uselocs_set:
                        self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                    continue

                if (
                    self._propagate_stack_addresses
                    and isinstance(stmt, Assignment)
                    and is_const_arm_ite(stmt.src)
                    and not has_tmp_expr(stmt.src)
                    and not self._address_taken(vvar, vvar_useloc_to_count, blocks)
                    and not any(
                        is_phi_assignment(blocks[(loc.block_addr, loc.block_idx)].statements[loc.stmt_idx])
                        for loc in vvar_useloc_to_count
                    )
                ):
                    # a devirtualized VM's branch select is a constant on each path; copying it into every use is
                    # what lets the constant arithmetic around it fold back into one select
                    for vvar_used, vvar_useloc in vvar_uselocs_set:
                        self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                    continue

                if is_vvar_propagatable(vvar, stmt, self.stack_arg_offsets, self._propagate_stack_addresses):
                    if self._address_taken(vvar, vvar_useloc_to_count, blocks):
                        # a use is the slot's address, not its value
                        continue
                    if len(vvar_uselocs_set) == 1:
                        vvar_used, vvar_useloc = next(iter(vvar_uselocs_set))
                        assert vvar_useloc.block_addr is not None and vvar_useloc.stmt_idx is not None
                        use_stmt = blocks[(vvar_useloc.block_addr, vvar_useloc.block_idx)].statements[
                            vvar_useloc.stmt_idx
                        ]
                        if self._propagate_stack_addresses and vvar.was_stack:
                            # a devirtualized VM body: let a slot's definition fold into its only use however deep
                            self.model.depth_exempt.add((vvar_useloc, vvar_id))
                        if (
                            not self._is_phi_source_mismatch(stmt, use_stmt, vvar_deflocs, blocks)
                            and is_const_vvar_load_assignment(
                                stmt, walker_cached=_whitelist_walker(CONST_VVAR_LOAD_WHITELIST)
                            )
                            and not has_store_stmt_in_between_stmts(self.func_graph, blocks, defloc, vvar_useloc)
                            and not has_tmp_expr(stmt.src)
                        ):
                            # we can propagate this load because there is no store between its def and use
                            self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                            continue

                        if is_const_and_vvar_assignment(
                            stmt, walker_cached=_whitelist_walker(CONST_VVAR_WHITELIST)
                        ) and not has_tmp_expr(stmt.src):
                            # if the useloc is a phi assignment statement, ensure that stmt.src is the same as the phi
                            # variable
                            if is_phi_assignment(use_stmt):
                                assert (
                                    isinstance(use_stmt, Assignment)
                                    and isinstance(use_stmt.dst, VirtualVariable)
                                    and isinstance(use_stmt.src, Phi)
                                )
                                if (
                                    isinstance(stmt.src, VirtualVariable)
                                    and stmt.src.oident == use_stmt.dst.oident
                                    and stmt.src.category == use_stmt.dst.category
                                ):
                                    self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                            else:
                                self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                            continue

                    else:
                        if is_const_and_vvar_assignment(stmt, walker_cached=_whitelist_walker(CONST_VVAR_WHITELIST)):
                            if (
                                self._propagate_stack_addresses
                                and len(vvar_useloc_to_count) == 1
                                and stmt.src.depth <= 3
                                and not has_tmp_expr(stmt.src)
                            ):
                                # a devirtualized VM body: every use is in one statement (a branch condition
                                # included); a shallow definition is cheaper duplicated than kept as a variable
                                useloc = next(iter(vvar_useloc_to_count))
                                use_stmt = blocks[(useloc.block_addr, useloc.block_idx)].statements[useloc.stmt_idx]
                                if not is_phi_assignment(use_stmt):
                                    if vvar.was_stack:
                                        # duplicates, but boundedly: the copy has depth <= 3 and each fold deepens
                                        # the definition it lands in, so chains of copies stop after two levels. MBA
                                        # folds need the copies in conditions already past the depth guard.
                                        self.model.depth_exempt.add((useloc, vvar_id))
                                    for vvar_used, vvar_useloc in vvar_uselocs_set:
                                        self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                                    continue
                            non_exitsite_uselocs = []
                            exitsite_uselocs_to_count = defaultdict(int)
                            for _, loc in vvar_uselocs[vvar_id]:
                                if (loc.block_addr, loc.block_idx, loc.stmt_idx) in ret_or_jump_sites:
                                    exitsite_uselocs_to_count[loc] += 1
                                else:
                                    non_exitsite_uselocs.append(loc)

                            if not exitsite_uselocs_to_count or max(exitsite_uselocs_to_count.values()) == 1:
                                if len(non_exitsite_uselocs) == 1:
                                    # this vvar is used once if we exclude its uses at ret sites or jump sites, and
                                    # used at most once at every exit site. we can propagate it
                                    for vvar_used, vvar_useloc in vvar_uselocs_set:
                                        self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                                    continue

                                if (
                                    len(set(non_exitsite_uselocs)) == 1
                                    and (
                                        not has_ite_expr(stmt.src)
                                        or (self._propagate_stack_addresses and is_const_arm_ite(stmt.src))
                                    )
                                    and not has_tmp_expr(stmt.src)
                                ):
                                    useloc = non_exitsite_uselocs[0]
                                    assert useloc.block_addr is not None
                                    assert useloc.stmt_idx is not None
                                    useloc_stmt = blocks[(useloc.block_addr, useloc.block_idx)].statements[
                                        useloc.stmt_idx
                                    ]
                                    if (
                                        stmt.src.depth <= 3
                                        or (self._propagate_stack_addresses and is_const_arm_ite(stmt.src))
                                    ) and not has_ite_stmt(useloc_stmt):
                                        # remove duplicate use locs (e.g., if the variable is used multiple times by the
                                        # same statement) - but ensure stmt is simple enough
                                        for vvar_used, vvar_useloc in vvar_uselocs_set:
                                            self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                                        continue

                # special logic for global variables: if it's used once or multiple times, and the variable is never
                # updated before it's used, we will propagate the load
                if (vvar.was_reg or vvar.was_parameter) and not has_tmp_expr(stmt.src):
                    stmt_src = stmt.src
                    # unpack conversions
                    while isinstance(stmt_src, Convert):
                        stmt_src = stmt_src.operand
                    if (
                        isinstance(stmt_src, Load)
                        and isinstance(stmt_src.addr, Const)
                        and isinstance(stmt_src.addr.value, int)
                    ):
                        # the forward slice from the definition also covers stores past the use; it is kept so that
                        # a load is not copied into more uses than before (copies into both arms of a branch hide
                        # that a phi merges one value)
                        gv_updated = any(
                            self.is_global_variable_updated(
                                self.func_graph,
                                blocks,
                                vvar.varid,
                                stmt_src.addr.value,
                                stmt_src.size,
                                defloc,
                                vvar_useloc,
                            )
                            or self._global_may_be_written(
                                blocks,
                                vvar.varid,
                                stmt_src.addr.value,
                                stmt_src.size,
                                defloc,
                                vvar_useloc,
                                vvar_deflocs,
                                const_vvars,
                            )
                            for vvar_useloc in vvar_useloc_to_count
                        )
                        if not gv_updated:
                            for vvar_used, vvar_useloc in vvar_uselocs_set:
                                self.replace(replacements, vvar_useloc, vvar_used, stmt.src)
                            continue

            self._drop_clobbered_memory_reads(replacements, vvar_deflocs, blocks, const_vvars)

        # the definitions propagated above hold sp before the call returns; StackPointerTracker's offsets below do not
        for vvar_id, (call_ins, adjustment) in call_sp_defs.items():
            for vvar_at_use, useloc in vvar_uselocs.get(vvar_id, ()):
                use_reps = replacements.get(useloc)
                if not use_reps or vvar_at_use not in use_reps or self._ins_addr_at(blocks, useloc) == call_ins:
                    continue
                if adjustment is None:
                    del use_reps[vvar_at_use]
                else:
                    use_reps[vvar_at_use] = self._value_after_call(use_reps[vvar_at_use], adjustment)

        for vvar_id, uselocs in vvar_uselocs.items():
            vvar = next(iter(uselocs))[0] if vvar_id not in vvarid_to_vvar else vvarid_to_vvar[vvar_id]
            vvar_uselocs_set = set(uselocs)  # deduplicate

            if self._sp_tracker is not None and vvar.category == VirtualVariableCategory.REGISTER:
                if vvar.oident == self.project.arch.sp_offset:
                    sp_bits = (
                        (self.project.arch.registers["sp"][1] * self.project.arch.byte_width)
                        if "sp" in self.project.arch.registers
                        else None
                    )
                    sp_offset = self.project.arch.sp_offset
                    assert sp_offset is not None
                    for vvar_at_use, useloc in vvar_uselocs_set:
                        sb_offset = self._stack_base_offset_at_use(vvar_id, useloc, sp_offset, vvar_deflocs, blocks)
                        if sb_offset is not None:
                            v = StackBaseOffset(self._ail_manager.next_atom(), self.project.arch.bits, sb_offset)
                            if sp_bits is not None and vvar.bits < sp_bits:
                                # truncation needed
                                v = Convert(self._ail_manager.next_atom(), sp_bits, vvar.bits, False, v)
                            self.replace(replacements, useloc, vvar_at_use, v)
                    continue
                if not self._bp_as_gpr and vvar.oident == self.project.arch.bp_offset:
                    bp_bits = (
                        (self.project.arch.registers["bp"][1] * self.project.arch.byte_width)
                        if "bp" in self.project.arch.registers
                        else None
                    )
                    bp_offset = self.project.arch.bp_offset
                    assert bp_offset is not None
                    for vvar_at_use, useloc in vvar_uselocs_set:
                        sb_offset = self._stack_base_offset_at_use(vvar_id, useloc, bp_offset, vvar_deflocs, blocks)
                        if sb_offset is not None:
                            v = StackBaseOffset(self._ail_manager.next_atom(), self.project.arch.bits, sb_offset)
                            if bp_bits is not None and vvar.bits < bp_bits:
                                # truncation needed
                                v = Convert(self._ail_manager.next_atom(), bp_bits, vvar.bits, False, v)
                            self.replace(replacements, useloc, vvar_at_use, v)
                    continue

        # tmp def/use locs were collected by the combined pass above.
        tmp_deflocs = _tmp_deflocs_cached
        tmp_uselocs = _tmp_uselocs_cached

        for block_loc, tmp_and_uses in tmp_uselocs.items():
            for tmp_atom, tmp_uses in tmp_and_uses.items():
                # take a look at the definition and propagate the definition if supported
                block = blocks[block_loc]
                if tmp_atom not in tmp_deflocs.get(block_loc, {}):
                    continue
                tmp_def_stmtidx = tmp_deflocs[block_loc][tmp_atom]

                stmt = block.statements[tmp_def_stmtidx]
                if isinstance(stmt, Assignment):
                    r, v = is_const_assignment(stmt, self.only_consts)
                    if r:
                        # we can propagate it!
                        for tmp_used, tmp_use_stmtidx in tmp_uses:
                            loc = AILCodeLocation(block_loc[0], block_loc[1], tmp_use_stmtidx)
                            self.replace(replacements, loc, tmp_used, stmt.src)
                        continue

                    r = is_const_vvar_tmp_assignment(stmt, walker_cached=_whitelist_walker(CONST_VVAR_TMP_WHITELIST))
                    if r:
                        if len(tmp_uses) > 1 and stmt.src.depth > 4:
                            # duplicating a deep expression into every use overfolds (e.g., a rewritten adc carry
                            # feeding the result, DEP2, and NDEP of the next adc); keep it as a variable instead
                            continue
                        # we can propagate it!
                        if isinstance(stmt.src, VirtualVariable):
                            v = const_vvars.get(stmt.src.varid, stmt.src)
                            if (
                                stmt.src.varid in call_sp_defs
                                and v is not stmt.src
                                and stmt.tags.get("ins_addr") != call_sp_defs[stmt.src.varid][0]
                            ):
                                v = self._value_after_call(v, call_sp_defs[stmt.src.varid][1]) or stmt.src
                        else:
                            v = stmt.src

                        for tmp_used, tmp_use_stmtidx in tmp_uses:
                            loc = AILCodeLocation(block_loc[0], block_loc[1], tmp_use_stmtidx)
                            self.replace(replacements, loc, tmp_used, v)
                        continue

                    if len(tmp_uses) <= 2 and is_const_vvar_load_dirty_assignment(
                        stmt, walker_cached=_whitelist_walker(CONST_VVAR_LOAD_DIRTY_WHITELIST)
                    ):
                        dirty_exprs = get_dirty_exprs(stmt)
                        if dirty_exprs and (len(tmp_uses) > 1 or any(map(dirty_has_side_effects, dirty_exprs))):
                            # a dirty helper is never duplicated (rdtsc), and one with side effects (fldenv) stays
                            # where it is
                            continue
                        for tmp_used, tmp_use_stmtidx in tmp_uses:
                            same_inst = (
                                block.statements[tmp_def_stmtidx].tags["ins_addr"]
                                == block.statements[tmp_use_stmtidx].tags["ins_addr"]
                            )
                            between = block.statements[tmp_def_stmtidx + 1 : tmp_use_stmtidx]
                            has_store = any(isinstance(stmt_, Store) for stmt_ in between)
                            # the old value an xchg or cmpxchg loads is read before its own compare-and-swap (or the
                            # intrinsic call that replaced it) writes the memory
                            writes_in_insn = any(
                                isinstance(stmt_, CAS) or (same_inst and has_call(stmt_)) for stmt_ in between
                            )
                            if not writes_in_insn and (same_inst or not has_store):
                                # we can propagate this load because either we do not consider memory aliasing problem
                                # within the same instruction (blocks must be originally lifted with
                                # CROSS_INSN_OPT=False), or there is no store between its def and use.
                                loc = AILCodeLocation(block_loc[0], block_loc[1], tmp_use_stmtidx)
                                self.replace(replacements, loc, tmp_used, stmt.src)

        self.model.replacements = replacements

    @staticmethod
    def is_global_variable_updated(
        func_graph, block_dict, varid: int, gv_addr: int, gv_size: int, defloc: AILCodeLocation, useloc: AILCodeLocation
    ) -> bool:
        defblock = block_dict[(defloc.block_addr, defloc.block_idx)]
        useblock = block_dict[(useloc.block_addr, useloc.block_idx)]

        # traverse a graph slice from the def block to the use block and check if the global variable is updated
        seen = {defblock}
        queue = [defblock]
        while queue:
            block = queue.pop(0)

            start_stmt_idx = defloc.stmt_idx if block is defblock else 0  # inclusive
            end_stmt_idx = useloc.stmt_idx if block is useblock else len(block.statements)  # exclusive
            assert start_stmt_idx is not None
            assert end_stmt_idx is not None

            for idx in range(start_stmt_idx, end_stmt_idx):
                stmt = block.statements[idx]
                if isinstance(stmt, Store) and isinstance(stmt.addr, Const):
                    store_addr = stmt.addr.value
                    store_size = stmt.size
                    if gv_addr <= store_addr < gv_addr + gv_size or store_addr <= gv_addr < store_addr + store_size:
                        return True

            if block is useblock:
                continue

            for succ in func_graph.successors(block):
                if succ not in seen:
                    abort_path = False
                    for stmt in succ.statements:
                        if is_phi_assignment(stmt) and any(
                            vvar.varid == varid for _, vvar in stmt.src.src_and_vvars if vvar is not None
                        ):
                            # the virtual variable is no longer live after this point
                            abort_path = True
                            break
                    if abort_path:
                        continue

                    seen.add(succ)
                    queue.append(succ)

        return False

    @staticmethod
    def _is_cmpf_status_word(expr: Expression) -> bool:
        """CmpF(a, b) over constants and vvars, possibly masked and width-converted."""
        while True:
            if isinstance(expr, Convert) and expr.from_type == Convert.TYPE_INT and expr.to_type == Convert.TYPE_INT:
                expr = expr.operand
            elif isinstance(expr, BinaryOp) and expr.op == "And" and isinstance(expr.operands[1], Const):
                expr = expr.operands[0]
            else:
                break
        return (
            isinstance(expr, BinaryOp)
            and expr.op == "CmpF"
            and all(isinstance(op, (Const, VirtualVariable)) for op in expr.operands)
        )

    @staticmethod
    def is_vvar_used_for_addr_loading_switch_case(uselocs: set[AILCodeLocation], blocks) -> bool:
        """
        Check if a virtual variable is used for loading an address in a switch-case construct.

        :param uselocs: The use locations of the virtual variable.
        :param blocks:  All blocks of the current function.
        :return:        True if the virtual variable is used for loading an address in a switch-case construct, False
                        otherwise.
        """

        if len(uselocs) != 2:
            return False

        useloc_0, useloc_1 = list(uselocs)
        block_0 = blocks[(useloc_0.block_addr, useloc_0.block_idx)]
        stmt_0 = block_0.statements[useloc_0.stmt_idx]
        block_1 = blocks[(useloc_1.block_addr, useloc_1.block_idx)]
        stmt_1 = block_1.statements[useloc_1.stmt_idx]

        if isinstance(stmt_0, Jump):
            stmt_0, stmt_1 = stmt_1, stmt_0
            block_0, block_1 = block_1, block_0
        if not isinstance(stmt_0, ConditionalJump) or not isinstance(stmt_1, Jump):
            return False

        # check if stmt_0 jumps to block_1
        if not isinstance(stmt_0.true_target, Const) or not isinstance(stmt_0.false_target, Const):
            return False
        stmt_0_targets = {
            (stmt_0.true_target.value, stmt_0.true_target_idx),
            (stmt_0.false_target.value, stmt_0.false_target_idx),
        }
        return (block_1.addr, block_1.idx) in stmt_0_targets

    @staticmethod
    def _is_phi_source_mismatch(
        def_stmt: Assignment,
        use_stmt: Statement,
        vvar_deflocs: Mapping[int, tuple[VirtualVariable, AILCodeLocation]],
        blocks: Mapping[tuple[int, int], Block],
    ) -> bool:
        """
        Whether propagating def_stmt.src into use_stmt, a phi, would give the phi a source it cannot have: a non-vvar
        expression, or a stack vvar holding a floating-point value in a register phi (dephication would coalesce the
        register with the stack slot, which an integer reload of a float slot must not share a variable with).
        """
        if not is_phi_assignment(use_stmt):
            return False
        assert isinstance(use_stmt, Assignment) and isinstance(use_stmt.dst, VirtualVariable)
        if not isinstance(def_stmt.src, VirtualVariable):
            return True
        if not (def_stmt.src.was_stack and not use_stmt.dst.was_stack):
            return False
        # other slots (spills of integer registers, call results, loads) are reloaded as what they hold
        entry = vvar_deflocs.get(def_stmt.src.varid)
        if entry is None or entry[1].is_extern or entry[1].stmt_idx is None:
            return True
        block = blocks.get((entry[1].block_addr, entry[1].block_idx))
        if block is None:
            return True
        slot_def = block.statements[entry[1].stmt_idx]
        return not isinstance(slot_def, Assignment) or SPropagator._is_fp_valued(slot_def.src)

    @staticmethod
    def _is_fp_valued(expr: Expression) -> bool:
        if isinstance(expr, Convert):
            return expr.to_type == Convert.TYPE_FP
        if isinstance(expr, Reinterpret):
            return expr.to_type == "F"
        if isinstance(expr, (BinaryOp, UnaryOp)):
            return bool(expr.floating_point)
        return False

    @staticmethod
    def replace(
        replacements: dict[AILCodeLocation, dict[VirtualVariable | Tmp, Expression]],
        loc: AILCodeLocation,
        expr: VirtualVariable | Tmp,
        value: Expression,
    ) -> None:
        replacements[loc][expr] = value

    @staticmethod
    def _nonphi_src_varids(
        src_varids: set[int | None], phivar_to_srcvarids: dict[int, set[int | None]]
    ) -> set[int | None]:
        """
        Expand source var IDs to non-phi var IDs.

        :param src_varids:          The source var IDs.
        :param phivar_to_srcvarids: The mapping from phi var IDs to their source var IDs.
        :return:                    The expanded non-phi var IDs.
        """

        # fast path
        if all(varid not in phivar_to_srcvarids for varid in src_varids):
            return src_varids

        result: set[int | None] = set()
        seen: set[int] = set()  # sufficient if we only store phi var IDs here
        queue: list[int | None] = list(src_varids)
        while queue:
            varid = queue.pop()
            if varid is None:
                result.add(None)
                continue
            if varid in seen:
                continue
            if varid not in phivar_to_srcvarids:
                result.add(varid)
                continue
            seen.add(varid)
            queue.extend(vid for vid in phivar_to_srcvarids[varid] if vid is not None and vid not in seen)
        return result


class SPropagatorAnalysis(Analysis, SPropagator):
    """
    A wrapper around SPropagator to make it an Analysis.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


register_analysis(SPropagatorAnalysis, "SPropagator")
