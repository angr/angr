from __future__ import annotations

from bisect import bisect_left
from collections import deque
from typing import TYPE_CHECKING

import networkx

from angr.ailment import AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    DirtyExpression,
    Expression,
    FunctionLikeMacro,
    Load,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import (
    CAS,
    Assignment,
    ConditionalJump,
    Jump,
    Return,
    SideEffectStatement,
    Statement,
    Store,
)
from angr.sim_type import (
    SimTypeArray,
    SimTypeChar,
    SimTypeFunction,
    SimTypeNum,
    SimTypePointer,
    SimTypeReg,
    SimTypeString,
    SimTypeWideChar,
    SimTypeWString,
)
from angr.utils.ail import dirty_has_side_effects

from .block_walkers import PURE_INTRINSIC_CALLS
from .peephole_optimizations.cas_intrinsics import _INTRINSICS_NAMES

if TYPE_CHECKING:
    from angr.project import Project

    from .variable_map import VariableMap
    from .vm_context_globals import VMContext

# (top, addrs): top is False -> addrs are the live bytes; top is True -> every byte is live except addrs
Liveness = tuple[bool, frozenset[int]]

_NOTHING_LIVE: Liveness = (False, frozenset())
_ALL_LIVE: Liveness = (True, frozenset())


def _is_stack_address(expr: Expression) -> bool:
    if isinstance(expr, StackBaseOffset):
        return True
    if isinstance(expr, UnaryOp) and expr.op == "Reference":
        return isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack
    if isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"}:
        return _is_stack_address(expr.operands[0]) or (expr.op == "Add" and _is_stack_address(expr.operands[1]))
    return False


def _const_addr(expr: Expression) -> int | None:
    if isinstance(expr, Const) and isinstance(expr.value, int):
        return expr.value
    return None


# lock-prefixed read-modify-write instructions, rewritten into intrinsics on their first operand
_ATOMIC_INTRINSICS = frozenset(name for names in _INTRINSICS_NAMES.values() for name in names.values())
# no user-space mapping starts below this on Windows or Linux; a smaller variadic argument is not a pointer
_MIN_MAPPED_ADDR = 0x10000


def _atomic_target(call: Call) -> tuple[int, int] | None:
    """
    (address, size) of the memory an atomic intrinsic operates on, if its first argument is a constant address.
    """
    if not (isinstance(call.target, str) and call.target in _ATOMIC_INTRINSICS and call.args and call.bits):
        return None
    base = _const_addr(call.args[0])
    return None if base is None else (base, call.bits // 8)


class CallGlobalReads:
    """
    The global memory a call may read.

    A library callee -- a hooked or SimProcedure function, or a call the decompiler synthesized by name -- whose name
    has a library-declared prototype reads globals only through its pointer arguments (and variadic arguments, which
    may be pointers). A string argument reaches its terminator in the loaded image, unless the function writes to the
    string; any other scalar pointer reaches at most the rest of the section it points into, since objects do not span
    sections. This ignores pointers the callee may load from that memory. A pointer to a non-scalar pointee
    (void, struct, pointer, function) may reach anything. A variadic callee qualifies only if it is a printf or scanf
    whose constant format string shows that the call site carries all its arguments. Every other callee may read every
    global.
    """

    def __init__(self, project: Project, variable_map: VariableMap | None = None):
        self._project = project
        self._variable_map = variable_map
        self._declared: dict[tuple[str, str | None], SimTypeFunction | None] = {}

    def is_global(self, addr: int) -> bool:
        """
        Whether a constant address is a global variable. One no loaded object maps is a placeholder, such as the
        address an argument buffer is seeded with when deobfuscation starts mid-function.
        """
        return self._project.loader.find_object_containing(addr) is not None

    def reads(self, call: Call, written: list[int] | None = None) -> list[tuple[int, int]] | None:
        """
        :param written: Sorted global bytes the function may write.
        :return:        Half-open address ranges the call may read, or None if it may read every global.
        """
        name, proto = self._library_prototype(call)
        if proto is None or call.args is None or len(call.args) < len(proto.args):
            return None
        if proto.variadic:
            count = self._format_arg_count(name, proto, call, written or [])
            if count is None or len(call.args) < len(proto.args) + count:
                return None
        ranges = []
        for i, arg in enumerate(call.args):
            arg_ty = proto.args[i] if i < len(proto.args) else None
            if arg_ty is not None and not isinstance(arg_ty, (SimTypePointer, SimTypeArray)):
                continue
            arg_ranges = self._pointer_reads(arg, arg_ty, written or [])
            if arg_ranges is None:
                return None
            ranges += arg_ranges
        return ranges

    def writes(self, call: Call) -> list[tuple[int, int]] | None:
        """
        :return: Half-open address ranges the call may write, or None if it may write every global. Like ``reads``,
                 but a pointer argument may be written up to the end of its section, string or not.
        """
        name, proto = self._library_prototype(call)
        if proto is None or call.args is None or len(call.args) < len(proto.args):
            return None
        if proto.variadic:
            count = self._format_arg_count(name, proto, call, [])
            if count is None or len(call.args) < len(proto.args) + count:
                return None
        ranges = []
        for i, arg in enumerate(call.args):
            arg_ty = proto.args[i] if i < len(proto.args) else None
            if arg_ty is not None and not isinstance(arg_ty, (SimTypePointer, SimTypeArray)):
                continue
            arg_ranges = self._pointer_writes(arg, arg_ty)
            if arg_ranges is None:
                return None
            ranges += arg_ranges
        return ranges

    def _pointer_writes(self, arg: Expression, arg_ty) -> list[tuple[int, int]] | None:
        if arg_ty is None:
            flat = True
        else:
            pointee = arg_ty.pts_to if isinstance(arg_ty, SimTypePointer) else arg_ty.elem_type
            flat = isinstance(pointee, (SimTypeNum, SimTypeString, SimTypeWString)) or (
                isinstance(pointee, SimTypeReg) and not isinstance(pointee, SimTypePointer)
            )
        while isinstance(arg, Convert):
            arg = arg.operand
        if _is_stack_address(arg):
            return [] if flat else None
        addr = _const_addr(arg)
        if addr is None or not flat:
            return None
        if addr == 0 or (arg_ty is None and addr < _MIN_MAPPED_ADDR):
            return []
        loader = self._project.loader
        region = loader.find_section_containing(addr) or loader.find_segment_containing(addr)
        if region is None:
            return None
        return [(addr, region.vaddr + region.memsize)]

    def _library_prototype(self, call: Call) -> tuple[str | None, SimTypeFunction | None]:
        hook = func = None
        if isinstance(call.target, str):
            name = call.target
        else:
            addr = _const_addr(call.target)
            if addr is None:
                return None, None
            if self._project.is_hooked(addr):
                hook = self._project.hooked_by(addr)
            func = self._project.kb.functions.get(addr, None)
            if hook is None and not (func is not None and (func.is_simprocedure or func.is_plt)):
                return None, None
            name = func.name if func is not None else hook.display_name
        libname = getattr(hook, "library_name", None) or (func.prototype_libname if func is not None else None)
        proto = self._declared_prototype(name, libname)
        if proto is None and hook is not None and hook.prototype is not None and not hook.guessed_prototype:
            proto = hook.prototype
        return name, None if proto is None else proto.with_arch(self._project.arch)

    def _string_end(self, addr: int, char_size: int) -> int | None:
        """
        The address past the terminator of the string at ``addr`` in the loaded image.
        """
        memory = self._project.loader.memory
        try:
            for end in range(addr, addr + 4096, char_size):
                if not any(memory.load(end, char_size)):
                    return end + char_size
        except KeyError:
            pass
        return None

    def _format_arg_count(self, name: str | None, proto: SimTypeFunction, call: Call, written: list[int]) -> int | None:
        """
        The number of variadic arguments a printf- or scanf-like call consumes, from its constant format string.
        """
        if name is None or ("printf" not in name and "scanf" not in name):
            return None
        from angr.procedures.stubs.format_parser import (  # pylint:disable=import-outside-toplevel
            FormatParser,
            FormatSpecifier,
        )

        assert call.args is not None
        fmt_idx = next(
            (
                i
                for i, ty in enumerate(proto.args)
                if isinstance(ty, SimTypePointer) and isinstance(ty.pts_to, SimTypeChar)
            ),
            None,
        )
        addr = None if fmt_idx is None else _const_addr(call.args[fmt_idx])
        end = None if addr is None else self._string_end(addr, 1)
        if addr is None or end is None:
            return None
        start = bisect_left(written, addr)
        if start < len(written) and written[start] < end:
            # the function may rewrite its format string
            return None
        fmt = self._project.loader.memory.load(addr, end - 1 - addr)
        parser = FormatParser(project=self._project)
        components = parser.extract_components([bytes([b]) for b in fmt])
        return sum(1 for c in components if isinstance(c, FormatSpecifier))

    def _declared_prototype(self, name: str, libname: str | None) -> SimTypeFunction | None:
        key = name, libname
        if key not in self._declared:
            from angr.procedures.definitions import (  # pylint:disable=import-outside-toplevel
                SIM_LIBRARIES,
                SimSyscallLibrary,
            )

            proto = None
            libs = list(SIM_LIBRARIES.get(libname, ())) if libname else []
            libs += [lib for group in SIM_LIBRARIES.values() for lib in group]
            for lib in libs:
                if not isinstance(lib, SimSyscallLibrary) and lib.has_prototype(name):
                    proto = lib.get_prototype(name, deref=True)
                    break
            self._declared[key] = proto
        return self._declared[key]

    def _pointer_reads(self, arg: Expression, arg_ty, written: list[int]) -> list[tuple[int, int]] | None:
        # char size of a string pointee: 1 or 2; 2 for a variadic argument, whose wide terminator is never earlier
        char_size = 2
        if arg_ty is None:
            flat = True
        else:
            pointee = arg_ty.pts_to if isinstance(arg_ty, SimTypePointer) else arg_ty.elem_type
            flat = isinstance(pointee, (SimTypeNum, SimTypeString, SimTypeWString)) or (
                isinstance(pointee, SimTypeReg) and not isinstance(pointee, SimTypePointer)
            )
            if isinstance(pointee, (SimTypeChar, SimTypeString)):
                char_size = 1
            elif not isinstance(pointee, (SimTypeWideChar, SimTypeWString)):
                char_size = 0
        if isinstance(arg, Const) and self._variable_map is not None and self._variable_map.custom_string(arg):
            return []
        while isinstance(arg, Convert):
            # e.g. a stack pointer passed where the format string says %d
            arg = arg.operand
        if _is_stack_address(arg):
            # a stack object of a scalar type holds no pointer to a global
            return [] if flat else None
        addr = _const_addr(arg)
        if addr is None or not flat:
            return None
        if addr == 0 or (arg_ty is None and addr < _MIN_MAPPED_ADDR):
            return []
        if char_size:
            end = self._string_end(addr, char_size)
            if end is not None:
                start = bisect_left(written, addr)
                if start == len(written) or written[start] >= end:
                    return [(addr, end)]
        loader = self._project.loader
        region = loader.find_section_containing(addr) or loader.find_segment_containing(addr)
        if region is None:
            return None
        return [(addr, region.vaddr + region.memsize)]


class _GlobalReadCollector(AILBlockViewer):
    """
    Collects the global memory a statement may read, and whether it has side effects beyond its own store.
    """

    def __init__(
        self,
        call_reads: CallGlobalReads | None = None,
        universe: list[int] | None = None,
        vm_context: VMContext | None = None,
    ):
        super().__init__()
        self.call_reads = call_reads
        # sorted bytes written by constant-address stores; only these matter when a call reads a whole range
        self.universe = universe or []
        self.vm_context = vm_context if vm_context is not None and vm_context.private else None
        self.reads_all = False
        # every global except the private VM context
        self.reads_nonprivate = False
        self.has_side_effects = False
        self.read_bytes: set[int] = set()
        # ((block addr, block idx), stmt idx) of the statement being collected
        self.loc = None

    def reset(self) -> None:
        self.reads_all = False
        self.reads_nonprivate = False
        self.has_side_effects = False
        self.read_bytes = set()

    def _read(self, addr: Expression, size: int) -> None:
        base = _const_addr(addr)
        if base is not None and size > 0:
            self.read_bytes.update(range(base, base + size))
        elif not _is_stack_address(addr):
            if self.vm_context is not None and not self.vm_context.tainted(addr, self.loc):
                self.reads_nonprivate = True
            else:
                self.reads_all = True

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._read(expr.addr, expr.size)
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx: int, stmt: CAS, block: Block | None):
        size = stmt.data_lo.size * (2 if stmt.data_hi is not None else 1)
        self._read(stmt.addr, size)
        self.has_side_effects = True
        super()._handle_CAS(stmt_idx, stmt, block)

    def _read_range(self, lo: int, hi: int) -> None:
        start = bisect_left(self.universe, lo)
        end = bisect_left(self.universe, hi, lo=start)
        self.read_bytes.update(self.universe[start:end])

    def _handle_Call(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if not (isinstance(expr.target, str) and expr.target in PURE_INTRINSIC_CALLS):
            self.has_side_effects = True
            atomic = _atomic_target(expr)
            ranges = (
                [(atomic[0], atomic[0] + atomic[1])]
                if atomic is not None
                else self.call_reads.reads(expr, self.universe)
                if self.call_reads is not None
                else None
            )
            if ranges is None:
                if (
                    self.vm_context is not None
                    and atomic is None
                    and not self.vm_context.call_may_access(expr, self.loc)
                ):
                    # the callee holds no pointer into the private VM context
                    self.reads_nonprivate = True
                else:
                    self.reads_all = True
            else:
                for lo, hi in ranges:
                    self._read_range(lo, hi)
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_FunctionLikeMacro(self, expr_idx, expr: FunctionLikeMacro, stmt_idx, stmt, block):
        self.reads_all = True
        self.has_side_effects = True
        super()._handle_FunctionLikeMacro(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if dirty_has_side_effects(expr):
            self.reads_all = True
            self.has_side_effects = True
        super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)


class _StmtEffect:
    __slots__ = (
        "candidate",
        "compare_reads",
        "faint",
        "kill",
        "live",
        "private",
        "read_bytes",
        "reads_all",
        "soft_reads",
        "written",
    )

    def __init__(
        self,
        kill: frozenset[int],
        read_bytes: frozenset[int],
        reads_all: bool,
        candidate: bool,
        written: frozenset[int] | None = None,
        compare_reads: frozenset[int] = frozenset(),
        private: frozenset[int] | None = None,
    ):
        self.kill = kill
        self.read_bytes = read_bytes
        self.reads_all = reads_all
        # set if the statement reads every global except these bytes
        self.private = private
        self.candidate = candidate
        self.written = kill if written is None else written
        # bytes an atomic reads only to decide its own write; ignored while it is assumed removable (faint)
        self.compare_reads = compare_reads
        self.faint = False
        # private-context reads whose values only reach these candidate stores: (bytes, stores)
        self.soft_reads: list[tuple[frozenset[int], list[_StmtEffect]]] = []
        # a candidate store some read needs (assumed false until found)
        self.live = False


def _join(a: Liveness, b: Liveness) -> Liveness:
    a_top, a_set = a
    b_top, b_set = b
    if not a_top and not b_top:
        return False, a_set | b_set
    if a_top and b_top:
        return True, a_set & b_set
    if a_top:
        return True, a_set - b_set
    return True, b_set - a_set


def _transfer(live: Liveness, effect: _StmtEffect) -> Liveness:
    top, addrs = live
    if effect.kill:
        addrs = addrs | effect.kill if top else addrs - effect.kill
    if effect.reads_all:
        return _ALL_LIVE
    if effect.private is not None:
        top, addrs = (True, addrs & effect.private) if top else (True, effect.private - addrs)
    read_bytes = effect.read_bytes if effect.faint else effect.read_bytes | effect.compare_reads
    for soft_bytes, stores in effect.soft_reads:
        if any(store.live for store in stores):
            read_bytes = read_bytes | soft_bytes
    if read_bytes:
        addrs = addrs - read_bytes if top else addrs | read_bytes
    return top, addrs


def _is_dead(live: Liveness, written: frozenset[int]) -> bool:
    top, addrs = live
    if top:
        return written <= addrs
    return not (written & addrs)


def _discarded_atomic(stmt: Statement) -> tuple[int, int] | None:
    if (
        isinstance(stmt, SideEffectStatement)
        and stmt.ret_expr is None
        and stmt.fp_ret_expr is None
        and isinstance(stmt.expr, Call)
    ):
        return _atomic_target(stmt.expr)
    return None


def _store_bytes(stmt: Statement) -> range | None:
    if isinstance(stmt, Store) and stmt.size > 0:
        base = _const_addr(stmt.addr)
        if base is not None:
            return range(base, base + stmt.size)
    atomic = _discarded_atomic(stmt)
    return None if atomic is None else range(atomic[0], atomic[0] + atomic[1])


def _stmt_effect(stmt: Statement, collector: _GlobalReadCollector, private: frozenset[int]) -> _StmtEffect:
    effect = _stmt_effect_core(stmt, collector)
    if collector.reads_nonprivate and not effect.reads_all:
        effect.private = private
    return effect


def _stmt_effect_core(stmt: Statement, collector: _GlobalReadCollector) -> _StmtEffect:
    collector.reset()
    atomic = _discarded_atomic(stmt)
    if atomic is not None:
        # an atomic read-modify-write whose old value is unused: a conditional store that reads its own bytes
        assert isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call) and stmt.expr.args
        for arg in stmt.expr.args[1:]:
            collector.walk_expression(arg)
        written = frozenset(range(atomic[0], atomic[0] + atomic[1]))
        return _StmtEffect(
            frozenset(),
            frozenset(collector.read_bytes),
            collector.reads_all,
            not collector.has_side_effects,
            written=written,
            compare_reads=written,
        )
    collector.walk_statement(stmt)
    kill: frozenset[int] = frozenset()
    candidate = False
    if isinstance(stmt, Store) and stmt.guard is None and stmt.size > 0:
        base = _const_addr(stmt.addr)
        if base is not None:
            kill = frozenset(range(base, base + stmt.size))
            candidate = not collector.has_side_effects
    return _StmtEffect(kill, frozenset(collector.read_bytes), collector.reads_all, candidate)


def _exit_liveness(block: Block, successors: list[Block]) -> Liveness | None:
    """
    Liveness contributed by control flow that leaves the function from the end of this block.
    """
    last = block.statements[-1] if block.statements else None
    if not successors:
        # leaving through a return makes no global live; any other exit (tail jump, unresolved jump) may read anything
        return _NOTHING_LIVE if isinstance(last, Return) else _ALL_LIVE
    succ_addrs = {succ.addr for succ in successors}
    if isinstance(last, Jump):
        targets = [last.target]
    elif isinstance(last, ConditionalJump):
        targets = [t for t in (last.true_target, last.false_target) if t is not None]
    else:
        return None
    for target in targets:
        addr = _const_addr(target)
        if addr is not None and addr not in succ_addrs:
            return _ALL_LIVE
    return None


class _PrivateLoads(AILBlockViewer):
    """
    Loads of private VM-context bytes by constant address, and whether the walked code has side effects.
    """

    def __init__(self, private: frozenset[int]):
        super().__init__()
        self.private = private
        self.read: set[int] = set()
        self.vvars: set[int] = set()
        self.side_effects = False

    def reset(self):
        self.read = set()
        self.vvars = set()
        self.side_effects = False

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        base = _const_addr(expr.addr)
        if base is not None and expr.size > 0:
            self.read.update(b for b in range(base, base + expr.size) if b in self.private)
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        self.vvars.add(expr.varid)

    def _handle_Phi(self, expr_idx, expr, stmt_idx, stmt, block):
        for _, vvar in expr.src_and_vvars:
            if vvar is not None:
                self.vvars.add(vvar.varid)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if not (isinstance(expr.target, str) and expr.target in PURE_INTRINSIC_CALLS):
            self.side_effects = True
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_FunctionLikeMacro(self, expr_idx, expr, stmt_idx, stmt, block):
        self.side_effects = True
        super()._handle_FunctionLikeMacro(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if dirty_has_side_effects(expr):
            self.side_effects = True
        super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)


_HARD = None


def _find_soft_reads(func_graph, current, effects, private: frozenset[int], collector) -> None:
    """
    Mark the private-context loads whose values only flow - through side-effect-free variable definitions - into the
    data of removable stores to the private context. Such a read is needed only if one of those stores is.
    """
    walker = _PrivateLoads(private)
    # per statement: (effect, private bytes read, consumer); consumer is a store effect, a defined vvar id, or _HARD
    sites = []
    # vvar id -> consumers of its value
    users: dict[int, list] = {}
    for node in func_graph:
        block = current(node)
        for idx, stmt in enumerate(block.statements):
            effect = effects[node][idx]
            walker.reset()
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                walker.walk_expression(stmt.src)
                consumer = _HARD if walker.side_effects else ("vvar", stmt.dst.varid)
            elif (
                isinstance(stmt, Store)
                and effect.candidate
                and not effect.reads_all
                and effect.written
                and effect.written <= private
            ):
                walker.walk_expression(stmt.data)
                consumer = _HARD if walker.side_effects else ("store", effect)
            else:
                walker.walk_statement(stmt)
                consumer = _HARD
            for varid in walker.vvars:
                users.setdefault(varid, []).append(consumer)
            if walker.read and consumer is not _HARD:
                sites.append((effect, frozenset(walker.read), consumer))

    # vvar id -> the stores its value reaches, or _HARD
    sinks: dict[int, set | None] = {varid: set() for varid in users}
    changed = True
    while changed:
        changed = False
        for varid, consumers in users.items():
            current_sinks = sinks[varid]
            if current_sinks is _HARD:
                continue
            new = set(current_sinks)
            for consumer in consumers:
                if consumer is _HARD:
                    new = _HARD
                    break
                kind, target = consumer
                if kind == "store":
                    new.add(id(target))
                else:
                    target_sinks = sinks.get(target, set())
                    if target_sinks is _HARD:
                        new = _HARD
                        break
                    new |= target_sinks
            if new is _HARD or new != current_sinks:
                if new != current_sinks:
                    sinks[varid] = new
                    changed = True

    by_id = {id(effect): effect for node_effects in effects.values() for effect in node_effects}
    for effect, read, (kind, target) in sites:
        if kind == "store":
            stores = [target]
        else:
            target_sinks = sinks.get(target, set())
            if target_sinks is _HARD:
                continue
            stores = [by_id[i] for i in target_sinks]
        if read & effect.compare_reads:
            continue
        effect.read_bytes = effect.read_bytes - read
        effect.soft_reads.append((read, stores))


def find_dead_global_stores(
    func_graph: networkx.DiGraph,
    blocks: dict[Block, Block] | None = None,
    call_reads: CallGlobalReads | None = None,
    vm_context: VMContext | None = None,
) -> dict[tuple[int, int | None], set[int]]:
    """
    Find stores to constant addresses whose bytes are never read before being overwritten or the function returns.

    Backward may-liveness over global memory bytes. A load from a constant address reads exactly those bytes; a load
    through any other non-stack address, a function-like macro, or a side-effecting dirty helper may read every
    global; a call reads what ``call_reads`` allows, or every global without it. Only unguarded stores to constant
    addresses kill. An atomic intrinsic on a constant address whose result is unused is removable like a store, but
    kills nothing; the bytes it compares count as read only if it has to stay. Returning from the function reads
    nothing: that is the assumption ``allow_global_dead_ass_elim`` opts into. Leaving the function in any other way
    reads everything.

    :param func_graph:  The function graph.
    :param blocks:      Maps graph nodes to their up-to-date blocks, if any.
    :param call_reads:  Bounds the globals a call may read, and restricts removal to stores into loaded objects.
    :param vm_context:  The VM context of a devirtualized function. If it is private (no address into it escapes),
                        calls and loads through pointers that carry no context address do not read it.
    :return:            Statement indices of dead stores, keyed by (block addr, block idx).
    """
    current = (lambda node: blocks.get(node, node)) if blocks else (lambda node: node)

    universe: set[int] = set()
    for node in func_graph:
        for stmt in current(node).statements:
            written = _store_bytes(stmt)
            if written is not None:
                universe.update(written)
    collector = _GlobalReadCollector(call_reads, sorted(universe), vm_context)
    private = vm_context.private_bytes(universe) if vm_context is not None else frozenset()
    effects: dict[Block, list[_StmtEffect]] = {}
    exit_live: dict[Block, Liveness | None] = {}
    for node in func_graph:
        block = current(node)
        effects[node] = []
        for idx, stmt in enumerate(block.statements):
            collector.loc = ((block.addr, block.idx), idx)
            effects[node].append(_stmt_effect(stmt, collector, private))
        if call_reads is not None:
            for effect in effects[node]:
                if effect.candidate and not call_reads.is_global(min(effect.written)):
                    effect.candidate = False
        exit_live[node] = _exit_liveness(block, [current(succ) for succ in func_graph.successors(node)])

    if not any(effect.candidate for node_effects in effects.values() for effect in node_effects):
        return {}

    def _solve() -> tuple[list[tuple[Block, int, _StmtEffect]], list[_StmtEffect]]:
        live_in: dict[Block, Liveness] = {}

        def _live_out(node) -> Liveness:
            live = exit_live[node]
            if live is None:
                live = _NOTHING_LIVE
            for succ in func_graph.successors(node):
                if succ in live_in:
                    live = _join(live, live_in[succ])
            return live

        worklist = deque(func_graph)
        in_worklist = set(worklist)
        while worklist:
            node = worklist.popleft()
            in_worklist.discard(node)
            live = _live_out(node)
            for effect in reversed(effects[node]):
                live = _transfer(live, effect)
            if live_in.get(node) == live:
                continue
            live_in[node] = live
            for pred in func_graph.predecessors(node):
                if pred not in in_worklist:
                    worklist.append(pred)
                    in_worklist.add(pred)

        dead_effects: list[tuple[Block, int, _StmtEffect]] = []
        live_effects: list[_StmtEffect] = []
        for node in func_graph:
            live = _live_out(node)
            for stmt_idx in range(len(effects[node]) - 1, -1, -1):
                effect = effects[node][stmt_idx]
                if effect.candidate:
                    if _is_dead(live, effect.written):
                        dead_effects.append((node, stmt_idx, effect))
                    else:
                        live_effects.append(effect)
                live = _transfer(live, effect)
        return dead_effects, live_effects

    if private:
        _find_soft_reads(func_graph, current, effects, private, collector)

    # Atomics that only read their own bytes would keep each other alive around a loop, and so would private-context
    # stores whose values are only read to compute other such stores. Assume every removable atomic and store is
    # faint, and revive the ones that turn out to be live until nothing changes.
    for node_effects in effects.values():
        for effect in node_effects:
            effect.faint = effect.candidate and bool(effect.compare_reads)
    while True:
        dead_effects, live_effects = _solve()
        revived = [effect for effect in live_effects if effect.faint or not effect.live]
        if not revived:
            break
        for effect in revived:
            effect.faint = False
            effect.live = True

    dead: dict[tuple[int, int | None], set[int]] = {}
    for node, stmt_idx, _ in dead_effects:
        block = current(node)
        dead.setdefault((block.addr, block.idx), set()).add(stmt_idx)
    return dead
