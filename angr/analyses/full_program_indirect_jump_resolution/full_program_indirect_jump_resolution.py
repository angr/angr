from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from angr import ailment
from angr.ailment import AILBlockViewer
from angr.analyses.analysis import AnalysesHub, Analysis
from angr.analyses.decompiler.clinic import ClinicStage

from .descriptors import (
    DescriptorStore,
    GlobalRegion,
    HeapRegion,
    MemoryRegion,
    PointerShapeDescriptor,
    StackRegion,
    UnknownRegion,
)

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.cfg_model import CFGModel
    from angr.knowledge_plugins.functions.function import Function

l = logging.getLogger(name=__name__)


# names of allocation functions whose return value is a fresh heap region
_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "xmalloc", "xcalloc", "_Znwm", "_Znam"}


class _FuncFacts:
    """
    Per-function facts extracted during the intra-procedural pass.
    """

    __slots__ = (
        "arg_param_regions",
        "call_bindings",
        "func_addr",
        "indirect_sites",
        "return_regions",
        "vvar_codeptrs",
        "vvar_region",
    )

    def __init__(self, func_addr: int):
        self.func_addr = func_addr
        # varid -> MemoryRegion that this vvar points to
        self.vvar_region: dict[int, MemoryRegion] = {}
        # varid -> set of concrete code-pointer values held directly by this vvar
        self.vvar_codeptrs: dict[int, set[int]] = {}
        # parameter index -> region representing the object behind that pointer parameter
        self.arg_param_regions: dict[int, MemoryRegion] = {}
        # list of (callee_addr, [arg regions or None]) recorded at Call sites
        self.call_bindings: list[tuple[int, list[MemoryRegion | None]]] = []
        # region returned by this function (best-effort), or None
        self.return_regions: set[MemoryRegion] = set()
        # list of indirect sites: (ins_addr, kind, target_expr)
        self.indirect_sites: list[tuple[int, str, Any]] = []


class FullProgramIndirectJumpResolution(Analysis):
    """
    Resolves indirect jumps and calls across a whole binary using AIL-level pointer-shape analysis.

    For each real function the analysis lifts a simplified AIL graph (via Clinic, stopping before variable recovery
    and structuring) and extracts *pointer shapes*: which memory regions pointers point to, which concrete code
    pointers get stored into which fields of those regions, and the element stride of indexed table accesses. Global
    tables are additionally harvested by reading initialized program memory. Pointer shapes are then propagated
    interprocedurally across the call graph (caller argument regions are unioned with callee parameter regions) to a
    fixed point. Finally, every indirect jump/call target expression is evaluated against the collected shapes to
    recover the set of possible target functions.

    The per-function phase dominates the runtime, so the analysis supports the usual angr responsiveness controls:
    pass ``progress_callback`` and/or ``show_progressbar`` (handled by the base :class:`Analysis`) to observe progress,
    ``low_priority=True`` to periodically release the GIL and keep a host application (e.g. a GUI) responsive, and call
    :meth:`abort` to stop early. Each progress update passes ``analysis=self`` to the callback, so a host can grab the
    running instance and call :meth:`abort` on it (or do so from another thread). An aborted run still finalizes the
    partial results collected so far, leaving ``resolved_indirect_jumps`` valid.

    :ivar resolved_indirect_jumps: mapping from the instruction address of an indirect jump/call to the set of
                                   resolved target function addresses.
    :ivar pointer_shapes:          the descriptor store, exposed for debugging and inspection.

    :param functions:      Optional iterable of Function objects or addresses to restrict the analysis to.
    :param fail_fast:      Re-raise per-function exceptions instead of skipping the offending function.
    :param max_iterations: Cap on the interprocedural propagation fixed-point iterations.
    :param low_priority:   Periodically release the GIL during the per-function phase to stay responsive.
    """

    def __init__(
        self,
        functions=None,
        fail_fast: bool = False,
        max_iterations: int = 8,
        low_priority: bool = False,
    ):
        self._fail_fast_flag = fail_fast
        self._max_iterations = max_iterations
        self._low_priority = low_priority

        # abort support: set via abort(); checked between per-function analyses and inside the later phases so a
        # requested abort finalizes the partial results collected so far instead of dropping them.
        self._should_abort = False
        # counter driving the periodic GIL release in low-priority mode
        self._gil_ctr = 0

        self.resolved_indirect_jumps: dict[int, set[int]] = {}
        self.pointer_shapes: DescriptorStore = DescriptorStore()

        self._cfg_model: CFGModel | None = self._get_cfg_model()
        self._func_facts: dict[int, _FuncFacts] = {}
        # func_addr -> {param index -> param vvar}
        self._func_arg_vvars: dict[int, dict[int, ailment.Expr.VirtualVariable]] = {}
        # func_addr -> ins_addr of the indirect site, so get_resolutions() can slice results by function
        self._site_to_func: dict[int, int] = {}
        # lazily-built stack-pointer trackers, keyed by function address
        self._spt_cache: dict[int, Any] = {}
        # cached integer argument-register offsets for the target arch
        self._arg_reg_offsets: set[int] | None = None

        self._selected_funcs = self._select_functions(functions)

        self._analyze()

    #
    # Public methods
    #

    @property
    def should_abort(self) -> bool:
        """
        Whether an abort of this analysis has been requested.
        """
        return self._should_abort

    def abort(self) -> None:
        """
        Request the analysis to stop as soon as possible. This is safe to call from another thread (e.g. a GUI thread).
        The analysis stops launching new per-function analyses and finalizes whatever partial results have been
        collected so far, so ``resolved_indirect_jumps`` remains valid (though possibly incomplete) afterwards.
        """
        self._should_abort = True

    def get_resolutions(self, func) -> dict[int, set[int]]:
        """
        Return the subset of ``resolved_indirect_jumps`` whose sites lie inside the given function.

        :param func: A Function object or a function address.
        :return:     A dict mapping indirect-site instruction addresses to sets of resolved target function addresses.
        """
        func_addr = func.addr if hasattr(func, "addr") else func
        return {
            ins_addr: targets
            for ins_addr, targets in self.resolved_indirect_jumps.items()
            if self._site_to_func.get(ins_addr) == func_addr
        }

    #
    # Setup helpers
    #

    def _get_cfg_model(self) -> CFGModel | None:
        try:
            cfg = self.kb.cfgs.get_most_accurate()
        except Exception:  # pylint:disable=broad-except
            cfg = None
        if cfg is None:
            return None
        return cfg.model if hasattr(cfg, "model") else cfg

    def _select_functions(self, functions) -> list[Function]:
        if functions is not None:
            selected = []
            for f in functions:
                func = self.kb.functions.get_by_addr(f) if isinstance(f, int) else f
                selected.append(func)
            return [f for f in selected if self._is_real_function(f)]
        return [f for f in self.kb.functions.values() if self._is_real_function(f)]

    @staticmethod
    def _is_real_function(func: Function) -> bool:
        return not (func is None or func.is_plt or func.is_simprocedure or func.is_syscall or func.is_alignment)

    #
    # Analysis driver
    #

    def _analyze(self):
        # Phase A dominates the runtime (a Clinic run per function), so it owns most of the progress budget; the
        # cheap interprocedural phases share the remainder.
        total = len(self._selected_funcs)

        # Phase A: per-function intra-procedural shape extraction
        for i, func in enumerate(self._selected_funcs):
            if self._should_abort:
                l.info(
                    "FullProgramIndirectJumpResolution aborted after %d/%d functions; finalizing partial results.",
                    i,
                    total,
                )
                break
            if total:
                self._update_progress(
                    i * 90.0 / total,
                    text=f"Analyzing function {i + 1}/{total} at {func.addr:#x}",
                    analysis=self,
                )
            try:
                self._analyze_function(func)
            except Exception:  # pylint:disable=broad-except
                if self._fail_fast_flag:
                    raise
                l.warning("Failed to analyze function %#x for indirect jump resolution.", func.addr, exc_info=True)
            if self._low_priority:
                self._gil_ctr += 1
                self._release_gil(self._gil_ctr, 1)

        # The remaining phases are cheap relative to Phase A and bounded by the facts already collected, so they run to
        # completion even after an abort in order to turn those partial facts into the best resolutions possible.

        # Phase B: interprocedural pointer-shape propagation (fixed point)
        self._update_progress(90.0, text="Propagating pointer shapes", analysis=self)
        self._propagate_interproc()

        # Phase C: harvest global tables now that strides/fields have settled
        self._update_progress(95.0, text="Harvesting global tables", analysis=self)
        self._harvest_global_tables()

        # Phase D: resolve indirect sites
        self._update_progress(98.0, text="Resolving indirect jumps", analysis=self)
        self._resolve_sites()

        self._finish_progress()

    #
    # Phase A: intra-procedural extraction
    #

    def _analyze_function(self, func: Function) -> None:
        clinic = self.project.analyses.Clinic(
            func,
            cfg=self._cfg_model,
            end_stage=ClinicStage.POST_SSA_LEVEL1_SIMPLIFICATIONS,
            fail_fast=self._fail_fast_flag,
        )
        graph = clinic.graph
        if graph is None:
            return

        facts = _FuncFacts(func.addr)
        self._func_facts[func.addr] = facts

        # record parameter vvars and seed their regions
        arg_vvars: dict[int, ailment.Expr.VirtualVariable] = {}
        if clinic.arg_vvars:
            for idx, (param_vvar, _simvar) in clinic.arg_vvars.items():
                arg_vvars[idx] = param_vvar
                region = UnknownRegion(func.addr, f"param{idx}")
                facts.arg_param_regions[idx] = region
                facts.vvar_region[param_vvar.varid] = region
                # ensure the region exists in the store
                self.pointer_shapes.descriptor(region)
        self._func_arg_vvars[func.addr] = arg_vvars

        # iterate the intra-procedural pass to a fixed point (SSA copies/phis may be seen out of order)
        for _ in range(4):
            changed = self._extract_shapes(func, graph, facts)
            if not changed:
                break

        # resolve call arguments that are undefined register vvars (e.g., a stack pointer that survives a call via
        # IPA register allocation, whose SSA definition was killed at the call boundary) into stack regions using the
        # stack-pointer tracker
        self._resolve_register_stack_args(func, graph, facts)

    def _extract_shapes(self, func: Function, graph, facts: _FuncFacts) -> bool:
        changed = False
        # reset the site list; it is fully rebuilt each pass
        facts.indirect_sites = []
        facts.call_bindings = []
        for block in graph.nodes():
            for stmt in block.statements:
                changed |= self._handle_statement(func, facts, stmt)
        return changed

    def _handle_statement(self, func: Function, facts: _FuncFacts, stmt) -> bool:
        changed = False

        # vvar definitions
        if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.dst, ailment.Expr.VirtualVariable):
            changed |= self._handle_definition(func, facts, stmt.dst.varid, stmt.src)

        # stores: record field accesses and stored code pointers
        if isinstance(stmt, ailment.Stmt.Store):
            changed |= self._handle_memory_access(func, facts, stmt.addr, stmt.size, store_data=stmt.data)

        # loads embedded anywhere in the statement: record field accesses
        loads = _collect_loads(stmt)
        for load in loads:
            changed |= self._handle_memory_access(func, facts, load.addr, load.size, store_data=None)

        # calls (both bare SideEffectStatements and call expressions embedded in returns/assignments)
        for call, call_ins in _collect_calls(stmt):
            changed |= self._handle_call(func, facts, call, call_ins)

        # indirect jumps
        if isinstance(stmt, ailment.Stmt.Jump) and not isinstance(stmt.target, ailment.Expr.Const):
            ins_addr = _ins_addr_of(stmt)
            if ins_addr is not None:
                facts.indirect_sites.append((ins_addr, "jump", stmt.target))

        # indirect conditional jumps (rare at this level, but be safe)
        if isinstance(stmt, ailment.Stmt.ConditionalJump):
            for tgt in (stmt.true_target, stmt.false_target):
                if tgt is not None and not isinstance(tgt, ailment.Expr.Const):
                    ins_addr = _ins_addr_of(stmt)
                    if ins_addr is not None:
                        facts.indirect_sites.append((ins_addr, "jump", tgt))

        return changed

    def _handle_definition(self, func: Function, facts: _FuncFacts, varid: int, src) -> bool:
        """
        Track what a vvar was defined as: a pointer to a region, or a direct code-pointer value.
        """
        changed = False

        # direct constant: either a code pointer (function start) or a data-region pointer
        if isinstance(src, ailment.Expr.Const):
            val = src.value
            if isinstance(val, int):
                if self._is_function_start(val):
                    changed |= self._add_codeptr(facts, varid, val)
                elif self._is_global_data_addr(val):
                    changed |= self._set_region(facts, varid, GlobalRegion(val))
            return changed

        # stack pointer
        if isinstance(src, ailment.Expr.StackBaseOffset):
            return self._set_region(facts, varid, StackRegion(func.addr, src.offset))

        # &stack_var  (Reference of a stack vvar)
        stack_off = _stack_ref_offset(src)
        if stack_off is not None:
            return self._set_region(facts, varid, StackRegion(func.addr, stack_off))

        # copy / conversion of another vvar
        inner = _unwrap_copy(src)
        if isinstance(inner, ailment.Expr.VirtualVariable):
            region = facts.vvar_region.get(inner.varid)
            if region is not None:
                changed |= self._set_region(facts, varid, region)
            codeptrs = facts.vvar_codeptrs.get(inner.varid)
            if codeptrs:
                changed |= self._add_codeptrs(facts, varid, codeptrs)
            return changed

        # phi / ITE of vvars or constants -> union of possibilities
        for operand in _phi_ite_operands(src):
            unwrapped = _unwrap_copy(operand)
            if isinstance(unwrapped, ailment.Expr.Const) and isinstance(unwrapped.value, int):
                if self._is_function_start(unwrapped.value):
                    changed |= self._add_codeptr(facts, varid, unwrapped.value)
            elif isinstance(unwrapped, ailment.Expr.VirtualVariable):
                region = facts.vvar_region.get(unwrapped.varid)
                if region is not None:
                    changed |= self._set_region(facts, varid, region)
                codeptrs = facts.vvar_codeptrs.get(unwrapped.varid)
                if codeptrs:
                    changed |= self._add_codeptrs(facts, varid, codeptrs)

        # allocation call results
        if isinstance(src, ailment.Expr.Call) and isinstance(src.target, ailment.Expr.Const):
            callee = self._function_name(src.target.value)
            if callee in _ALLOC_FUNCS:
                ins_addr = _ins_addr_of(src)
                if ins_addr is not None:
                    region = HeapRegion(ins_addr)
                    changed |= self._set_region(facts, varid, region)
                    desc = self.pointer_shapes.descriptor(region)
                    size = _concrete_alloc_size(src)
                    if size is not None and (desc.alloc_size is None or size > desc.alloc_size):
                        desc.alloc_size = size
                        changed = True

        return changed

    def _handle_memory_access(self, func: Function, facts: _FuncFacts, addr_expr, size, store_data) -> bool:
        """
        Decompose a Load/Store address into (base region, constant offset, stride) and record a field access.
        """
        base, base_addr, offset, stride = _decompose_address(addr_expr)
        if base is not None:
            region = self._region_of_expr(func, facts, base)
        elif base_addr is not None and self._is_global_data_addr(base_addr):
            region = GlobalRegion(base_addr)
        else:
            region = None
        if region is None:
            return False

        changed = False
        desc = self.pointer_shapes.descriptor(region)
        if stride is not None:
            changed |= desc.set_stride(stride)

        field_off = desc.normalize_offset(offset)
        fa = desc.field(field_off)
        if size is not None and (fa.size is None or size > fa.size):
            fa.size = size
            changed = True

        # a store of a concrete function address -> code pointer field
        if store_data is not None:
            for val in self._codeptr_values_of(facts, store_data):
                if not fa.is_code_pointer:
                    fa.is_code_pointer = True
                    changed = True
                if val not in fa.stored_values:
                    fa.stored_values.add(val)
                    changed = True

        return changed

    def _handle_call(self, func: Function, facts: _FuncFacts, call, call_ins) -> bool:
        changed = False

        # indirect call site
        if not isinstance(call.target, ailment.Expr.Const):
            if call_ins is not None and (call_ins, "call", call.target) not in facts.indirect_sites:
                facts.indirect_sites.append((call_ins, "call", call.target))
            return changed

        callee_addr = call.target.value
        if not isinstance(callee_addr, int):
            return changed

        # record argument-region bindings for interproc propagation
        arg_regions: list[MemoryRegion | None] = []
        if call.args:
            for arg in call.args:
                arg_regions.append(self._region_of_expr(func, facts, arg))
        facts.call_bindings.append((callee_addr, arg_regions))
        return changed

    def _resolve_register_stack_args(self, func: Function, graph, facts: _FuncFacts) -> None:
        """
        For direct calls whose pointer argument is an undefined register vvar (its SSA definition was killed at a call
        boundary, e.g., a stack pointer preserved across a call by IPA register allocation), use the stack-pointer
        tracker to recover the stack offset the register holds at the call site, and bind the callee parameter to that
        stack region.
        """
        pending: list[tuple[int, int, int, int]] = []  # (callee_addr, arg_idx, ins_addr, reg_offset)
        for block in graph.nodes():
            for stmt in block.statements:
                for call, call_ins in _collect_calls(stmt):
                    if call_ins is None or not isinstance(call.target, ailment.Expr.Const):
                        continue
                    callee_addr = call.target.value
                    if not isinstance(callee_addr, int) or not call.args:
                        continue
                    for idx, arg in enumerate(call.args):
                        if self._region_of_expr(func, facts, arg) is not None:
                            continue
                        reg_off = _register_arg_offset(arg)
                        if reg_off is not None:
                            pending.append((callee_addr, idx, call_ins, reg_off))

        if not pending:
            return

        spt = self._get_spt(func)
        if spt is None:
            return

        for callee_addr, idx, ins_addr, reg_off in pending:
            region = self._stack_region_via_spt(func, spt, ins_addr, reg_off)
            if region is not None:
                # append a partial binding carrying just this argument
                arg_regions: list[MemoryRegion | None] = [None] * (idx + 1)
                arg_regions[idx] = region
                facts.call_bindings.append((callee_addr, arg_regions))

    def _get_spt(self, func: Function):
        if func.addr in self._spt_cache:
            return self._spt_cache[func.addr]
        spt = None
        sp_offset = self.project.arch.sp_offset
        reg_offsets = {sp_offset} | self._int_arg_reg_offsets()
        try:
            spt = self.project.analyses.StackPointerTracker(func, reg_offsets, track_memory=False)
        except Exception:  # pylint:disable=broad-except
            spt = None
        self._spt_cache[func.addr] = spt
        return spt

    def _int_arg_reg_offsets(self) -> set[int]:
        if self._arg_reg_offsets is not None:
            return self._arg_reg_offsets
        offsets: set[int] = set()
        arch = self.project.arch
        try:
            cc = self.project.factory.cc()
            names = list(getattr(cc, "ARG_REGS", []) or [])
        except Exception:  # pylint:disable=broad-except
            names = []
        for name in names:
            reg = arch.registers.get(name)
            if reg is not None:
                offsets.add(reg[0])
        self._arg_reg_offsets = offsets
        return offsets

    def _stack_region_via_spt(self, func: Function, spt, ins_addr: int, reg_offset: int) -> MemoryRegion | None:
        """
        Query the stack-pointer tracker for the value of ``reg_offset`` at ``ins_addr``; if it is the stack pointer
        plus a constant, return the corresponding StackRegion.
        """
        sp_offset = self.project.arch.sp_offset
        try:
            regval = spt._value_for(ins_addr, "pre", spt.reg_values, spt.reg_deltas, reg_offset)
        except Exception:  # pylint:disable=broad-except
            return None
        base_reg = getattr(regval, "reg", None)
        raw_offset = getattr(regval, "offset", None)
        if base_reg is None or raw_offset is None:
            return None
        if getattr(base_reg, "offset", None) != sp_offset:
            return None
        signed = _to_signed(raw_offset, self.project.arch.bits)
        return StackRegion(func.addr, signed)

    #
    # Region / value resolution helpers
    #

    def _region_of_expr(self, func: Function, facts: _FuncFacts, expr) -> MemoryRegion | None:
        """
        Determine which memory region a pointer expression refers to.
        """
        expr = _unwrap_copy(expr)

        if isinstance(expr, ailment.Expr.VirtualVariable):
            return facts.vvar_region.get(expr.varid)

        if isinstance(expr, ailment.Expr.Const) and isinstance(expr.value, int):
            if self._is_global_data_addr(expr.value):
                return GlobalRegion(expr.value)
            return None

        if isinstance(expr, ailment.Expr.StackBaseOffset):
            return StackRegion(func.addr, expr.offset)

        stack_off = _stack_ref_offset(expr)
        if stack_off is not None:
            return StackRegion(func.addr, stack_off)

        # base of an add-with-index: e.g., table + idx*scale
        base, base_addr, _offset, _stride = _decompose_address(expr)
        if base is not None and base is not expr:
            return self._region_of_expr(func, facts, base)
        if base_addr is not None and self._is_global_data_addr(base_addr):
            return GlobalRegion(base_addr)

        return None

    def _codeptr_values_of(self, facts: _FuncFacts, expr) -> set[int]:
        """
        Extract the set of concrete code-pointer values that a stored value expression may evaluate to.
        """
        result: set[int] = set()
        expr = _unwrap_copy(expr)
        if isinstance(expr, ailment.Expr.Const) and isinstance(expr.value, int) and self._is_function_start(expr.value):
            result.add(expr.value)
        elif isinstance(expr, ailment.Expr.VirtualVariable):
            result |= facts.vvar_codeptrs.get(expr.varid, set())
        else:
            for operand in _phi_ite_operands(expr):
                result |= self._codeptr_values_of(facts, operand)
        return result

    def _set_region(self, facts: _FuncFacts, varid: int, region: MemoryRegion) -> bool:
        if facts.vvar_region.get(varid) == region:
            return False
        facts.vvar_region[varid] = region
        self.pointer_shapes.descriptor(region)
        return True

    @staticmethod
    def _add_codeptr(facts: _FuncFacts, varid: int, value: int) -> bool:
        s = facts.vvar_codeptrs.setdefault(varid, set())
        if value in s:
            return False
        s.add(value)
        return True

    @staticmethod
    def _add_codeptrs(facts: _FuncFacts, varid: int, values: set[int]) -> bool:
        s = facts.vvar_codeptrs.setdefault(varid, set())
        if values <= s:
            return False
        s |= values
        return True

    #
    # Phase B: interprocedural propagation
    #

    def _propagate_interproc(self) -> None:
        for _ in range(self._max_iterations):
            changed = False
            for facts in self._func_facts.values():
                for callee_addr, arg_regions in facts.call_bindings:
                    callee_params = self._func_facts.get(callee_addr)
                    if callee_params is None:
                        continue
                    for idx, arg_region in enumerate(arg_regions):
                        if arg_region is None:
                            continue
                        param_region = callee_params.arg_param_regions.get(idx)
                        if param_region is None:
                            continue
                        changed |= self.pointer_shapes.union(arg_region, param_region)
            if not changed:
                break

    #
    # Phase C: global table harvesting
    #

    def _harvest_global_tables(self) -> None:
        for region, desc in list(self.pointer_shapes.items()):
            if not isinstance(region, GlobalRegion):
                continue
            self._harvest_global_table(region, desc)

    def _harvest_global_table(self, region: GlobalRegion, desc: PointerShapeDescriptor) -> None:
        base = region.addr
        ptr_size = self.project.arch.bytes
        section = self.project.loader.find_section_containing(base)
        sec_end = (section.vaddr + section.memsize) if section is not None else None

        # code-pointer field offsets: those fields we recorded as code pointers, or - for a plain load with no
        # store evidence - every field whose size matches the pointer size
        code_offsets = {off for off, fa in desc.fields.items() if fa.is_code_pointer}
        if not code_offsets:
            code_offsets = {off for off, fa in desc.fields.items() if fa.size == ptr_size}
        if not code_offsets:
            code_offsets = {0}

        stride = desc.stride if desc.stride and desc.stride > 0 else None

        for field_off in code_offsets:
            fa = desc.field(field_off)
            if stride is not None:
                # walk the table entry by entry
                k = 0
                while True:
                    addr = base + k * stride + field_off
                    if sec_end is not None and addr + ptr_size > sec_end:
                        break
                    if k > 0 and self._symbol_boundary_crossed(base, addr):
                        break
                    word = self._read_word(addr, ptr_size)
                    if word is None or not self._is_function_start(word):
                        break
                    fa.is_code_pointer = True
                    fa.stored_values.add(word)
                    k += 1
            else:
                # single fixed-offset global function pointer
                addr = base + field_off
                if sec_end is not None and addr + ptr_size > sec_end:
                    continue
                word = self._read_word(addr, ptr_size)
                if word is not None and self._is_function_start(word):
                    fa.is_code_pointer = True
                    fa.stored_values.add(word)

    def _symbol_boundary_crossed(self, base: int, addr: int) -> bool:
        """
        Return True if ``addr`` lies at or beyond the next symbol boundary after ``base``.
        """
        try:
            base_sym = self.project.loader.find_symbol(base)
        except Exception:  # pylint:disable=broad-except
            base_sym = None
        if base_sym is not None and base_sym.size:
            return addr >= base_sym.rebased_addr + base_sym.size
        return False

    def _read_word(self, addr: int, size: int) -> int | None:
        try:
            return self.project.loader.memory.unpack_word(addr, size)
        except Exception:  # pylint:disable=broad-except
            return None

    #
    # Phase D: resolution
    #

    def _resolve_sites(self) -> None:
        for func_addr, facts in self._func_facts.items():
            for ins_addr, _kind, target in facts.indirect_sites:
                targets = self._evaluate_target(facts, target)
                targets = {t for t in targets if self._is_valid_target(t)}
                if targets:
                    self.resolved_indirect_jumps.setdefault(ins_addr, set()).update(targets)
                    self._site_to_func[ins_addr] = func_addr

    def _evaluate_target(self, facts: _FuncFacts, target) -> set[int]:
        target = _unwrap_copy(target)

        # ITE / phi of constants (scenario 4) or vvars carrying code pointers
        result: set[int] = set()

        # a vvar directly carrying code pointers
        if isinstance(target, ailment.Expr.VirtualVariable):
            result |= facts.vvar_codeptrs.get(target.varid, set())
            region = facts.vvar_region.get(target.varid)
            if region is not None:
                result |= self._codeptrs_from_region(region)
            if result:
                return result

        # a load from a table/struct field
        if isinstance(target, ailment.Expr.Load):
            base, base_addr, offset, _stride = _decompose_address(target.addr)
            region = None
            if base is not None:
                region = self._region_of_target_base(facts, base)
            elif base_addr is not None:
                region = GlobalRegion(base_addr)
            if region is not None:
                desc = self.pointer_shapes.get(region)
                if desc is not None:
                    field_off = desc.normalize_offset(offset)
                    fa = desc.fields.get(field_off)
                    if fa is not None:
                        result |= fa.stored_values
            return result

        # ITE / phi of constants directly at the target
        for operand in _phi_ite_operands(target):
            result |= self._evaluate_target(facts, operand)
        if (
            isinstance(target, ailment.Expr.Const)
            and isinstance(target.value, int)
            and self._is_function_start(target.value)
        ):
            result.add(target.value)

        return result

    def _region_of_target_base(self, facts: _FuncFacts, base) -> MemoryRegion | None:
        base = _unwrap_copy(base)
        if isinstance(base, ailment.Expr.Const) and isinstance(base.value, int):
            return GlobalRegion(base.value)
        if isinstance(base, ailment.Expr.VirtualVariable):
            return facts.vvar_region.get(base.varid)
        return None

    def _codeptrs_from_region(self, region: MemoryRegion) -> set[int]:
        desc = self.pointer_shapes.get(region)
        if desc is None:
            return set()
        result: set[int] = set()
        for fa in desc.fields.values():
            result |= fa.stored_values
        return result

    #
    # kb / loader predicates
    #

    def _is_function_start(self, addr: int) -> bool:
        if not isinstance(addr, int):
            return False
        if self.kb.functions.contains_addr(addr):
            return True
        if self._cfg_model is not None:
            node = self._cfg_model.get_any_node(addr)
            if node is not None and node.addr == addr:
                return True
        return False

    def _is_valid_target(self, addr: int) -> bool:
        if self._is_function_start(addr):
            return True
        section = self.project.loader.find_section_containing(addr)
        return section is not None and section.is_executable

    def _is_global_data_addr(self, addr: int) -> bool:
        if self._is_function_start(addr):
            return False
        section = self.project.loader.find_section_containing(addr)
        if section is None:
            # accept known symbols even without a section match
            try:
                return self.project.loader.find_symbol(addr) is not None
            except Exception:  # pylint:disable=broad-except
                return False
        return not section.is_executable

    def _function_name(self, addr) -> str | None:
        if not isinstance(addr, int):
            return None
        try:
            func = self.kb.functions.get_by_addr(addr)
        except KeyError:
            return None
        return func.name if func is not None else None


#
# module-level AIL helpers
#


def _ins_addr_of(obj) -> int | None:
    tags = getattr(obj, "tags", None)
    if tags is None:
        return None
    return tags.get("ins_addr")


def _to_signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    if value >= (1 << (bits - 1)):
        value -= 1 << bits
    return value


def _register_arg_offset(expr) -> int | None:
    """
    If ``expr`` (after unwrapping) is a register-backed virtual variable, return its register offset, else None.
    """
    expr = _unwrap_copy(expr)
    if isinstance(expr, ailment.Expr.VirtualVariable):
        try:
            if expr.was_reg:
                return expr.reg_offset
        except Exception:  # pylint:disable=broad-except
            return None
    return None


def _unwrap_copy(expr):
    """
    Strip zero-cost wrappers (Convert, And-with-mask) to expose the underlying pointer/value expression.
    """
    seen = 0
    while expr is not None and seen < 8:
        seen += 1
        if isinstance(expr, ailment.Expr.Convert):
            expr = expr.operand
            continue
        # `x & 0xffffffff...` style zero-extension masks
        if isinstance(expr, ailment.Expr.BinaryOp) and expr.op == "And":
            a, b = expr.operands
            if isinstance(b, ailment.Expr.Const) and _is_low_mask(b.value):
                expr = a
                continue
            if isinstance(a, ailment.Expr.Const) and _is_low_mask(a.value):
                expr = b
                continue
        break
    return expr


def _is_low_mask(value) -> bool:
    return isinstance(value, int) and value > 0 and (value & (value + 1)) == 0


def _stack_ref_offset(expr) -> int | None:
    """
    If ``expr`` is ``Reference(stack_vvar)``, return the stack offset of the referenced vvar, else None.
    """
    if isinstance(expr, ailment.Expr.UnaryOp) and expr.op == "Reference":
        operand = expr.operand
        if isinstance(operand, ailment.Expr.VirtualVariable):
            try:
                if operand.was_stack:
                    return operand.stack_offset
            except Exception:  # pylint:disable=broad-except
                return None
    return None


def _phi_ite_operands(expr):
    """
    Yield the value operands of a Phi or ITE expression.
    """
    if isinstance(expr, ailment.Expr.Phi):
        for _src, vvar in expr.src_and_vvars:
            if vvar is not None:
                yield vvar
    elif isinstance(expr, ailment.Expr.ITE):
        yield expr.iftrue
        yield expr.iffalse


def _decompose_address(addr_expr):
    """
    Decompose a memory address expression into ``(base_expr, base_addr, constant_offset, stride)``.

    - ``base_expr``: the symbolic base expression (a vvar, stack pointer, ...), unwrapped from Convert/masks, or None
      when the base is a pure constant address.
    - ``base_addr``: the integer base address when the base is a pure constant (a global table); otherwise None. When
      present, all constant terms are folded into it and ``constant_offset`` is 0, so harvesting can simply walk
      ``base_addr + k*stride``.
    - ``constant_offset``: the constant field offset relative to a symbolic base.
    - ``stride``: the element stride recovered from an indexed term ``idx*scale`` / ``idx << shift``.

    Handles ``base``, ``base + const``, ``base + idx*scale``, ``base + (idx*scale + off)``, ``base + idx*scale + off``,
    and the pure-global variants ``const + idx*scale (+ off)``.
    """
    addr_expr = _unwrap_copy(addr_expr)

    if not (isinstance(addr_expr, ailment.Expr.BinaryOp) and addr_expr.op in ("Add", "Sub")):
        if isinstance(addr_expr, ailment.Expr.Const) and isinstance(addr_expr.value, int):
            return None, addr_expr.value, 0, None
        return addr_expr, None, 0, None

    offset = 0
    stride: int | None = None
    base = None
    ambiguous = False

    # flatten the Add/Sub chain into additive terms
    for term, sign in _flatten_add(addr_expr):
        term = _unwrap_copy(term)
        if isinstance(term, ailment.Expr.Const) and isinstance(term.value, int):
            offset += sign * term.value
            continue
        s = _index_scale(term)
        if s is not None:
            stride = s if stride is None else stride
            continue
        # otherwise this term is (part of) the base
        if base is None:
            base = term
        else:
            # more than one non-index base term; give up on a precise base
            base = None
            ambiguous = True
            break

    if ambiguous:
        return None, None, offset, stride
    if base is None:
        # a pure-constant base (global table): fold all constant terms into the base address
        return None, offset, 0, stride
    return base, None, offset, stride


def _flatten_add(expr, sign: int = 1):
    """
    Flatten a nested Add/Sub tree into ``(term, sign)`` pairs.
    """
    if isinstance(expr, ailment.Expr.BinaryOp) and expr.op in ("Add", "Sub"):
        a, b = expr.operands
        yield from _flatten_add(_unwrap_copy(a), sign)
        yield from _flatten_add(_unwrap_copy(b), sign if expr.op == "Add" else -sign)
    else:
        yield expr, sign


def _index_scale(expr) -> int | None:
    """
    If ``expr`` is an indexed term ``idx * scale`` or ``idx << shift``, return ``scale``. Otherwise None.
    """
    expr = _unwrap_copy(expr)
    if not isinstance(expr, ailment.Expr.BinaryOp):
        return None
    if expr.op == "Mul":
        a, b = expr.operands
        if isinstance(b, ailment.Expr.Const) and isinstance(b.value, int):
            return b.value
        if isinstance(a, ailment.Expr.Const) and isinstance(a.value, int):
            return a.value
    if expr.op == "Shl":
        _a, b = expr.operands
        if isinstance(b, ailment.Expr.Const) and isinstance(b.value, int):
            return 1 << b.value
    return None


def _collect_loads(stmt) -> list:
    """
    Collect all Load expressions appearing anywhere inside a statement.
    """
    collector = _ExprCollector(ailment.Expr.Load)
    collector.walk(stmt)
    return collector.results


def _collect_calls(stmt) -> list[tuple[Any, int | None]]:
    """
    Collect all Call expressions inside a statement, paired with their instruction address.
    """
    collector = _ExprCollector(ailment.Expr.Call)
    collector.walk(stmt)
    return [(c, _ins_addr_of(c) or _ins_addr_of(stmt)) for c in collector.results]


class _ExprCollector(AILBlockViewer):
    """
    Walk a single statement and collect every expression that is an instance of ``expr_cls``.
    """

    def __init__(self, expr_cls):
        super().__init__()
        self._expr_cls = expr_cls
        self.results: list = []

    def walk(self, stmt):  # type: ignore[override]
        self.walk_statement(stmt)

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr, self._expr_cls):
            self.results.append(expr)
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def _concrete_alloc_size(call) -> int | None:
    """
    Best-effort extraction of a concrete allocation size from a malloc/calloc call.
    """
    if not call.args:
        return None
    consts = []
    for arg in call.args:
        arg = _unwrap_copy(arg)
        if isinstance(arg, ailment.Expr.Const) and isinstance(arg.value, int):
            consts.append(arg.value)
        else:
            consts.append(None)
    # calloc(n, size) -> n*size; malloc(size) -> size
    if len(consts) >= 2 and consts[0] is not None and consts[1] is not None:
        return consts[0] * consts[1]
    if consts and consts[0] is not None:
        return consts[0]
    return None


AnalysesHub.register_default("FullProgramIndirectJumpResolution", FullProgramIndirectJumpResolution)
