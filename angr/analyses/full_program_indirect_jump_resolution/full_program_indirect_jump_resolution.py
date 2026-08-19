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


# smallest value accepted as a pointer into unmapped memory (RAM, memory-mapped peripherals) in a raw image; below
# this, a constant is far more likely to be a plain integer literal
_MIN_UNMAPPED_DATA_ADDR = 0x1000

# upper bound on how many entries of a global pointer table are walked when following a run-time index
_MAX_TABLE_ENTRIES = 256

# names of allocation functions whose return value is a fresh heap region
_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "xmalloc", "xcalloc", "_Znwm", "_Znam"}


class _FuncFacts:
    """
    Per-function facts extracted during the intra-procedural pass.
    """

    __slots__ = (
        "arg_param_regions",
        "call_arg_codeptrs",
        "call_bindings",
        "copy_edges",
        "func_addr",
        "indirect_sites",
        "load_edges",
        "return_regions",
        "store_edges",
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
        #
        # Dataflow skeleton. Code-pointer values often only become known after interprocedural propagation (a callback
        # is passed as an argument, stored into a global by the callee, and invoked from a third function). Re-running
        # the AIL walk for every fixed-point round would mean holding every function's AIL graph in memory, so the
        # intra-procedural pass instead records the few edges that matter and the fixed point replays those.
        #
        # dst_varid <- src_varid, from copies/conversions/phis/ITEs
        self.copy_edges: list[tuple[int, int]] = []
        # dst_varid <- (region, field offset), from ``vvar = Load(...)``
        self.load_edges: list[tuple[MemoryRegion, int, int]] = []
        # (region, field offset) <- src_varid, from ``Store(..., data=vvar)``
        self.store_edges: list[tuple[MemoryRegion, int, int]] = []
        # (callee_addr, {arg index: (src varid or None, immediately-known code pointers)}) recorded at direct calls
        self.call_arg_codeptrs: list[tuple[int, dict[int, tuple[int | None, frozenset[int]]]]] = []


class FullProgramIndirectJumpResolution(Analysis):
    """
    Resolves indirect jumps and calls across a whole binary using AIL-level pointer-shape analysis.

    For each real function the analysis lifts a simplified AIL graph (via Clinic, stopping before variable recovery
    and structuring) and extracts *pointer shapes*: which memory regions pointers point to, which concrete code
    pointers get stored into which fields of those regions, and the element stride of indexed table accesses. Global
    tables are additionally harvested by reading initialized program memory. Pointer shapes are then propagated
    interprocedurally across the call graph (caller argument regions are unioned with callee parameter regions) to a
    fixed point. Concrete code-pointer values are propagated along the same fixed point: through copies, into and out
    of the fields of global structs and arrays, and across call arguments into callee parameters. That is what
    recovers callbacks registered at run time, where a function pointer is passed to a registration function, stored
    into a global by it, and finally invoked from a third function such as an interrupt handler. Pointers stored in
    memory are tracked too (a field records which region its pointer points to, falling back to the statically
    initialized contents of the binary), so chained dereferences like ``dev->driver->read`` can be followed. Finally,
    every indirect jump/call target expression is evaluated against the collected shapes to recover the set of
    possible target functions.

    Only entry points of functions are ever reported as targets, so jump tables -- which hold basic-block addresses --
    are deliberately not resolved here; CFGFast's jump-table resolvers already handle those.

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
        # a raw image (no section table) needs a different notion of what a data address is
        main_object = self.project.loader.main_object
        self._sectionless_image: bool = main_object is not None and not main_object.sections
        self._recovered_code_cache: dict[int, bool] = {}

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
        # Stop right after the level-1 SSA transformation, before the post-SSA-level-1 simplification round. That final
        # round is the single most expensive slice of the per-function decompilation (profiled at ~25% of the analysis
        # on libc) yet contributes nothing to indirect-jump resolution: a whole-binary A/B on libc.so.6 found the SSA
        # form produced here already exposes every pointer shape the post-round would (39/39 sites, 64/64 targets
        # identical), so stopping here is byte-for-byte resolution-equivalent while ~25% faster. Do not drop to
        # PRE_SSA_LEVEL1_SIMPLIFICATIONS: without the level-1 transform two libc sites stop resolving.
        clinic = self.project.analyses.Clinic(
            func,
            cfg=self._cfg_model,
            end_stage=ClinicStage.SSA_LEVEL1_TRANSFORMATION,
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
        # reset the site list and the dataflow skeleton; both are fully rebuilt each pass
        facts.indirect_sites = []
        facts.call_bindings = []
        facts.copy_edges = []
        facts.load_edges = []
        facts.store_edges = []
        facts.call_arg_codeptrs = []
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
            facts.copy_edges.append((varid, inner.varid))
            region = facts.vvar_region.get(inner.varid)
            if region is not None:
                changed |= self._set_region(facts, varid, region)
            codeptrs = facts.vvar_codeptrs.get(inner.varid)
            if codeptrs:
                changed |= self._add_codeptrs(facts, varid, codeptrs)
            return changed

        # a value loaded out of a region field: remember where it came from so that code pointers written into that
        # field (possibly by another function, and possibly only discovered later) flow into this vvar
        if isinstance(inner, ailment.Expr.Load):
            load_region, load_off = self._region_and_offset_of_address(func, facts, inner.addr)
            if load_region is not None:
                facts.load_edges.append((load_region, load_off, varid))
                desc = self.pointer_shapes.get(load_region)
                if desc is not None:
                    fa = desc.fields.get(load_off)
                    if fa is not None and fa.stored_values:
                        changed |= self._add_codeptrs(facts, varid, fa.stored_values)
            return changed

        # phi / ITE of vvars or constants -> union of possibilities
        for operand in _phi_ite_operands(src):
            unwrapped = _unwrap_copy(operand)
            if isinstance(unwrapped, ailment.Expr.Const) and isinstance(unwrapped.value, int):
                if self._is_function_start(unwrapped.value):
                    changed |= self._add_codeptr(facts, varid, unwrapped.value)
            elif isinstance(unwrapped, ailment.Expr.VirtualVariable):
                facts.copy_edges.append((varid, unwrapped.varid))
                region = facts.vvar_region.get(unwrapped.varid)
                if region is not None:
                    changed |= self._set_region(facts, varid, region)
                codeptrs = facts.vvar_codeptrs.get(unwrapped.varid)
                if codeptrs:
                    changed |= self._add_codeptrs(facts, varid, codeptrs)

        # address arithmetic that yields a pointer into a known region, e.g. ``table + idx * elem_size``. Only a
        # zero constant offset is accepted: a vvar is tracked by region alone, so a pointer into the middle of an
        # element would make every field recorded through it come out shifted.
        if isinstance(src, ailment.Expr.BinaryOp):
            base, base_addr, offset, stride = _decompose_address(src)
            if offset == 0 and (base is not None or base_addr is not None):
                region = self._region_of_expr(func, facts, src)
                if region is not None:
                    changed |= self._set_region(facts, varid, region)
                    if stride is not None:
                        changed |= self.pointer_shapes.descriptor(region).set_stride(stride)

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

        region, offset = self._canonicalize_global(region, offset)
        changed = False
        desc = self.pointer_shapes.descriptor(region)
        if stride is not None:
            changed |= desc.set_stride(stride)

        field_off = desc.normalize_offset(offset)
        fa = desc.field(field_off)
        if size is not None and (fa.size is None or size > fa.size):
            fa.size = size
            changed = True

        # a store of a data pointer -> remember which region the field points to
        if store_data is not None:
            stored_region = self._region_of_expr(func, facts, store_data)
            if stored_region is not None and stored_region not in fa.pointed_regions:
                fa.pointed_regions.add(stored_region)
                changed = True

        # a store of a concrete function address -> code pointer field
        if store_data is not None:
            # remember the vvars feeding this store; their code-pointer sets may only be discovered later
            for src_varid in _codeptr_source_varids(store_data):
                facts.store_edges.append((region, offset, src_varid))
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
        arg_codeptrs: dict[int, tuple[int | None, frozenset[int]]] = {}
        if call.args:
            for idx, arg in enumerate(call.args):
                arg_regions.append(self._region_of_expr(func, facts, arg))
                # a function pointer passed as an argument: record both what we already know and where to look later
                immediate = frozenset(self._codeptr_values_of(facts, arg))
                unwrapped = _unwrap_copy(arg)
                src_varid = unwrapped.varid if isinstance(unwrapped, ailment.Expr.VirtualVariable) else None
                if immediate or src_varid is not None:
                    arg_codeptrs[idx] = (src_varid, immediate)
        facts.call_bindings.append((callee_addr, arg_regions))
        if arg_codeptrs:
            facts.call_arg_codeptrs.append((callee_addr, arg_codeptrs))
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

    @staticmethod
    def _canonicalize_global(region: MemoryRegion | None, offset: int):
        """
        Fold a constant offset into the address of a global region.

        ``_decompose_address()`` already folds every constant term into the base address when the base is a pure
        constant, so ``table + idx*16 + 8`` arrives as base ``table+8`` with offset 0. An access written against a
        symbolic base -- ``p = table + idx*16`` followed by ``p->field`` -- arrives as base ``table`` with offset 8
        instead. Folding both spellings the same way is what lets a store and a load of the very same location meet
        in the same descriptor.
        """
        if offset and isinstance(region, GlobalRegion):
            return GlobalRegion(region.addr + offset), 0
        return region, offset

    def _region_and_offset_of_address(self, func: Function, facts: _FuncFacts, addr_expr):
        """
        Resolve a memory address expression to the region it addresses and the raw constant offset into it. The offset
        is returned un-normalized because the region's stride may only be discovered later.
        """
        base, base_addr, offset, _stride = _decompose_address(addr_expr)
        if base is not None:
            region = self._region_of_expr(func, facts, base)
        elif base_addr is not None and self._is_global_data_addr(base_addr):
            region = GlobalRegion(base_addr)
        else:
            region = None
        if region is None:
            return None, 0
        region, offset = self._canonicalize_global(region, offset)
        self.pointer_shapes.descriptor(region)
        return region, offset

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

        # a pointer read out of memory: follow the points-to information of the field it was loaded from. This is
        # what makes chained dereferences such as ``dev->driver->read`` tractable.
        if isinstance(expr, ailment.Expr.Load):
            base_region, base_offset = self._region_and_offset_of_address(func, facts, expr.addr)
            if base_region is not None:
                return self._pointed_region(base_region, base_offset)
            return None

        # base of an add-with-index: e.g., table + idx*scale
        base, base_addr, _offset, _stride = _decompose_address(expr)
        if base is not None and base is not expr:
            return self._region_of_expr(func, facts, base)
        if base_addr is not None and self._is_global_data_addr(base_addr):
            return GlobalRegion(base_addr)

        return None

    def _pointed_regions(self, region: MemoryRegion, offset: int) -> set[MemoryRegion]:
        """
        Return the regions that the pointer stored at ``region + offset`` may point to.

        Recorded stores are used when present. For a global region the statically initialized contents of the binary
        are consulted as well, which covers driver structs and pointer tables living in read-only memory. When the
        region is an indexed table the whole table is walked, so that an access through a run-time index yields every
        entry rather than just the first.
        """
        result: set[MemoryRegion] = set()

        desc = self.pointer_shapes.get(region)
        if desc is not None:
            fa = desc.fields.get(desc.normalize_offset(offset))
            if fa is not None:
                result |= fa.pointed_regions

        representative = self.pointer_shapes.find(region)
        if isinstance(representative, GlobalRegion):
            ptr_size = self.project.arch.bytes
            base = representative.addr + offset
            stride = desc.stride if desc is not None and desc.indexed and desc.stride else None
            if stride is None:
                word = self._read_word(base, ptr_size)
                if word is not None and self._is_global_data_addr(word):
                    result.add(GlobalRegion(word))
            else:
                section = self.project.loader.find_section_containing(base)
                section_end = (section.vaddr + section.memsize) if section is not None else None
                addr = base
                for _ in range(_MAX_TABLE_ENTRIES):
                    if section_end is not None and addr + ptr_size > section_end:
                        break
                    if addr != base and self._symbol_boundary_crossed(base, addr):
                        break
                    word = self._read_word(addr, ptr_size)
                    if word is None or not self._is_global_data_addr(word):
                        break
                    result.add(GlobalRegion(word))
                    addr += stride
        return result

    def _pointed_region(self, region: MemoryRegion, offset: int) -> MemoryRegion | None:
        """
        Single-region view of :meth:`_pointed_regions`, for the region propagation that tracks one region per vvar.
        Several candidates are unioned, since the field may hold any of them.
        """
        candidates = sorted(self._pointed_regions(region, offset), key=repr)
        if not candidates:
            return None
        representative = candidates[0]
        for other in candidates[1:]:
            self.pointer_shapes.union(representative, other)
        return representative

    def _target_base_regions(self, facts: _FuncFacts, expr) -> set[MemoryRegion]:
        """
        Resolve the base of an indirect-call target expression to every region it may address. Unlike the propagation
        path this keeps all candidates, so a call through ``devs[i]->drv->read`` yields the handlers of every device
        rather than only the first.
        """
        expr = _unwrap_copy(expr)

        if isinstance(expr, ailment.Expr.Const) and isinstance(expr.value, int):
            return {GlobalRegion(expr.value)}
        if isinstance(expr, ailment.Expr.VirtualVariable):
            region = facts.vvar_region.get(expr.varid)
            return {region} if region is not None else set()
        if isinstance(expr, ailment.Expr.Load):
            base, base_addr, offset, _stride = _decompose_address(expr.addr)
            if base_addr is not None:
                bases = {GlobalRegion(base_addr)}
            elif base is not None:
                bases = self._target_base_regions(facts, base)
            else:
                bases = set()
            result: set[MemoryRegion] = set()
            for candidate in bases:
                canonical, canonical_offset = self._canonicalize_global(candidate, offset)
                result |= self._pointed_regions(canonical, canonical_offset)
            return result

        base, base_addr, _offset, _stride = _decompose_address(expr)
        if base_addr is not None:
            return {GlobalRegion(base_addr)}
        if base is not None and base is not expr:
            return self._target_base_regions(facts, base)
        return set()

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
            changed = self._propagate_regions()
            changed |= self._propagate_codeptrs()
            if not changed:
                break

    def _propagate_regions(self) -> bool:
        """
        Union each caller argument's region into the corresponding callee parameter's region.
        """
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
        return changed

    def _propagate_codeptrs(self) -> bool:
        """
        Propagate concrete code-pointer values through the dataflow skeleton recorded during the intra-procedural pass.

        This is what resolves callbacks that are registered at run time: a caller passes a function pointer as an
        argument, the callee stores it into a field of a global struct or array, and a third function (typically an
        interrupt handler) loads that field and calls it. None of those three steps sees a constant function address
        by itself, so the value has to be threaded across all of them.
        """
        changed = False

        # intra-procedural: replay copies, loads and stores until each function is locally stable
        for facts in self._func_facts.values():
            for _ in range(self._max_iterations):
                local_changed = False
                for dst_varid, src_varid in facts.copy_edges:
                    values = facts.vvar_codeptrs.get(src_varid)
                    if values:
                        local_changed |= self._add_codeptrs(facts, dst_varid, values)
                for region, offset, dst_varid in facts.load_edges:
                    desc = self.pointer_shapes.get(region)
                    if desc is None:
                        continue
                    fa = desc.fields.get(desc.normalize_offset(offset))
                    if fa is not None and fa.stored_values:
                        local_changed |= self._add_codeptrs(facts, dst_varid, fa.stored_values)
                for region, offset, src_varid in facts.store_edges:
                    desc = self.pointer_shapes.descriptor(region)
                    fa = desc.field(desc.normalize_offset(offset))
                    stored_region = facts.vvar_region.get(src_varid)
                    if stored_region is not None and stored_region not in fa.pointed_regions:
                        fa.pointed_regions.add(stored_region)
                        local_changed = True
                    values = facts.vvar_codeptrs.get(src_varid)
                    if not values:
                        continue
                    if not fa.is_code_pointer:
                        fa.is_code_pointer = True
                        local_changed = True
                    if not values <= fa.stored_values:
                        fa.stored_values |= values
                        local_changed = True
                if not local_changed:
                    break
                changed = True

        # interprocedural: a code pointer passed as an argument reaches the callee's parameter
        for facts in self._func_facts.values():
            for callee_addr, arg_map in facts.call_arg_codeptrs:
                callee_facts = self._func_facts.get(callee_addr)
                if callee_facts is None:
                    continue
                param_vvars = self._func_arg_vvars.get(callee_addr)
                if not param_vvars:
                    continue
                for idx, (src_varid, immediate) in arg_map.items():
                    param_vvar = param_vvars.get(idx)
                    if param_vvar is None:
                        continue
                    values = set(immediate)
                    if src_varid is not None:
                        values |= facts.vvar_codeptrs.get(src_varid, set())
                    if values:
                        changed |= self._add_codeptrs(callee_facts, param_vvar.varid, values)

        return changed

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
            if base_addr is not None:
                regions = {GlobalRegion(base_addr)}
            elif base is not None:
                regions = self._target_base_regions(facts, base)
            else:
                regions = set()
            for candidate in regions:
                region, field_offset = self._canonicalize_global(candidate, offset)
                observed: set[int] = set()
                desc = self.pointer_shapes.get(region)
                if desc is not None:
                    fa = desc.fields.get(desc.normalize_offset(field_offset))
                    if fa is not None:
                        observed |= fa.stored_values
                if observed:
                    result |= observed
                    continue
                # nothing was observed being written here; read the function pointer straight out of the binary,
                # which covers vtables and driver structs that live in initialized read-only memory
                representative = self.pointer_shapes.find(region)
                if isinstance(representative, GlobalRegion):
                    word = self._read_word(representative.addr + field_offset, self.project.arch.bytes)
                    if word is not None and self._is_function_start(word):
                        result.add(word)
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
        if isinstance(base, ailment.Expr.Load):
            func = self.kb.functions[facts.func_addr]
            inner_region, inner_offset = self._region_and_offset_of_address(func, facts, base.addr)
            if inner_region is not None:
                return self._pointed_region(inner_region, inner_offset)
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
        """
        Whether ``addr`` is the entry point of a function, i.e. a plausible target of a function pointer.

        This must stay strict: a word that merely points at some basic block is not a function pointer. Accepting any
        block start would make jump tables (which hold block addresses) look like tables of function pointers.
        """
        if not isinstance(addr, int):
            return False
        if self.kb.functions.contains_addr(addr):
            return True
        if self._cfg_model is not None:
            node = self._cfg_model.get_any_node(addr)
            if node is not None and node.addr == addr and node.function_address == addr:
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
        if section is not None:
            return not section.is_executable

        if not self._sectionless_image:
            # accept known symbols even without a section match
            try:
                return self.project.loader.find_symbol(addr) is not None
            except Exception:  # pylint:disable=broad-except
                return False

        # A raw flash image (``objcopy -O binary``, firmware dumps) carries no section table at all, so the check
        # above can never accept anything and no global region is ever formed -- every table, vtable and callback
        # slot becomes invisible. Fall back to what such an image does tell us.
        segment = self.project.loader.find_segment_containing(addr)
        if segment is not None:
            if not segment.is_executable:
                return True
            # The whole image is typically mapped as one executable segment, so permissions cannot separate
            # read-only data from code. Treat whatever the CFG did not recover as code as data.
            return not self._is_recovered_code(addr)

        # Not mapped at all: a raw image contains only flash, so RAM and memory-mapped peripherals fall here. Those
        # addresses still need a region identity for a store and a load of the same location to meet, so accept
        # values that are plausible pointers rather than small integer literals.
        return _MIN_UNMAPPED_DATA_ADDR <= addr < (1 << self.project.arch.bits)

    def _is_recovered_code(self, addr: int) -> bool:
        """
        Whether the CFG recovered ``addr`` as part of some basic block, i.e. whether it is code rather than data.
        """
        if self._cfg_model is None:
            return False
        cached = self._recovered_code_cache.get(addr)
        if cached is None:
            cached = self._cfg_model.get_any_node(addr, anyaddr=True) is not None
            self._recovered_code_cache[addr] = cached
        return cached

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


def _codeptr_source_varids(expr) -> set[int]:
    """
    Collect the ids of the vvars whose code-pointer values could flow into ``expr``.
    """
    result: set[int] = set()
    expr = _unwrap_copy(expr)
    if isinstance(expr, ailment.Expr.VirtualVariable):
        result.add(expr.varid)
    else:
        for operand in _phi_ite_operands(expr):
            result |= _codeptr_source_varids(operand)
    return result


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
