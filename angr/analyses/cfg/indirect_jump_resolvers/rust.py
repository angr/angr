"""
Map CFGFast's indirect-jump resolvers onto the Rust resolver chain (``angr.rustylib.ijr``).

Each resolver instance runs in Rust only when its exact class has a Rust implementation (a subclass may override
anything), its ``timeless`` flag and configuration match what the Rust implementation supports, its kind is enabled
(``CFGFast._rust_ijr_kinds``) and ``use_rust`` is left on. Everything else, including user-supplied resolvers, runs
as before in Python, in the same position of the same list.
"""

from __future__ import annotations

import functools
from collections import defaultdict
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any

from archinfo import Endness

from angr.analyses.propagator.vex_vars import VEXReg, VEXTmp
from angr.code_location import CodeLocation
from angr.engines.vex.lifter import VEXLifter
from angr.knowledge_plugins.cfg.indirect_jump import IndirectJumpType
from angr.knowledge_plugins.functions.recovery import RecoveryFunctionManager
from angr.knowledge_plugins.propagations import PropagationModel
from angr.rustylib.cfg_jobs import CFGJob, FunctionCallEdge, FunctionTransitionEdge
from angr.rustylib.ijr import FcpService, FcpTableView, ResolverChain
from angr.simos import SimWindows

from . import mips_elf_fast
from .amd64_elf_got import AMD64ElfGotResolver
from .amd64_pe_iat import AMD64PeIatResolver
from .arm_elf_fast import ArmElfFastResolver
from .const_resolver import ConstantResolver
from .jumptable import JumpTableResolver
from .memload_resolver import MemoryLoadResolver
from .mips_elf_fast import MipsElfFastResolver
from .mips_elf_got import MipsElfGotResolver
from .resolver import IndirectJumpResolver
from .syscall_resolver import SyscallResolver
from .x86_elf_pic_plt import X86ElfPicPltResolver
from .x86_pe_iat import X86PeIatResolver

if TYPE_CHECKING:
    from angr.analyses.cfg.cfg_fast import CFGFast

# resolver class -> (kind, timeless)
RUST_RESOLVERS: dict[type[IndirectJumpResolver], tuple[str, bool]] = {
    MemoryLoadResolver: ("MemoryLoadResolver", True),
    ConstantResolver: ("ConstantResolver", False),
    AMD64ElfGotResolver: ("AMD64ElfGotResolver", True),
    SyscallResolver: ("SyscallResolver", True),
    MipsElfFastResolver: ("MipsElfFastResolver", True),
    MipsElfGotResolver: ("MipsElfGotResolver", True),
    ArmElfFastResolver: ("ArmElfFastResolver", True),
    X86PeIatResolver: ("X86PeIatResolver", True),
    AMD64PeIatResolver: ("AMD64PeIatResolver", True),
    X86ElfPicPltResolver: ("X86ElfPicPltResolver", True),
    JumpTableResolver: ("JumpTableResolver", False),
}

# the pseudo-kind of the timeless pre-check (a cross-instruction-optimized re-lift with a constant next)
PRECHECK = "precheck"
# ConstantValueManager's FCP (used by JumpTableResolver and SyscallResolver)
CVM = "ConstantValueManager"

ALL_KINDS: frozenset[str] = frozenset({PRECHECK, CVM, *(kind for kind, _ in RUST_RESOLVERS.values())})


def _run_supports(cfg: CFGFast, kind: str) -> bool:
    """
    Run-level preconditions of a kind.
    """
    if kind in ("AMD64ElfGotResolver", "AMD64PeIatResolver"):
        return cfg.project.arch.name == "AMD64"
    if kind == "X86PeIatResolver":
        return cfg.project.arch.name == "X86"
    if kind == "JumpTableResolver":
        return isinstance(cfg.kb.functions, RecoveryFunctionManager)
    if kind in ("ConstantResolver", CVM):
        # FCP reads project.kb; earlier FCP results in the KB would be reused by the Python resolver
        kb = cfg.kb
        return (
            kb is cfg.project.kb
            and isinstance(kb.functions, RecoveryFunctionManager)
            and not any(key[0] == "FCP" for key in kb.propagations._propagations)
        )
    return True


def _instance_supported(resolver: IndirectJumpResolver) -> bool:
    if isinstance(resolver, ConstantResolver):
        return type(resolver.max_func_nodes) is int
    if isinstance(resolver, MipsElfFastResolver):
        # the profiling counters are updated by the Python implementation
        return not mips_elf_fast.PROFILING
    return True


def rust_kind(resolver: IndirectJumpResolver, kinds: frozenset[str]) -> str | None:
    """
    The Rust kind that runs this resolver instance, or None for the Python implementation.
    """
    entry = RUST_RESOLVERS.get(type(resolver))
    if entry is None:
        return None
    kind, timeless = entry
    if kind not in kinds or not resolver.use_rust or resolver.timeless != timeless or resolver.base_state is not None:
        return None
    if not _instance_supported(resolver):
        return None
    return kind


def callee_caller_saved(functions, registers: dict[str, tuple[int, int]], addr: int):
    """
    FastConstantPropagation._handle_function's clobbers for the callee at addr: its calling convention's
    CALLER_SAVED_REGS as (offset, size), None for the default calling convention, or "error" for an unknown register.
    """
    if not functions.contains_addr(addr):
        return None
    cc = functions.get_by_addr(addr, meta_only=True).calling_convention
    if cc is None:
        return None
    out = []
    for name in cc.CALLER_SAVED_REGS:
        reg = registers.get(name)
        if reg is None:
            return "error"
        out.append(reg)
    return out


class LazyFcpReplacements(Mapping):
    """
    The ``replacements`` of an FCP PropagationModel published by the Rust ConstantResolver: built on first use.
    """

    __slots__ = ("_data", "_view")

    def __init__(self, view: FcpTableView):
        self._view: FcpTableView | None = view
        self._data: defaultdict[CodeLocation, dict] | None = None

    def _materialize(self) -> defaultdict[CodeLocation, dict]:
        if self._data is None:
            assert self._view is not None
            data: defaultdict[CodeLocation, dict] = defaultdict(dict)
            for (block_addr, stmt_idx, ins_addr), row in self._view.rows():
                d = data[CodeLocation(block_addr, stmt_idx, ins_addr=ins_addr)]
                for (kind, a, b), value in row:
                    d[VEXTmp(a) if kind == "tmp" else VEXReg(a, b)] = value
            self._data = data
            self._view = None
        return self._data

    def __getitem__(self, key):
        return self._materialize()[key]

    def __iter__(self) -> Iterator:
        return iter(self._materialize())

    def __len__(self) -> int:
        return len(self._materialize())

    def __reduce__(self):
        return dict, (dict(self._materialize()),)


def publish_fcp(cfg: CFGFast, func_addr: int, view: FcpTableView, function_block_count: int) -> PropagationModel:
    """
    Store a Rust FCP result as kb.propagations[("FCP", func_addr)], as ConstantResolver does.
    """
    key = "FCP", func_addr
    model = PropagationModel(key, replacements=LazyFcpReplacements(view), function_block_count=function_block_count)
    cfg.kb.propagations.update(key, model)
    return model


def shadow_blade(cfg: CFGFast, addr: int) -> tuple[list, list]:
    """
    The slice ConstantResolver's Python implementation builds for the jump at addr (shadow mode).
    """
    from angr.blade import Blade  # pylint:disable=import-outside-toplevel

    b = Blade(
        cfg.graph,
        addr,
        -1,
        cfg=cfg,
        project=cfg.project,
        ignore_bp=False,
        ignore_sp=False,
        max_level=3,
        stop_at_calls=True,
        cross_insn_opt=True,
        control_dependence=False,
    )
    return list(b.slice.nodes()), list(b.slice.edges())


def jt_py_shadow(
    cfg: CFGFast,
    resolver: JumpTableResolver,
    addr: int,
    func_addr: int,
    block,
    jumpkind: str,
    func_graph_complete: bool,
) -> tuple[bool, bool, list[int] | None, list[dict]]:
    """
    Run the Python JumpTableResolver on a jump the Rust one answered, for comparison: its writes to the IndirectJump
    are undone. Returns (resolved, deferred, targets, table records).
    """
    ij = cfg.indirect_jumps.get(addr)
    saved = None if ij is None else (ij.jumptable, list(ij.jumptables), ij.resolved_targets, ij.type)
    resolved, targets, deferred = False, None, False
    if resolver.filter(cfg, addr, func_addr, block, jumpkind):
        resolved, targets = resolver.resolve(
            cfg, addr, func_addr, block, jumpkind, func_graph_complete=func_graph_complete
        )
        deferred = not resolved and resolver.deferred
    tables = []
    if ij is not None:
        tables = [
            {
                "addr": ji.addr,
                "size": ji.size,
                "entry_size": ji.entry_size,
                "entries_guessed": ji.entries_guessed,
                "n": len(ji.entries),
            }
            for ji in ij.jumptables
        ]
        assert saved is not None
        ij.jumptable, ij.jumptables, ij.resolved_targets, ij.type = saved
    return bool(resolved), bool(deferred), list(targets) if resolved and targets is not None else None, tables


def _arch_ctx(cfg: CFGFast) -> dict[str, Any]:
    project = cfg.project
    arch = project.arch
    registers = {name: (off, size) for name, (off, size) in arch.registers.items()}
    default_clobbers = None
    cc = project.factory.cc()
    if cc is not None and all(name in registers for name in cc.CALLER_SAVED_REGS):
        default_clobbers = [registers[name] for name in cc.CALLER_SAVED_REGS]
    return {
        "bits": arch.bits,
        "bytes": arch.bytes,
        "byte_width": arch.byte_width,
        "sp_offset": arch.sp_offset,
        "bp_offset": arch.bp_offset,
        "ip_offset": arch.ip_offset,
        "ret_offset": arch.ret_offset,
        "call_pushes_ret": arch.call_pushes_ret,
        "ftop": registers.get("ftop") if arch.name in ("X86", "AMD64") else None,
        "initial_sp": arch.initial_sp,
        "memory_be": arch.memory_endness == Endness.BE,
        "base_reg": {k: v[0] for k, v in arch.subregister_map.items() if isinstance(k, int)},
        "registers": registers,
        "register_names": dict(arch.register_names),
        "default_clobbers": default_clobbers,
    }


def _usable(cfg: CFGFast) -> bool:
    """
    Run-level preconditions of every Rust kind: the Rust lifter (so no base state, patches, pcode, ...) and the
    default VEX engine on an 8-bit-byte architecture.
    """
    if cfg._rust_lifter is None or cfg._loader_snapshot is None or cfg._base_state is not None:
        return False
    arch = cfg.project.arch
    return isinstance(cfg.project.factory.default_engine, VEXLifter) and arch.byte_width == 8 and arch.bytes <= 8


def _ctx(cfg: CFGFast) -> dict[str, Any]:
    engine = cfg.project.factory.default_engine
    assert isinstance(engine, VEXLifter)
    functions = cfg.kb.functions
    arch_ctx = _arch_ctx(cfg)
    return {
        "sim_procedures": cfg.project._sim_procedures,
        "extra_stop_points": cfg._known_thunks,
        "exec_regions": list(cfg._exec_mem_regions),
        "strict_block_end": bool(engine.default_strict_block_end),
        "default_opt_level": engine._default_opt_level,
        "arch": arch_ctx,
        "graph": cfg.model.graph._graph,
        "functions": functions if isinstance(functions, RecoveryFunctionManager) else None,
        "functions_store": functions.store if isinstance(functions, RecoveryFunctionManager) else None,
        "callee_caller_saved": functools.partial(callee_caller_saved, functions, arch_ctx["registers"]),
        "publish_fcp": publish_fcp,
        "shadow_blade": shadow_blade if cfg._rust_ijr_shadow else None,
        "shadow": cfg._rust_ijr_shadow,
        "simos_windows": isinstance(cfg.project.simos, SimWindows),
        "jt_arches": sorted(cfg._rust_jt_arches),
        "jt_skip": cfg._rust_jt_skip,
        "jt_skip_unbounded": cfg._rust_jt_skip_unbounded,
        "jt_py_shadow": jt_py_shadow if cfg._rust_jt_py_shadow else None,
        "indirect_jump_target_limit": cfg._indirect_jump_target_limit,
        "write_back": _write_back_ctx(cfg),
    }


def _write_back_ctx(cfg: CFGFast) -> dict[str, Any] | None:
    """
    What the chain needs to write resolved jumps back in Rust, or None when this run must call
    `_indirect_jump_resolved` (a subclass overrides it, or its jobs and edges are not the Rust classes).
    """
    from angr.analyses.cfg.cfg_fast import CFGFast  # pylint:disable=import-outside-toplevel

    if not (
        cfg._rust_ijr_write_back
        and type(cfg)._indirect_jump_resolved is CFGFast._indirect_jump_resolved
        and cfg._job_cls is CFGJob
        and cfg._transition_edge_cls is FunctionTransitionEdge
        and cfg._call_edge_cls is FunctionCallEdge
    ):
        return None
    return {"vtable": IndirectJumpType.Vtable}


def build_chain(cfg: CFGFast) -> ResolverChain | None:
    """
    Build the resolver chain for this CFGFast run, or return None when the whole run stays in Python.
    """
    if not _usable(cfg):
        return None
    kinds = frozenset(kind for kind in cfg._rust_ijr_kinds if _run_supports(cfg, kind))
    timeless = [(rust_kind(r, kinds), r) for r in cfg.timeless_indirect_jump_resolvers]
    deferred = [(rust_kind(r, kinds), r) for r in cfg.indirect_jump_resolvers]
    rust_precheck = PRECHECK in kinds
    if not rust_precheck and all(kind is None for kind, _ in timeless + deferred):
        return None
    return ResolverChain(
        cfg._rust_lifter, cfg._loader_snapshot, _ctx(cfg), rust_precheck, timeless, deferred, cfg._rust_ijr_shadow
    )


def build_fcp_service(cfg: CFGFast) -> FcpService | None:
    """
    The Rust FCP that ConstantValueManager uses during this CFGFast run, or None.
    """
    if not _usable(cfg) or CVM not in cfg._rust_ijr_kinds or not _run_supports(cfg, CVM):
        return None
    return FcpService(cfg._rust_lifter, cfg._loader_snapshot, _ctx(cfg))
