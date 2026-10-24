"""
Map CFGFast's indirect-jump resolvers onto the Rust resolver chain (``angr.rustylib.ijr``).

Each resolver instance runs in Rust only when its exact class has a Rust implementation (a subclass may override
anything), its ``timeless`` flag and configuration match what the Rust implementation supports, its kind is enabled
(``CFGFast._rust_ijr_kinds``) and ``use_rust`` is left on. Everything else, including user-supplied resolvers, runs
as before in Python, in the same position of the same list.
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any

from archinfo import Endness

from angr.engines.vex.lifter import VEXLifter
from angr.knowledge_plugins.functions.recovery import RecoveryFunctionManager
from angr.rustylib.ijr import ResolverChain

from .memload_resolver import MemoryLoadResolver
from .resolver import IndirectJumpResolver

if TYPE_CHECKING:
    from angr.analyses.cfg.cfg_fast import CFGFast

# resolver class -> (kind, timeless)
RUST_RESOLVERS: dict[type[IndirectJumpResolver], tuple[str, bool]] = {
    MemoryLoadResolver: ("MemoryLoadResolver", True),
}

# the pseudo-kind of the timeless pre-check (a cross-instruction-optimized re-lift with a constant next)
PRECHECK = "precheck"

ALL_KINDS: frozenset[str] = frozenset({PRECHECK, *(kind for kind, _ in RUST_RESOLVERS.values())})


def _run_supports(cfg: CFGFast, kind: str) -> bool:
    """
    Run-level preconditions of a kind.
    """
    return True


def _instance_supported(resolver: IndirectJumpResolver) -> bool:
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
        "default_clobbers": default_clobbers,
    }


def build_chain(cfg: CFGFast) -> ResolverChain | None:
    """
    Build the resolver chain for this CFGFast run, or return None when the whole run stays in Python.
    """
    lifter = cfg._rust_lifter
    snapshot = cfg._loader_snapshot
    if lifter is None or snapshot is None or cfg._base_state is not None:
        return None
    engine = cfg.project.factory.default_engine
    arch = cfg.project.arch
    if not isinstance(engine, VEXLifter) or arch.byte_width != 8 or arch.bytes > 8:
        return None
    kinds = frozenset(kind for kind in cfg._rust_ijr_kinds if _run_supports(cfg, kind))
    timeless = [(rust_kind(r, kinds), r) for r in cfg.timeless_indirect_jump_resolvers]
    deferred = [(rust_kind(r, kinds), r) for r in cfg.indirect_jump_resolvers]
    rust_precheck = PRECHECK in kinds
    if not rust_precheck and all(kind is None for kind, _ in timeless + deferred):
        return None
    functions = cfg.kb.functions
    arch_ctx = _arch_ctx(cfg)
    ctx = {
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
    }
    return ResolverChain(lifter, snapshot, ctx, rust_precheck, timeless, deferred, cfg._rust_ijr_shadow)
