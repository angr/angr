"""
Map CFGFast's indirect-jump resolvers onto the Rust resolver chain (``angr.rustylib.ijr``).

Each resolver instance runs in Rust only when its exact class has a Rust implementation (a subclass may override
anything), its ``timeless`` flag and configuration match what the Rust implementation supports, its kind is enabled
(``CFGFast._rust_ijr_kinds``) and ``use_rust`` is left on. Everything else, including user-supplied resolvers, runs
as before in Python, in the same position of the same list.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.engines.vex.lifter import VEXLifter
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
    return kind


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
    kinds = cfg._rust_ijr_kinds
    timeless = [(rust_kind(r, kinds), r) for r in cfg.timeless_indirect_jump_resolvers]
    deferred = [(rust_kind(r, kinds), r) for r in cfg.indirect_jump_resolvers]
    rust_precheck = PRECHECK in kinds
    if not rust_precheck and all(kind is None for kind, _ in timeless + deferred):
        return None
    return ResolverChain(
        lifter,
        snapshot,
        cfg.project._sim_procedures,
        cfg._known_thunks,
        list(cfg._exec_mem_regions),
        arch.bits,
        arch.bytes,
        bool(engine.default_strict_block_end),
        engine._default_opt_level,
        rust_precheck,
        timeless,
        deferred,
        cfg._rust_ijr_shadow,
    )
