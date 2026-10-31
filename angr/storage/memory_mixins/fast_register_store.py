"""
A shortcut for the VEX engine's register writes (Put) through the default memory stack.

A Put of a BV to a concrete register offset passes through about fifteen store mixins, nearly all of which forward it
unchanged; on VM-heavy symbolic execution that call chain is a fifth of the run. fast_register_store() does what the
chain does for exactly that case and returns False whenever anything could make a layer act differently (other
store mixins, an action, a size or option that a layer looks at, reg_write breakpoints), so callers fall back to
the normal store.
"""

from __future__ import annotations

from angr import claripy
from angr import sim_options as o
from angr.state_plugins.inspect import BP_AFTER, BP_BEFORE

_CHAIN_OK: dict[type, bool] = {}

# the store implementations, in MRO order, whose effect fast_register_store reproduces
_EXPECTED_CHAIN = (
    "UnwrapperMixin",
    "NameResolutionMixin",
    "DataNormalizationMixin",
    "SimplificationMixin",
    "ActionsMixinHigh",
    "UnderconstrainedMixin",
    "SizeConcretizationMixin",
    "SizeNormalizationMixin",
    "InspectMixin",
    "AddressConcretizationMixin",
    "ActionsMixinLow",
    "ConditionalMixin",
    "ConvenientMappingsMixin",
    "DirtyAddrsMixin",
    "PagedMemoryMixin",
    "MemoryMixin",
)

# options some layer above PagedMemoryMixin reads on a register store (SIMPLIFY_REGISTER_WRITES is reproduced)
_OPTIONS_READ = (
    o.AUTO_REFS,
    o.MEMORY_SYMBOLIC_BYTES_MAP,
    o.REVERSE_MEMORY_NAME_MAP,
    o.REVERSE_MEMORY_HASH_MAP,
)


def _chain_ok(cls) -> bool:
    ok = _CHAIN_OK.get(cls)
    if ok is None:
        from angr.storage.memory_mixins.paged_memory.paged_memory_mixin import PagedMemoryMixin

        chain = tuple(k.__name__ for k in cls.__mro__ if "store" in k.__dict__)
        ok = chain == _EXPECTED_CHAIN and any(k is PagedMemoryMixin for k in cls.__mro__)
        _CHAIN_OK[cls] = ok
    return ok


def fast_register_store(state, offset, data, inspect=True) -> bool:
    """
    state.registers.store(offset, data, action=None, inspect=inspect) for a concrete offset (int or BVV) and a BV, or
    False (nothing done) when the shortcut does not apply.
    """
    mem = state.registers
    if type(offset) is int:
        concrete_offset = offset
    elif type(offset) is claripy.ast.BV and offset.op == "BVV":
        # AddressConcretizationMixin evaluates a concrete offset to its value; the events still see the AST
        concrete_offset = offset.args[0]
    else:
        return False
    if concrete_offset < 0 or type(data) is not claripy.ast.BV or mem.category != "reg":
        return False
    if not _chain_ok(type(mem)):
        return False
    bits = len(data)
    byte_width = state.arch.byte_width
    if bits == 0 or bits % byte_width != 0:
        return False
    options = state.options
    for opt in _OPTIONS_READ:
        if opt in options:
            return False

    if o.SIMPLIFY_REGISTER_WRITES in options:
        # SimplificationMixin, above the size and inspect layers, which see the simplified value. Simplifying is
        # pure, so falling back afterwards (which simplifies again) changes nothing.
        data = state.solver.simplify(data)
        if type(data) is not claripy.ast.BV:
            return False
        bits = len(data)
        if bits == 0 or bits % byte_width != 0:
            return False
    size = bits // byte_width
    events = inspect and state.supports_inspect
    if events:
        inspector = state.inspect
        from angr.state_plugins.inspect import SimInspector  # pylint:disable=import-outside-toplevel

        # a breakpoint may rewrite the store; leave that to InspectMixin
        if type(inspector) is not SimInspector or inspector._breakpoints.get("reg_write", True):
            return False
        state._inspect(
            "reg_write",
            BP_BEFORE,
            reg_write_offset=offset,
            reg_write_length=size,
            reg_write_expr=data,
            reg_write_condition=None,
            reg_write_endness=None,
        )

    from angr.storage.memory_mixins.paged_memory.paged_memory_mixin import PagedMemoryMixin  # pylint:disable=import-outside-toplevel

    # what DirtyAddrsMixin hands PagedMemoryMixin for this store
    PagedMemoryMixin.store(mem, concrete_offset, data, size=size, endness=None, inspect=inspect, action=None)

    if events:
        state._inspect(
            "reg_write",
            BP_AFTER,
            reg_write_offset=offset,
            reg_write_length=size,
            reg_write_expr=data,
            reg_write_condition=None,
            reg_write_endness=None,
        )
    return True
