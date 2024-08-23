from __future__ import annotations
import logging

import claripy

from . import MemoryMixin
from ... import sim_options as options
from ...misc.ux import once
from ...errors import SimMemoryMissingError

l = logging.getLogger(__name__)


class DefaultFillerMixin(MemoryMixin):
    def _default_value(
        self, addr, size, name=None, inspect=True, events=True, key=None, fill_missing: bool = True, **kwargs
    ):
        if self.state.project and self.state.project.concrete_target:
            mem = self.state.project.concrete_target.read_memory(addr, size)
            endness = kwargs["endness"]
            bvv = claripy.BVV(mem)
            return bvv if endness == "Iend_BE" else bvv.reversed

        if fill_missing is False:
            raise SimMemoryMissingError(addr, size)

        bits = size * self.state.arch.byte_width

        if (
            type(addr) is int
            and self.category == "mem"
            and options.ZERO_FILL_UNCONSTRAINED_MEMORY in self.state.options
            or self.category == "reg"
            and options.ZERO_FILL_UNCONSTRAINED_REGISTERS in self.state.options
        ):
            return claripy.BVV(0, bits)

        if self.category == "reg" and type(addr) is int and addr == self.state.arch.ip_offset:
            # short-circuit this pathological case
            return claripy.BVV(0, self.state.arch.bits)

        is_mem = (
            self.category == "mem"
            and options.ZERO_FILL_UNCONSTRAINED_MEMORY not in self.state.options
            and options.SYMBOL_FILL_UNCONSTRAINED_MEMORY not in self.state.options
        )
        is_reg = (
            self.category == "reg"
            and options.ZERO_FILL_UNCONSTRAINED_REGISTERS not in self.state.options
            and options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS not in self.state.options
        )
        if type(addr) is int and (is_mem or is_reg):
            if once("mem_fill_warning"):
                what = "memory" if is_mem else "register"
                l.warning(
                    "The program is accessing %s with an unspecified value. This could indicate unwanted behavior.",
                    what,
                )
                l.warning(
                    "angr will cope with this by generating an unconstrained symbolic variable and continuing. "
                    "You can resolve this by:"
                )
                l.warning("1) setting a value to the initial state")
                l.warning(
                    "2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, "
                    "to make unknown regions hold null"
                )
                l.warning(
                    "3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, "
                    "to suppress these messages."
                )

            if is_mem:
                refplace_int = self.state.solver.eval(self.state._ip)
                if self.state.project:
                    refplace_str = self.state.project.loader.describe_addr(refplace_int)
                else:
                    refplace_str = "unknown"
                l.warning(
                    "Filling memory at %#x with %d unconstrained bytes referenced from %#x (%s)",
                    addr,
                    size,
                    refplace_int,
                    refplace_str,
                )
            else:
                if addr == self.state.arch.ip_offset:
                    refplace_int = 0
                    refplace_str = "symbolic"
                else:
                    refplace_int = self.state.solver.eval(self.state._ip)
                    if self.state.project:
                        refplace_str = self.state.project.loader.describe_addr(refplace_int)
                    else:
                        refplace_str = "unknown"
                reg_str = self.state.arch.translate_register_name(addr, size=size)
                l.warning(
                    "Filling register %s with %d unconstrained bytes referenced from %#x (%s)",
                    reg_str,
                    size,
                    refplace_int,
                    refplace_str,
                )
                if name is None and not reg_str.isdigit():
                    name = "reg_" + reg_str

        if name is None:
            name = f"{self.id}_{addr:x}" if type(addr) is int else self.category

        return self.state.solver.Unconstrained(name, bits, key=key, inspect=inspect, events=events)


class SpecialFillerMixin(MemoryMixin):
    def __init__(self, special_memory_filler=None, **kwargs):
        super().__init__(**kwargs)
        self._special_memory_filler = special_memory_filler

    def _default_value(self, addr, size, name=None, **kwargs):
        if (
            options.SPECIAL_MEMORY_FILL in self.state.options
            and self.state._special_memory_filler is not None
            and type(addr) is int
        ):
            return self.state._special_memory_filler(name, addr, size * self.state.arch.byte_width, self.state)
        return super()._default_value(addr, size, name=name, **kwargs)

    def copy(self, memo):
        o = super().copy(memo)
        o._special_memory_filler = self._special_memory_filler
        return o


class ExplicitFillerMixin(MemoryMixin):
    def __init__(self, uninitialized_read_handler=None, **kwargs):
        super().__init__(**kwargs)
        self._uninitialized_read_handler = uninitialized_read_handler

    def _default_value(self, addr, size, inspect=True, events=True, **kwargs):
        if self._uninitialized_read_handler is not None:
            return self._uninitialized_read_handler(addr, size, inspect=inspect, events=events)
        return super()._default_value(addr, size, inspect=inspect, events=events, **kwargs)

    def copy(self, memo):
        o = super().copy(memo)
        o._uninitialized_read_handler = self._uninitialized_read_handler
        return o
