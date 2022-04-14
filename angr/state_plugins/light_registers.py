import claripy
import logging

from .plugin import SimStatePlugin
from ..errors import SimFastMemoryError
from ..misc.ux import once
from .. import sim_options as options

l = logging.getLogger(__name__)

class SimLightRegisters(SimStatePlugin):
    def __init__(self, reg_map=None, registers=None):
        super().__init__()

        self.reg_map = {} if reg_map is None else reg_map
        self.registers = {} if registers is None else registers

    @SimStatePlugin.memo
    def copy(self, _memo):
        o = type(self)(reg_map=self.reg_map, registers=dict(self.registers))
        return o

    def set_state(self, state):
        super().set_state(state)

        if not self.registers:
            ip_name = state.arch.register_names[state.arch.ip_offset]
            self.registers[ip_name] = claripy.BVV(0, state.arch.registers[ip_name][1])

        if self.reg_map:
            return

        bw = state.arch.byte_width
        for reg in state.arch.register_list:
            self.reg_map[(reg.vex_offset, reg.size)] = reg.name, None, reg.size*bw
            for subreg_name, subreg_suboffset, subreg_size in reg.subregisters:
                # endian swap gets undone here
                if state.arch.register_endness == 'Iend_BE':
                    extract_high = (reg.size - 1 - subreg_suboffset) * bw + 7
                    extract_low = extract_high - subreg_size * bw + 1
                else:
                    extract_low = subreg_suboffset * bw
                    extract_high = extract_low + subreg_size * bw - 1
                self.reg_map[(reg.vex_offset + subreg_suboffset, subreg_size)] = reg.name, (extract_high, extract_low), subreg_size*bw

    def resolve_register(self, offset, size):
        if type(offset) is str:
            offset, size = self.state.arch.registers[offset]
        else:
            if type(size) is not int:
                try:
                    if size.symbolic:
                        raise SimFastMemoryError("Can't handle symbolic register access")
                    else:
                        size = offset.args[0]
                except AttributeError:
                    raise TypeError("Invalid size argument") from None

            if type(offset) is not int:
                try:
                    if offset.symbolic:
                        raise SimFastMemoryError("Can't handle symbolic register access")
                    else:
                        offset = offset.args[0]
                except AttributeError:
                    raise TypeError("Invalid offset argument") from None

            if size is None:
                raise SimFastMemoryError("No size for register access available")

        try:
            return self.reg_map[(offset, size)]
        except KeyError as e:
            raise SimFastMemoryError("Register access to an unknown register or register slice") from e

    def load(self, offset, size=None, **kwargs):
        name, extract, _ = self.resolve_register(offset, size)
        return self._complex_load(name, extract)

    def _complex_load(self, name, extract):
        val = self._simple_load(name)
        if extract is not None:
            val = val[extract[0]:extract[1]]
        return val

    def _simple_load(self, name):
        try:
            return self.registers[name]
        except KeyError:
            pass

        try:
            size = self.state.arch.registers[name][1]
        except KeyError as e:
            raise KeyError("Critical programming error in SimLightRegisters - pls report") from e

        return self._fill(name, size)


    def store(self, offset, value, size=None, endness=None, **kwargs):
        if size is None and type(offset) is not str and type(value) is not int:
            try:
                size = len(value) // self.state.arch.byte_width
            except TypeError:
                raise SimFastMemoryError("Invalid register store value") from None

        name, extract, xsize = self.resolve_register(offset, size)

        if size is not None:
            try:
                if not self.state.solver.is_true(size*self.state.arch.byte_width == xsize):
                    raise SimFastMemoryError("Inconsistent register store size")
            except TypeError:
                raise SimFastMemoryError("Invalid register store value") from None

        if type(value) is int:
            value = self.state.solver.BVV(value, xsize)

        if endness is not None and endness != self.state.arch.register_endness:
            # ???????
            value = value.reversed

        self._complex_store(name, value, extract)

    def _complex_store(self, name, value, extract):
        if extract is not None:
            baseval = self._simple_load(name)
            if extract[0] != len(baseval) - 1:
                value = baseval[len(baseval)-1:extract[0]+1].concat(value)
            if extract[1] != 0:
                value = value.concat(baseval[extract[1]-1:0])

        self._simple_store(name, value)

    def _simple_store(self, name, value):
        self.registers[name] = value

    def _fill(self, name, size):
        size_bits = size * self.state.arch.byte_width
        if options.ZERO_FILL_UNCONSTRAINED_REGISTERS in self.state.options:
            value = self.state.solver.BVV(0, size_bits)
        else:
            if options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS not in self.state.options:
                if once('mem_fill_warning'):
                    l.warning("The program is accessing memory or registers with an unspecified value. "
                              "This could indicate unwanted behavior.")
                    l.warning("angr will cope with this by generating an unconstrained symbolic variable and continuing. "
                              "You can resolve this by:")
                    l.warning("1) setting a value to the initial state")
                    l.warning("2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, "
                              "to make unknown regions hold null")
                    l.warning("3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, "
                              "to suppress these messages.")
                l.warning("Filling register %s with %d unconstrained bytes", name, size)
            return self.state.solver.Unconstrained('reg_%s' % name, size_bits, key=('reg', name), eternal=True)  # :)

        self.registers[name] = value
        return value
