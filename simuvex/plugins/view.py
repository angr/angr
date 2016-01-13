import claripy
from .plugin import SimStatePlugin

class SimRegNameView(SimStatePlugin):
    def __init__(self):
        super(SimRegNameView, self).__init__()

    def __getattr__(self, k):
        state = super(SimRegNameView, self).__getattribute__('state')
        try:
            return state.registers.load(state.arch.registers[k][0], state.arch.registers[k][1])
        except KeyError:
            return super(SimRegNameView, self).__getattribute__(k)

    def __setattr__(self, k, v):
        if k == 'state' or k in dir(SimStatePlugin):
            return object.__setattr__(self, k, v)

        v = _raw_ast(v)
        if not isinstance(v, claripy.Bits):
            v = self.state.se.BVV(v, self.state.arch.registers[k][1]*8)

        try:
            reg_offset = self.state.arch.registers[k][0]
        except KeyError:
            raise AttributeError(k)

        return self.state.registers.store(reg_offset, v)

    def __dir__(self):
        return self.state.arch.registers.keys()

    def copy(self):
        return SimRegNameView()

    def merge(self, others, merge_flag, flag_values):
        return False, [ ]

    def widen(self, others, merge_flag, flag_values):
        return False, [ ]

class SimMemView(SimStatePlugin):
    def __init__(self, ty=None, addr=None, state=None):
        super(SimMemView, self).__init__()
        self._type = ty
        self._addr = addr
        if state is not None:
            self.set_state(state)

    def __getstate__(self):
        return {'type': self._type, 'addr': self._addr, 'state': self.state}

    def __setstate__(self, data):
        self.__init__(data['type'], data['addr'], data['state'])

    def set_state(self, state):
        super(SimMemView, self).set_state(state)

        # Make sure self._addr is always an AST
        if isinstance(self._addr, (int, long)):
            self._addr = self.state.se.BVV(self._addr, self.state.arch.bits)

    def _deeper(self, **kwargs):
        if 'ty' not in kwargs:
            kwargs['ty'] = self._type
        if 'addr' not in kwargs:
            kwargs['addr'] = self._addr
        if 'state' not in kwargs:
            kwargs['state'] = self.state
        return SimMemView(**kwargs)

    def __getitem__(self, k):
        if isinstance(k, slice):
            if k.step is not None:
                raise ValueError("Slices with strides are not supported")
            elif k.start is None:
                raise ValueError("Must specify start index")
            elif k.stop is not None:
                raise ValueError("Slices with stop index are not supported")
            else:
                addr = k.start
        else:
            addr = k
        return self._deeper(addr=addr)

    def __setitem__(self, k, v):
        self.__getitem__(k).store(v)

    types = {}
    state = None

    def __repr__(self):
        value = '<unresolvable>' if not self.resolvable else self.resolved
        addr = self._addr.__repr__(inner=True)
        type_name = self._type.name if self._type is not None else '<untyped>'
        return '<{} {} at {}>'.format(type_name,
                                      value,
                                      addr)

    def __dir__(self):
        return self._type._refine_dir() if self._type else SimMemView.types.keys()

    def __getattr__(self, k):
        if k in ('resolvable', 'resolved', 'state', '_addr', '_type') or k in dir(SimStatePlugin):
            return object.__getattribute__(self, k)
        if self._type:
            return self._type._refine(self, k)
        if k in SimMemView.types:
            return self._deeper(ty=SimMemView.types[k](self.state.arch))
        raise AttributeError(k)

    def __setattr__(self, k, v):
        if k in ('state', '_addr', '_type') or k in dir(SimStatePlugin):
            return object.__setattr__(self, k, v)
        self.__getattr__(k).store(v)

    def __cmp__(self, other):
        raise ValueError("Trying to compare SimMemView is not what you want to do")

    def copy(self):
        return SimMemView()

    def merge(self, others, merge_flag, flag_values):
        return False, [ ]

    def widen(self, others, merge_flag, flag_values):
        return False, [ ]

    @property
    def resolvable(self):
        return self._type is not None and self._addr is not None

    @property
    def resolved(self):
        if not self.resolvable:
            raise ValueError("Trying to resolve value without type and addr defined")
        return self._type.extract(self.state, self._addr)

    def store(self, value):
        if self._addr is None:
            raise ValueError("Trying to store to location without specifying address")

        if isinstance(value, claripy.ast.BV):
            return self.state.memory.store(self._addr, value)

        if self._type is None:
            raise ValueError("Trying to store to location without specifying type")

        return self._type.store(self.state, self._addr, value)

from ..s_type import ALL_TYPES
SimMemView.types = ALL_TYPES # identity purposefully here

from ..s_action_object import _raw_ast
SimStatePlugin.register_default('regs', SimRegNameView)
SimStatePlugin.register_default('mem', SimMemView)
