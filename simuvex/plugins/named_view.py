import claripy
from .plugin import SimStatePlugin

class SimRegNameView(SimStatePlugin):
    def __init__(self):
        super(SimRegNameView, self).__init__()

    def __getattr__(self, k):
        try:
            return self.state.reg_expr(self.state.arch.registers[k][0])
        except KeyError:
            return getattr(super(SimRegNameView, self), k)

    def __setattr__(self, k, v):
        if k == 'state':
            return object.__setattr__(self, k, v)

        try:
            return self.state.store_reg(self.state.arch.registers[k][0], v)
        except KeyError:
            raise AttributeError(k)

    def __dir__(self):
        return self.state.arch.registers.keys()

    def copy(self):
        return SimRegNameView()

    def merge(self, others, merge_flag, flag_values):
        return False, [ ]

    def widen(self, others, merge_flag, flag_values):
        return False, [ ]

class SimMemIndexView(SimStatePlugin):
    def __init__(self):
        super(SimMemIndexView, self).__init__()
        self._endness = None
        self._size = None
        self._addr = None
        self._signed = None

    def set_state(self, state):
        super(SimMemIndexView, self).set_state(state)
        self._endness = state.arch.memory_endness

    def _deeper(self, **kwargs):
        return SimMemIndexOverlay(self, **kwargs)

    def __getitem__(self, k):
        if isinstance(k, slice):
            if k.step is not None:
                raise ValueError("Slices with strides are not supported")
            elif k.start is None:
                raise ValueError("Must specify start index")
            elif k.stop is None:
                return self._deeper(address=k.start)
            else:
                return self._deeper(address=k.start, size=k.stop-k.start, endness='Iend_BE')
        elif isinstance(k, (int, long, claripy.A)):
            return self._deeper(address=k, size=1)
        else:
            raise KeyError(k)

    def __setitem__(self, k, v):
        self[k].store(v)

    attributes = {
        'byte': {'size': 1},
        'word': {'size': 2},
        'dword': {'size': 4},
        'qword': {'size': 8},
        'oword': {'size': 16},
        'LE': {'endness': 'Iend_LE'},
        'BE': {'endness': 'Iend_BE'},
        'signed': {'signed': True},
        'unsigned': {'signed': False}
    }
    state = None

    __dir__ = attributes.keys

    def __getattr__(self, k):
        try:
            return self._deeper(**SimMemIndexView.attributes[k])
        except KeyError:
            return getattr(super(SimMemIndexView, self), k)

    def __setattr__(self, k, v):
        if k in ('state', '_endness', '_addr', '_size', '_signed'):
            return object.__setattr__(self, k, v)
        self.__getattr__(k).store(v)

    def copy(self):
        return SimMemIndexView()

    def merge(self, others, merge_flag, flag_values):
        return False, [ ]

    def widen(self, others, merge_flag, flag_values):
        return False, [ ]

class SimMemIndexOverlay(SimMemIndexView):
    def __init__(self, view, endness=None, size=None, address=None, signed=None): #pylint: disable=super-init-not-called
        self.state = view.state
        self._endness = endness if endness is not None else view._endness
        self._size = size if size is not None else view._size
        self._addr = address if address is not None else view._addr
        self._signed = signed if signed is not None else view._signed

    @property
    def resolvable(self):
        return self._endness is not None and self._size is not None and self._addr is not None

    @property
    def resolved(self):
        if not self.resolvable:
            raise ValueError("Trying to resolve value without endness, size, and address defined")
        return self.state.mem_expr(self._addr, self._size, endness=self._endness)

    def __repr__(self):
        if self.resolvable:
            return 'SimMemIndexView(%s)' % self.resolved
        else:
            return 'SimMemIndexView(%s)' % ', '.join('%s=%s' % (k[1:], getattr(self, k)) for k in ('_addr', '_size', '_endness', '_signed') if getattr(self, k) is not None)

    def store(self, value):
        if self._endness is None or self._addr is None:
            raise ValueError("Trying to store to location without specifying endness and address")
        if isinstance(value, SimMemIndexView):
            if value._size is None and self._size is None:
                raise ValueError("Trying to store to location with no size information available")
            if value._size is None:
                value = value._deeper(size=self._size)
            if self._signed is None:
                self._deeper(signed=value._signed).store(value.resolved)
            else:
                self.store(value.resolved)
        elif isinstance(value, (int, long)):
            if self._size is None:
                raise ValueError("Trying to store to location with no size information available")
            self.state.store_mem(self._addr, self.state.BVV(value, self._size*8), endness=self._endness)
        elif isinstance(value, claripy.A):
            if self._size is None:
                pass
            elif self._size*8 > value.size():
                if self._signed is None:
                    raise ValueError("Trying to extend value with signed/unsigned unspecified")
                elif self._signed:
                    value = value.sign_extend(self._size*8 - value.size())
                else:
                    value = value.zero_extend(self._size*8 - value.size())
            elif self._size*8 < value.size():
                value = value[self._size*8 - 1:0]
            self.state.store_mem(self._addr, value, endness=self._endness)
