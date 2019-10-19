import logging

import claripy
from archinfo.arch_soot import ArchSoot, SootAddressDescriptor
from archinfo.arch_arm import is_arm_arch
from .plugin import SimStatePlugin


l = logging.getLogger(name=__name__)


class SimRegNameView(SimStatePlugin):
    def __getattr__(self, k):
        """
        Get the value of a register.

        :param str k: Name of the register. Prefix it with "_" prevents SimInspect being triggered and SimActions being
                      created.
        :param v:     Value to set to the register.
        :return:      Value of the register.
        :rtype:       claripy.ast.Base
        """

        state = super(SimRegNameView, self).__getattribute__('state') # type: SimState

        if isinstance(k, str) and k.startswith('_'):
            k = k[1:]
            inspect = False
            disable_actions = True
        else:
            inspect = True
            disable_actions = False

        try:
            return state.registers.load(k, inspect=inspect, disable_actions=disable_actions)
        except KeyError:
            return super(SimRegNameView, self).__getattribute__(k)

    def __setattr__(self, k, v):
        """
        Set value to a register.

        :param str k: Name of the register. Prefix it with "_" prevents SimInspect being triggered and SimActions being
                      created.
        :param v:     Value to set to the register.
        :return:      None
        """

        if k == 'state' or k in dir(SimStatePlugin):
            return object.__setattr__(self, k, v)

        if isinstance(k, str) and k.startswith('_'):
            k = k[1:]
            inspect = False
            disable_actions = True
        else:
            inspect = True
            disable_actions = False

        # When executing a Java JNI application, we need to update the state's
        # instruction pointer flag every time the ip gets written.
        # This flag will then toggle between the native and the java view of the
        # state.
        if self.state.project and \
           isinstance(self.state.project.arch, ArchSoot) and \
           k == 'ip' and \
           self.state.project.simos.is_javavm_with_jni_support:
            self.state.ip_is_soot_addr = isinstance(v, SootAddressDescriptor)

        try:
            return self.state.registers.store(k, v, inspect=inspect, disable_actions=disable_actions)
        except KeyError:
            # What do we do in case we are dealing with soot? there are no register
            if isinstance(self.state.arch, ArchSoot):
                pass
            else:
                raise AttributeError(k)

    def __dir__(self):
        if self.state.arch.name in ('X86', 'AMD64'):
            return list(self.state.arch.registers.keys()) + ['st%d' % n for n in range(8)] + ['tag%d' % n for n in range(8)] + ['flags', 'eflags', 'rflags']
        elif is_arm_arch(self.state.arch):
            return list(self.state.arch.registers.keys()) + ['flags']
        return self.state.arch.registers.keys()

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        return SimRegNameView()

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument
        return False

    def widen(self, others): # pylint: disable=unused-argument
        return False

    def get(self, reg_name):
        return self.__getattr__(reg_name)

class SimMemView(SimStatePlugin):
    """
    This is a convenient interface with which you can access a program's memory.

    The interface works like this:

        - You first use [array index notation] to specify the address you'd like to load from
        - If at that address is a pointer, you may access the ``deref`` property to return a SimMemView at the
          address present in memory.
        - You then specify a type for the data by simply accesing a property of that name. For a list of supported
          types, look at ``state.mem.types``.
        - You can then *refine* the type. Any type may support any refinement it likes. Right now the only refinements
          supported are that you may access any member of a struct by its member name, and you may index into a
          string or array to access that element.
        - If the address you specified initially points to an array of that type, you can say `.array(n)` to view the
          data as an array of n elements.
        - Finally, extract the structured data with ``.resolved`` or ``.concrete``. ``.resolved`` will return bitvector
          values, while ``.concrete`` will return integer, string, array, etc values, whatever best represents the
          data.
        - Alternately, you may store a value to memory, by assigning to the chain of properties that you've
          constructed. Note that because of the way python works, ``x = s.mem[...].prop; x = val`` will NOT work,
          you must say ``s.mem[...].prop = val``.

    For example:

        >>> s.mem[0x601048].long
        <long (64 bits) <BV64 0x4008d0> at 0x601048>
        >>> s.mem[0x601048].long.resolved
        <BV64 0x4008d0>
        >>> s.mem[0x601048].deref
        <<untyped> <unresolvable> at 0x4008d0>
        >>> s.mem[0x601048].deref.string.concrete
        'SOSNEAKY'
    """

    def __init__(self, ty=None, addr=None, state=None):
        super(SimMemView, self).__init__()
        self._type = ty
        self._addr = addr
        if state is not None:
            self.set_state(state)

    def set_state(self, state):
        super(SimMemView, self).set_state(state)

        # Make sure self._addr is always an AST
        if isinstance(self._addr, int):
            self._addr = self.state.solver.BVV(self._addr, self.state.arch.bits)

    def _deeper(self, **kwargs) -> 'SimMemView':
        if 'ty' not in kwargs:
            kwargs['ty'] = self._type
        if 'addr' not in kwargs:
            kwargs['addr'] = self._addr
        if 'state' not in kwargs:
            kwargs['state'] = self.state
        return SimMemView(**kwargs)

    def __getitem__(self, k) -> 'SimMemView':
        if isinstance(k, slice):
            if k.step is not None:
                raise ValueError("Slices with strides are not supported")
            elif k.start is None:
                raise ValueError("Must specify start index")
            elif k.stop is not None:
                raise ValueError("Slices with stop index are not supported")
            else:
                addr = k.start
        elif self._type is not None and self._type._can_refine_int:
            return self._type._refine(self, k)
        else:
            addr = k
        return self._deeper(addr=addr)

    def __setitem__(self, k, v):
        self.__getitem__(k).store(v)

    types = {}
    state = None

    def __repr__(self):
        if self._addr is None:
            return '<SimMemView>'
        value = '<unresolvable>' if not self.resolvable else self.resolved

        if isinstance(self._addr, claripy.ast.Base):
            addr = self._addr.__repr__(inner=True)
        elif hasattr(self._addr, 'ast') and isinstance(self._addr.ast, claripy.ast.Base):
            addr = self._addr.ast.__repr__(inner=True)
        else:
            addr = repr(self._addr)

        type_name = repr(self._type) if self._type is not None else '<untyped>'
        return '<{} {} at {}>'.format(type_name,
                                      value,
                                      addr)

    def __dir__(self):
        return self._type._refine_dir() if self._type else [x for x in SimMemView.types if ' ' not in x] + ['struct']

    def __getattr__(self, k):
        if k in ('concrete', 'deref', 'resolvable', 'resolved', 'state', 'array', 'store', '_addr', '_type') or k in dir(SimStatePlugin):
            return object.__getattribute__(self, k)
        if self._type and k in self._type._refine_dir():
            return self._type._refine(self, k)
        if k == 'struct':
            return StructMode(self)
        if k in SimMemView.types:
            return self._deeper(ty=SimMemView.types[k].with_arch(self.state.arch))
        raise AttributeError(k)

    def __setattr__(self, k, v):
        if k in ('state', '_addr', '_type') or k in dir(SimStatePlugin):
            return object.__setattr__(self, k, v)
        return self.__getattr__(k).store(v)

    def __cmp__(self, other):
        raise ValueError("Trying to compare SimMemView is not what you want to do")

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        return SimMemView()

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument
        return False

    def widen(self, others): # pylint: disable=unused-argument
        return False

    @property
    def resolvable(self):
        return self._type is not None and self._addr is not None

    @property
    def resolved(self):
        if not self.resolvable:
            raise ValueError("Trying to resolve value without type and addr defined")
        return self._type.extract(self.state, self._addr)

    @property
    def concrete(self):
        if not self.resolvable:
            raise ValueError("Trying to resolve value without type and addr defined")
        return self._type.extract(self.state, self._addr, True)

    @property
    def deref(self):
        if self._addr is None:
            raise ValueError("Trying to dereference pointer without addr defined")
        ptr = self.state.memory.load(self._addr, self.state.arch.bytes, endness=self.state.arch.memory_endness)
        if ptr.symbolic:
            l.warning("Dereferencing symbolic pointer %s at %#x", repr(ptr), self.state.solver.eval(self._addr))
        ptr = self.state.solver.eval(ptr)

        return self._deeper(ty=self._type.pts_to if isinstance(self._type, SimTypePointer) else None, addr=ptr)

    def array(self, n):
        if self._addr is None:
            raise ValueError("Trying to produce array without specifying adddress")
        if self._type is None:
            raise ValueError("Trying to produce array without specifying type")
        return self._deeper(ty=SimTypeFixedSizeArray(self._type, n))

    def store(self, value):
        if self._addr is None:
            raise ValueError("Trying to store to location without specifying address")

        if self._type is None:
            raise ValueError("Trying to store to location without specifying type")

        return self._type.store(self.state, self._addr, value)


class StructMode(object):
    def __init__(self, view):
        self._view = view

    def __dir__(self):
        return [x[7:] for x in SimMemView.types if x.startswith('struct ')]

    def __getattr__(self, k):
        assert k != '_view'
        return self._view._deeper(ty=SimMemView.types['struct ' + k].with_arch(self._view.state.arch))

    def __setattr__(self, k, v):
        if k == '_view':
            object.__setattr__(self, k, v)
        else:
            self.__getattr__(k).store(v)

from ..sim_type import ALL_TYPES, SimTypeFixedSizeArray, SimTypePointer
SimMemView.types = ALL_TYPES # identity purposefully here


from angr.sim_state import SimState
SimState.register_default('mem', SimMemView)
SimState.register_default('regs', SimRegNameView)
