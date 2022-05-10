import collections.abc
import claripy
from typing import Optional, TYPE_CHECKING

from .protos import variables_pb2 as pb2
from .serializable import Serializable

if TYPE_CHECKING:
    import archinfo


class SimVariable(Serializable):

    __slots__ = ['ident', 'name', 'region', 'category', 'renamed', 'candidate_names', 'size', ]

    def __init__(self, ident=None, name=None, region: Optional[int]=None, category=None, size: Optional[int]=None):
        """
        :param ident: A unique identifier provided by user or the program. Usually a string.
        :param str name: Name of this variable.
        """
        self.ident = ident
        self.name = name
        self.region: Optional[int] = region
        self.category: Optional[str] = category
        self.renamed = False
        self.candidate_names = None
        self.size = size

    def copy(self):
        raise NotImplementedError()

    def loc_repr(self, arch: 'archinfo.Arch'):
        """
        The representation that shows up in a GUI
        """
        raise NotImplementedError()

    def _set_base(self, obj):
        obj.base.ident = self.ident
        if self.category is not None:
            obj.base.category = self.category
        if self.region is not None:
            obj.base.region = self.region
        if self.name is not None:
            obj.base.name = self.name
        obj.base.renamed = self.renamed

    def _from_base(self, obj):
        self.ident = obj.base.ident
        if obj.base.HasField("category"):
            self.category = obj.base.category
        else:
            self.category = None
        if obj.base.HasField("region"):
            self.region = obj.base.region
        self.name = obj.base.name
        self.renamed = obj.base.renamed

    @property
    def is_function_argument(self):
        return self.ident and self.ident.startswith("arg_")

    #
    # Operations
    #

    def __add__(self, other):
        if isinstance(other, int) and other == 0:
            return self
        return None

    def __sub__(self, other):
        if isinstance(other, int) and other == 0:
            return self
        return None


class SimConstantVariable(SimVariable):

    __slots__ = ['value', '_hash']

    def __init__(self, ident=None, value=None, region=None, size=None):
        super().__init__(ident=ident, region=region, size=size)
        self.value = value
        self._hash = None

    def __repr__(self):
        s = "<%s|const %s>" % (self.region, self.value)

        return s

    def loc_repr(self, arch):
        return f'const {self.value}'

    def __eq__(self, other):
        if not isinstance(other, SimConstantVariable):
            return False

        if self.value is None or other.value is None:
            # they may or may not represent the same constant. return not equal to be safe
            return False

        return self.ident == other.ident and self.value == other.value and self.region == other.region

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(('const', self.value, self.ident, self.region, self.ident))
        return self._hash

    def copy(self) -> 'SimConstantVariable':
        r = SimConstantVariable(ident=self.ident, value=self.value, region=self.region, size=self.size)
        r._hash = self._hash
        return r


class SimTemporaryVariable(SimVariable):

    __slots__ = ['tmp_id', '_hash']

    def __init__(self, tmp_id, size=None):
        SimVariable.__init__(self, size=size)

        self.tmp_id = tmp_id
        self._hash = None

    def __repr__(self):
        s = "<tmp %d>" % (self.tmp_id,)
        return s

    def loc_repr(self, arch):
        return f'tmp #{self.tmp_id}'

    def __hash__(self):
        if self._hash is None:
            self._hash = hash('tmp_%d' % (self.tmp_id))
        return self._hash

    def __eq__(self, other):
        if isinstance(other, SimTemporaryVariable):
            return hash(self) == hash(other)

        return False

    def copy(self) -> 'SimTemporaryVariable':
        r = SimTemporaryVariable(self.tmp_id, size=self.size)
        r._hash = self._hash
        return r

    @classmethod
    def _get_cmsg(cls):
        return pb2.TemporaryVariable()

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        self._set_base(obj)
        obj.tmp_id = self.tmp_id
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        obj = cls(cmsg.tmp_id)
        obj._from_base(cmsg)
        return obj


class SimRegisterVariable(SimVariable):

    __slots__ = ['reg', '_hash']

    def __init__(self, reg_offset, size, ident=None, name=None, region=None, category=None):
        SimVariable.__init__(self, ident=ident, name=name, region=region, category=category, size=size)

        self.reg: int = reg_offset
        self._hash: Optional[int] = None

    @property
    def bits(self):
        return self.size * 8

    def __repr__(self):

        ident_str = "[%s]" % self.ident if self.ident else ""
        region_str = hex(self.region) if isinstance(self.region, int) else self.region

        s = "<%s%s|Reg %s, %sB>" % (region_str, ident_str, self.reg, self.size)

        return s

    def loc_repr(self, arch):
        return arch.translate_register_name(self.reg, self.size)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(('reg', self.region, self.reg, self.size, self.ident))
        return self._hash

    def __eq__(self, other):
        if isinstance(other, SimRegisterVariable):
            return self.ident == other.ident and \
                   self.reg == other.reg and \
                   self.size == other.size and \
                   self.region == other.region

        return False

    def copy(self) -> 'SimRegisterVariable':
        s = SimRegisterVariable(self.reg, self.size, ident=self.ident, name=self.name, region=self.region,
                                category=self.category)
        s._hash = self._hash
        return s

    @classmethod
    def _get_cmsg(cls):
        return pb2.RegisterVariable()

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        self._set_base(obj)
        obj.reg = self.reg
        obj.size = self.size
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        obj = cls(cmsg.reg,
                  cmsg.size,
                  )
        obj._from_base(cmsg)
        return obj


class SimMemoryVariable(SimVariable):

    __slots__ = ['addr', '_hash']

    def __init__(self, addr, size, ident=None, name=None, region=None, category=None):
        SimVariable.__init__(self, ident=ident, name=name, region=region, category=category, size=size)

        self.addr = addr

        if isinstance(size, claripy.ast.BV) and not size.symbolic:
            # Convert it to a concrete number
            size = size._model_concrete.value

        self.size = size
        self._hash = None

    def __repr__(self):
        if type(self.size) is int:
            size = '%d' % self.size
        else:
            size = '%s' % self.size

        if type(self.addr) is int:
            s = "<%s: %s-Mem %#x %s>" % (self.name, self.region, self.addr, size)
        else:
            s = "<%s: %s-Mem %s %s>" % (self.name, self.region, self.addr, size)

        return s

    def loc_repr(self, arch):
        return f'[{self.addr:#x}]'

    def __hash__(self):
        if self._hash is not None:
            return self._hash

        if isinstance(self.addr, AddressWrapper):
            addr_hash = hash(self.addr)
        elif type(self.addr) is int:
            addr_hash = self.addr
        elif self.addr._model_concrete is not self.addr:
            addr_hash = hash(self.addr._model_concrete)
        elif self.addr._model_vsa is not self.addr:
            addr_hash = hash(self.addr._model_vsa)
        elif self.addr._model_z3 is not self.addr:
            addr_hash = hash(self.addr._model_z3)
        else:
            addr_hash = hash(self.addr)
        self._hash = hash((addr_hash, hash(self.size), self.ident))

        return self._hash

    def __eq__(self, other):
        if isinstance(other, SimMemoryVariable):
            return self.ident == other.ident and \
                   self.addr == other.addr and \
                   self.size == other.size

        return False

    @property
    def bits(self):
        return self.size * 8

    def copy(self) -> 'SimMemoryVariable':
        r = SimMemoryVariable(self.addr, self.size, ident=self.ident, name=self.name, region=self.region,
                              category=self.category)
        r._hash = self._hash
        return r

    @classmethod
    def _get_cmsg(cls):
        return pb2.MemoryVariable()

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        self._set_base(obj)
        obj.addr = self.addr
        obj.size = self.size
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        obj = cls(cmsg.addr,
                  cmsg.size,
                  )
        obj._from_base(cmsg)
        return obj


class SimStackVariable(SimMemoryVariable):

    __slots__ = ('base', 'offset', 'base_addr',)

    def __init__(self, offset, size, base='sp', base_addr=None, ident=None, name=None, region=None, category=None):
        if isinstance(offset, int) and offset > 0x1000000:
            # I don't think any positive stack offset will be greater than that...
            # convert it to a negative number
            mask = (1 << offset.bit_length()) - 1
            offset = - ((0 - offset) & mask)

        if base_addr is not None:
            addr = offset + base_addr
        else:
            # TODO: this is not optimal
            addr = offset

        super().__init__(addr, size, ident=ident, name=name, region=region, category=category)

        self.base = base
        self.offset = offset
        self.base_addr = base_addr

    def __repr__(self):
        if type(self.size) is int:
            size = '%d' % self.size
        else:
            size = '%s' % self.size

        prefix = "%s(stack)" % self.name if self.name is not None else "Stack"
        ident = "[%s]" % self.ident if self.ident else ""
        region_str = hex(self.region) if isinstance(self.region, int) else self.region

        if type(self.offset) is int:
            if self.offset < 0:
                offset = "%#x" % self.offset
            elif self.offset > 0:
                offset = "+%#x" % self.offset
            else:
                offset = ""

            s = "<%s%s|%s %s%s, %s B>" % (region_str, ident, prefix, self.base, offset, size)
        else:
            s = "<%s%s|%s %s%s, %s B>" % (region_str, ident, prefix, self.base, self.addr, size)

        return s

    def loc_repr(self, arch):
        return f'[{self.base}{self.offset:+#x}]'

    def __eq__(self, other):
        if type(other) is not SimStackVariable:
            return False

        return self.ident == other.ident and \
               self.base == other.base and \
               self.offset == other.offset and \
               self.size == other.size

    def __hash__(self):
        return hash((self.ident, self.base, self.offset, self.size))

    def copy(self) -> 'SimStackVariable':
        s = SimStackVariable(self.offset, self.size, base=self.base, base_addr=self.base_addr,
                             ident=self.ident, name=self.name, region=self.region, category=self.category)
        s._hash = self._hash
        return s

    @classmethod
    def _get_cmsg(cls):
        return pb2.StackVariable()

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        self._set_base(obj)
        obj.sp_base = self.base == "sp"
        obj.offset = self.offset
        obj.size = self.size
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        obj = cls(cmsg.offset,
                  cmsg.size,
                  base='sp' if cmsg.sp_base else "bp",
                  )
        obj._from_base(cmsg)
        return obj


class SimVariableSet(collections.abc.MutableSet):
    """
    A collection of SimVariables.
    """

    def __init__(self):

        self.register_variables = set()
        # For the sake of performance optimization, all elements in register_variables must be concrete integers which
        # representing register offsets..
        # There shouldn't be any problem apart from GetI/PutI instructions. We simply ignore them for now.
        # TODO: Take care of register offsets that are not aligned to (arch.bytes)
        # TODO: arch.bits/what? That number has no power here anymore.
        self.register_variable_offsets = set()

        # memory_variables holds SimMemoryVariable objects
        self.memory_variables = set()
        # For the sake of performance, we have another set that stores memory addresses of memory_variables
        self.memory_variable_addresses = set()

    def add(self, item):  # pylint:disable=arguments-differ
        if type(item) is SimRegisterVariable:
            if not self.contains_register_variable(item):
                self.add_register_variable(item)
        elif type(item) is SimMemoryVariable:
            if not self.contains_memory_variable(item):
                self.add_memory_variable(item)
        else:
            # TODO:
            raise Exception('WTF')

    def add_register_variable(self, reg_var):
        self.register_variables.add(reg_var)
        self.register_variable_offsets.add(reg_var.reg)

    def add_memory_variable(self, mem_var):
        self.memory_variables.add(mem_var)
        base_address = mem_var.addr.address # Dealing with AddressWrapper
        for i in range(mem_var.size):
            self.memory_variable_addresses.add(base_address + i)

    def discard(self, item):  # pylint:disable=arguments-differ
        if type(item) is SimRegisterVariable:
            if self.contains_register_variable(item):
                self.discard_register_variable(item)
        elif isinstance(item, SimMemoryVariable):
            if self.contains_memory_variable(item):
                self.discard_memory_variable(item)
        else:
            # TODO:
            raise Exception('')

    def discard_register_variable(self, reg_var):
        self.register_variables.remove(reg_var)
        self.register_variable_offsets.remove(reg_var.reg)

    def discard_memory_variable(self, mem_var):
        self.memory_variables.remove(mem_var)
        for i in range(mem_var.size):
            self.memory_variable_addresses.remove(mem_var.addr.address + i)

    def __len__(self):
        return len(self.register_variables) + len(self.memory_variables)

    def __iter__(self):
        for i in self.register_variables: yield i
        for i in self.memory_variables: yield i

    def add_memory_variables(self, addrs, size):
        for a in addrs:
            var = SimMemoryVariable(a, size)
            self.add_memory_variable(var)

    def copy(self):
        s = SimVariableSet()
        s.register_variables |= self.register_variables
        s.register_variable_offsets |= self.register_variable_offsets
        s.memory_variables |= self.memory_variables
        s.memory_variable_addresses |= self.memory_variable_addresses

        return s

    def complement(self, other):
        """
        Calculate the complement of `self` and `other`.

        :param other:   Another SimVariableSet instance.
        :return:        The complement result.
        """

        s = SimVariableSet()
        s.register_variables = self.register_variables - other.register_variables
        s.register_variable_offsets = self.register_variable_offsets - other.register_variable_offsets
        s.memory_variables = self.memory_variables - other.memory_variables
        s.memory_variable_addresses = self.memory_variable_addresses - other.memory_variable_addresses

        return s

    def contains_register_variable(self, reg_var):
        reg_offset = reg_var.reg
        # TODO: Make sure reg_offset is aligned to machine-word length

        return reg_offset in self.register_variable_offsets

    def contains_memory_variable(self, mem_var):
        a = mem_var.addr
        if type(a) in (tuple, list): a = a[-1]

        return a in self.memory_variable_addresses

    def __ior__(self, other):
        # other must be a SimVariableSet
        self.register_variables |= other.register_variables
        self.register_variable_offsets |= other.register_variable_offsets
        self.memory_variables |= other.memory_variables
        self.memory_variable_addresses |= other.memory_variable_addresses

    def __contains__(self, item):
        if type(item) is SimRegisterVariable:

            return self.contains_register_variable(item)

        elif type(item) is SimMemoryVariable:
            # TODO: Make it better!
            return self.contains_memory_variable(item)

        else:
            __import__('ipdb').set_trace()
            raise Exception("WTF is this variable?")


from .storage.memory_mixins.regioned_memory.region_data import AddressWrapper
