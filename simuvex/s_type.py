from collections import OrderedDict, defaultdict

from z3 import eq
import claripy

try:
    import pycparser
except ImportError:
    pycparser = None

class SimType(object):
    '''
    SimType exists to track type information for SimProcedures.
    '''

    _fields = ()
    base = True

    def __init__(self, label=None):
        '''
        @param label: the type label
        '''
        self.label = label

    def __eq__(self, other):
        if type(self) != type(other):
            return False

        for attr in self._fields:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        # wow many efficient
        return not self == other

    def __hash__(self):
        # very hashing algorithm many secure wow
        out = hash(type(self))
        for attr in self._fields:
            out ^= hash(getattr(self, attr))
        return out

    def view(self, state, addr):
        return SimMemView(ty=self, addr=addr, state=state)

    @property
    def name(self):
        return repr(self)

    def _refine_dir(self):
        return []

    def _refine(self, view, k):
        if k == 'array':
            return lambda length: view._deeper(ty=SimTypeFixedSizeArray(self, length))
        raise KeyError("{} is not a valid refinement".format(k))

class SimTypeBottom(SimType):
    '''
    SimTypeBottom basically repesents a type error.
    '''

    def __repr__(self):
        return 'BOT'

class SimTypeTop(SimType):
    '''
    SimTypeTop represents any type (mostly used with a pointer for void*).
    '''

    _fields = ('size',)

    def __init__(self, size=None):
        SimType.__init__(self)
        self.size = size

    def __repr__(self):
        return 'TOP'

class SimTypeReg(SimType):
    '''
    SimTypeReg is the base type for all types that are register-sized.
    '''

    _fields = ('size',)

    def __init__(self, size, label=None):
        '''
        @param label: the type label
        @param size: the size of the type (e.g. 32bit, 8bit, etc.)
        '''
        SimType.__init__(self, label=label)
        self.size = size

    def __repr__(self):
        return "reg{}_t".format(self.size)

    def extract(self, state, addr):
        return state.memory.load(addr, self.size / 8, endness=state.arch.memory_endness)

    def store(self, state, addr, value):
        if isinstance(value, claripy.ast.BV):
            if value.size() != self.size:
                raise ValueError("size of expression is wrong size for type")
        elif isinstance(value, (int, long)):
            value = state.se.BVV(value, self.size)
        else:
            raise TypeError("unrecognized expression type for SimType {}".format(type(self).__name__))

        state.memory.store(addr, value, endness=state.arch.memory_endness)

class SimTypeInt(SimTypeReg):
    '''
    SimTypeInt is a type that specifies a signed or unsigned integer of some size.
    '''

    _fields = SimTypeReg._fields + ('signed',)

    def __init__(self, size, signed, label=None):
        '''
        @param label: the type label
        @param size: the size of the integer (e.g. 32bit, 8bit, etc.)
        @param signed: True if signed, False if unsigned
        '''
        SimTypeReg.__init__(self, size, label=label)
        self.signed = signed

    def __repr__(self):
        return ('' if self.signed else 'u') + 'int{}_t'.format(self.size)

class SimTypeChar(SimTypeReg):
    '''
    SimTypeChar is a type that specifies a character;
    this could be represented by an 8-bit int, but this is meant to be interpreted as a character.
    '''

    _fields = SimTypeReg._fields

    def __init__(self, label=None):
        '''
        @param label: the type label
        '''
        SimTypeReg.__init__(self, 8, label=label) # a char better be 8 bits (I'm looking at you, DCPU-16)
        self.signed = False

    def __repr__(self):
        return 'char'

    def store(self, state, addr, value):
        try:
            super(SimTypeChar, self).store(state, addr, value)
        except TypeError:
            if isinstance(value, str) and len(value) == 1:
                value = state.se.BVV(ord(value), 8)
                super(SimTypeChar, self).store(state, addr, value)
            else:
                raise

class SimTypeFd(SimTypeReg):
    '''
    SimTypeFd is a type that specifies a file descriptor.
    '''

    _fields = SimTypeReg._fields

    def __init__(self, label=None):
        '''
        @param label: the type label
        '''
        # file descriptors are always 32 bits, right?
        SimTypeReg.__init__(self, 32, label=label)

    def __repr__(self):
        return 'fd_t'

class SimTypePointer(SimTypeReg):
    '''
    SimTypePointer is a type that specifies a pointer to some other type.
    '''

    _fields = SimTypeReg._fields + ('pts_to',)

    def __init__(self, arch, pts_to, label=None):
        '''
        @param label: the type label
        @param pts_to: the type to which this pointer points to
        '''
        SimTypeReg.__init__(self, arch.bits, label=label)
        self._arch = arch
        self.pts_to = pts_to
        self.signed = False

    def __repr__(self):
        return '{}*'.format(self.pts_to)

    def make(self, pts_to):
        new = type(self)(self._arch, pts_to)
        return new

class SimTypeFixedSizeArray(SimType):
    '''
    SimTypeFixedSizeArray is a literal (i.e. not a pointer) fixed-size array.
    '''

    def __init__(self, elem_type, length):
        SimType.__init__(self)
        self.elem_type = elem_type
        self.length = length
        self.size = elem_type.size * length

    def __repr__(self):
        return '{}[{}]'.format(self.elem_type, self.length)

    def extract(self, state, addr):
        return [self.elem_type.extract(state, addr + i*self.elem_type.size) for i in xrange(self.length)]

    def store(self, state, addr, values):
        for i, val in enumerate(values):
            self.elem_type.store(state, addr + i*self.elem_type.size, val)

class SimTypeArray(SimType):
    '''
    SimTypeArray is a type that specifies a pointer to an array; while it is a pointer, it has a semantic difference.
    '''

    _fields = ('elem_type', 'length')

    def __init__(self, elem_type, length=None, label=None):
        '''
        @param label: the type label
        @param elem_type: the type of each element in the array
        @param length: an expression of the length of the array, if known
        '''
        SimType.__init__(self, label=label)
        self.elem_type = elem_type
        self.length = length

    def __repr__(self):
        return '{}[{}]'.format(self.elem_type, '' if self.length is None else self.length)

class SimTypeString(SimTypeArray):
    '''
    SimTypeString is a type that represents a C-style string,
    i.e. a NUL-terminated array of bytes.
    '''

    _fields = SimTypeArray._fields + ('length',)

    def __init__(self, length=None, label=None):
        '''
        @param label: the type label
        @param length: an expression of the length of the string, if known
        '''
        SimTypeArray.__init__(self, SimTypeChar(), label=label)
        self.length = length

    def __repr__(self):
        return 'string_t'

    def extract(self, state, addr):
        mem = state.memory.load(addr, self.length)
        if state.se.symbolic(mem):
            return mem
        else:
            return repr(state.se.any_str(mem))

class SimTypeFunction(SimType):
    '''
    SimTypeFunction is a type that specifies an actual function (i.e. not a pointer) with certain types of arguments and a certain return value.
    '''

    _fields = ('args', 'returnty')
    base = False

    def __init__(self, args, returnty, label=None):
        '''
        @param label: the type label
        @param args: a tuple of types representing the arguments to the function
        @param returnty: the return type of the function
        '''
        SimType.__init__(self, label=label)
        self.args = args
        self.returnty = returnty

    def __repr__(self):
        return '({}) -> {}'.format(', '.join(str(a) for a in self.args), self.returnty)

class SimTypeLength(SimTypeInt):
    '''
    SimTypeLength is a type that specifies the length of some buffer in memory.
    '''

    _fields = SimTypeInt._fields + ('addr', 'length') # ?

    def __init__(self, arch, addr=None, length=None, label=None):
        '''
        @param label: the type label
        @param addr: the memory address (expression)
        @param length: the length (expression)
        '''
        SimTypeInt.__init__(self, arch.bits, False, label=label)
        self.addr = addr
        self.length = length
        self.signed = False

    def __repr__(self):
        return 'size_t'

class SimStructValue(object):
    def __init__(self, struct, values=None):
        self._struct = struct
        self._values = defaultdict(lambda: None, values or ())

    def __repr__(self):
        fields = ('.{} = {}'.format(name, self._values[name]) for name in self._struct.fields)
        return '{{\n  {}\n}}'.format(',\n  '.join(fields))

_C_TYPE_TO_SIMTYPE = {
    ('int',): lambda _: SimTypeInt(32, True),
    ('unsigned', 'int'): lambda _: SimTypeInt(32, False),
    ('long',): lambda arch: SimTypeInt(arch.bits, True),
    ('unsigned', 'long'): lambda arch: SimTypeInt(arch.bits, False),
    ('char',): lambda _: SimTypeChar(),
    ('int8_t',): lambda _: SimTypeInt(8, True),
    ('uint8_t',): lambda _: SimTypeInt(8, False),
    ('int16_t',): lambda _: SimTypeInt(16, True),
    ('uint16_t',): lambda _: SimTypeInt(16, False),
    ('int32_t',): lambda _: SimTypeInt(32, True),
    ('uint32_t',): lambda _: SimTypeInt(32, False),
    ('int64_t',): lambda _: SimTypeInt(64, True),
    ('uint64_t',): lambda _: SimTypeInt(64, False),
    ('ptrdiff_t',): lambda arch: SimTypeInt(arch.bits, False),
    ('size_t',): lambda arch: SimTypeInt(arch.bits, False),
    ('ssize_t',): lambda arch: SimTypeInt(arch.bits, True),
    ('uintptr_t',) : lambda arch: SimTypeInt(arch.bits, False),
}

def _decl_to_type(decl):
    if isinstance(decl, pycparser.c_ast.TypeDecl):
        return _C_TYPE_TO_SIMTYPE[tuple(decl.type.names)]
    elif isinstance(decl, pycparser.c_ast.PtrDecl):
        pts_to = _decl_to_type(decl.type)
        return lambda arch: SimTypePointer(arch, pts_to(arch))
    elif isinstance(decl, pycparser.c_ast.ArrayDecl):
        elem_type = _decl_to_type(decl.type)
        size = int(decl.dim.value)
        return lambda arch: SimTypeFixedSizeArray(elem_type(arch), size)

# these are all bogus, on purpose
_C_STRUCT_PREAMBLE = """
typedef int int8_t;
typedef int uint8_t;
typedef int int16_t;
typedef int uint16_t;
typedef int int32_t;
typedef int uint32_t;
typedef int int64_t;
typedef int uint64_t;
"""

class SimStruct(SimType):
    _fields = ('name', 'fields')

    def __init__(self, name, fields, pack=True):
        if not pack:
            raise ValueError("you think I've implemented padding, how cute")

        self._name = name
        self.fields = fields
        self._arch_offsets_cache = {}

    def _arch_offsets(self, arch):
        if arch in self._arch_offsets_cache:
            return self._arch_offsets_cache[arch]

        offsets = {}
        offset_so_far = 0
        for name, almost_ty in self.fields.iteritems():
            ty = almost_ty(arch)
            offsets[name] = (ty, offset_so_far)
            offset_so_far += ty.size / 8

        self._arch_offsets_cache[arch] = offsets
        return offsets

    def extract(self, state, addr):
        values = {name: ty.view(state, addr + offset)
                  for (name, (ty, offset))
                  in self._arch_offsets(state.arch).iteritems()}
        return SimStructValue(self, values=values)

    @property
    def name(self):
        return self._name

    @classmethod
    def from_c(cls, defn):
        if pycparser is None:
            raise ImportError("pycparser is needed to use SimStruct.from_c!")

        # if preprocess:
        #     defn = subprocess.Popen(['cpp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate(input=defn)[0]

        node = pycparser.c_parser.CParser().parse(_C_STRUCT_PREAMBLE + defn)

        if not isinstance(node, pycparser.c_ast.FileAST) or \
           not isinstance(node.ext[-1], pycparser.c_ast.Decl) or \
           not isinstance(node.ext[-1].type, pycparser.c_ast.Struct):
            raise ValueError("invalid struct definition")

        struct = node.ext[-1].type
        fields = OrderedDict((decl.name, _decl_to_type(decl.type)) for decl in struct.decls)

        return cls(struct.name, fields)

    def _refine_dir(self):
        return self.fields.keys()

    def _refine(self, view, k):
        ty, offset = self._arch_offsets(view.state.arch)[k]
        return view._deeper(ty=ty, addr=view._addr + offset)

try:
    _example_struct = SimStruct.from_c("""
struct example {
  int foo;
  int bar;
  char *hello;
};
""")
except ImportError:
    _example_struct = None

ALL_TYPES = {
    'char': lambda _: SimTypeInt(8, True),
    'int8_t': lambda _: SimTypeInt(8, True),
    'uchar': lambda _: SimTypeInt(8, False),
    'uint8_t': lambda _: SimTypeInt(8, False),
    'byte': lambda _: SimTypeInt(8, False),

    'short': lambda _: SimTypeInt(16, True),
    'int16_t': lambda _: SimTypeInt(16, True),
    'ushort': lambda _: SimTypeInt(16, False),
    'uint16_t': lambda _: SimTypeInt(16, False),
    'word': lambda _: SimTypeInt(16, False),

    'int': lambda _: SimTypeInt(32, True),
    'int32_t': lambda _: SimTypeInt(32, True),
    'uint': lambda _: SimTypeInt(32, False),
    'uint32_t': lambda _: SimTypeInt(32, False),
    'dword': lambda _: SimTypeInt(32, False),

    'long': lambda _: SimTypeInt(64, True),
    'int64_t': lambda _: SimTypeInt(64, True),
    'ulong': lambda _: SimTypeInt(64, False),
    'uint64_t': lambda _: SimTypeInt(64, False),
    'qword': lambda _: SimTypeInt(64, False),

    'string': lambda arch: SimTypePointer(arch, SimTypeChar()),
    'example': lambda _: _example_struct,


}

def define_struct(defn):
    struct = SimStruct.from_c(defn)
    ALL_TYPES[struct.name] = lambda _: struct
    return struct

from .plugins.view import SimMemView
