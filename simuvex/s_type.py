from z3 import eq
import symexec

class SimType(object):
    '''
    SimType exists to track type information for SimProcedures.
    '''

    _fields = ()

    def __init__(self, label=None):
        '''
        @param label: the type label
        '''
        self.label = label

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        for attr in self._fields:
            thing1, thing2 = getattr(self, attr), getattr(other, attr)
                        # Yes, this is very hacky, but it generally works
            if hasattr(thing1, '_obj') or hasattr(thing2, '_obj'): # crap, at least one's a Wrapper
                if (hasattr(thing1, '_obj') and not hasattr(thing2, '_obj')) \
                   or (not hasattr(thing1, '_obj') and hasattr(thing2, '_obj')):
                    return False
                elif not eq(thing1._obj, thing2._obj):
                    return False
            elif thing1 != thing2:
                return False
        else:
            return True

    def __ne__(self, other):
        # wow many efficient
        return not (self == other)

    def __hash__(self):
        # very hashing algorithm many secure wow
        out = hash(type(self))
        for attr in self._fields:
            if isinstance(getattr(self, attr), symexec.Wrapper):
                out ^= hash(getattr(self, attr)._obj.sexpr())
            elif isinstance(getattr(self, attr), symexec.BV):
                out ^= hash(str(getattr(self, attr)))
            else:
                out ^= hash(getattr(self, attr))
        return out

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

    def __repr__(self):
        return 'char'

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
        self.pts_to = pts_to

    def __repr__(self):
        return '{}*'.format(self.pts_to)

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
        SimType.__init__(self, label=label)

    def __repr__(self):
        return 'string_t'

class SimTypeFunction(SimType):
    '''
    SimTypeFunction is a type that specifies an actual function (i.e. not a pointer) with certain types of arguments and a certain return value.
    '''

    _fields = ('args', 'returnty')

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
        return '({}) -> {}'.format(', '.format(str(a) for a in self.args), self.returnty)

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

    def __repr__(self):
        return 'size_t'
