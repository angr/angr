
from itertools import count

"""
Type variables and constraints
"""


class Subtype:
    def __init__(self, super_type, sub_type):
        self.super_type = super_type
        self.sub_type = sub_type

    def __repr__(self):
        return "%s <: %s" % (self.sub_type, self.super_type)

    def __eq__(self, other):
        return type(other) is Subtype and self.sub_type == other.sub_type and self.super_type == other.super_type

    def __hash__(self):
        return hash((Subtype, hash(self.sub_type), hash(self.super_type)))


_typevariable_counter = count()


class TypeVariable:
    def __init__(self, idx=None):
        if idx is None:
            self.idx = next(_typevariable_counter)
        else:
            self.idx = idx

    def __eq__(self, other):
        return type(other) is TypeVariable and other.idx == self.idx

    def __hash__(self):
        return hash((TypeVariable, self.idx))

    def __repr__(self):
        return "tv_%s" % self.idx


class DerivedTypeVariable(TypeVariable):
    def __init__(self, type_var, label, idx=None):
        super().__init__(idx=idx)
        self.type_var = type_var
        self.label = label

    def __eq__(self, other):
        return isinstance(other, DerivedTypeVariable) and \
            self.type_var == other.type_var and \
            self.label == other.label

    def __hash__(self):
        return hash((DerivedTypeVariable, self.type_var, self.label))

    def __repr__(self):
        return "%r.%r" % (self.type_var, self.label)


class TypeVariables:
    def __init__(self):
        self._typevars = { }

    def merge(self, tvs):
        merged = TypeVariables()

        # TODO: Replace this with a real lattice-based merging
        merged._typevars = self._typevars.copy()
        merged._typevars.update(tvs._typevars)

        return merged

    def copy(self):
        copied = TypeVariables()
        copied._typevars = self._typevars.copy()
        return copied

    def __repr__(self):
        #return "{TypeVars: %d items for %d variables}" % (
        #    sum(len(v) for v in self._typevars.items()),
        #    len(self._typevars),
        #)
        return "{TypeVars: %d items}" % len(self._typevars)

    def add_type_variable(self, var, codeloc, typevar):

        #if var not in self._typevars:
        #    self._typevars[var] = { }

        # assert codeloc not in self._typevars[var]
        # self._typevars[var][codeloc] = typevar
        self._typevars[var] = typevar

    def get_type_variable(self, var, codeloc):

        return self._typevars[var] #[codeloc]

    def has_type_variable_for(self, var, codeloc):
        if var not in self._typevars:
            return False
        return True
        # if codeloc not in self._typevars[var]:
        #     return False
        # return True

    def __getitem__(self, var):
        return self._typevars[var]

    def __contains__(self, var):
        return var in self._typevars


#
# Labels
#


class BaseLabel:

    __slots__ = tuple()

    def __eq__(self, other):
        return type(self) is type(other) and hash(self) == hash(other)

    def __hash__(self):
        return hash(tuple(getattr(self, k) for k in self.__slots__))


class FuncIn(BaseLabel):

    __slots__ = ('loc',)

    def __init__(self, loc):
        self.loc = loc

    def __repr__(self):
        return "in<%s>" % self.loc


class FuncOut(BaseLabel):

    __slots__ = ('loc',)

    def __init__(self, loc):
        self.loc = loc

    def __repr__(self):
        return "out<%s>" % self.loc


class Load(BaseLabel):

    __slots__ = tuple()

    def __repr__(self):
        return "load"


class Store(BaseLabel):

    __slots__ = tuple()

    def __repr__(self):
        return "store"


class AddN(BaseLabel):

    __slots__ = ('n',)

    def __init__(self, n):
        self.n = n

    def __repr__(self):
        return "+%d" % self.n


class SubN(BaseLabel):

    __slots__ = ('n',)

    def __init__(self, n):
        self.n = n

    def __repr__(self):
        return "-%d" % self.n


class HasField(BaseLabel):

    __slots__ = ('bits', 'offset', )

    def __init__(self, bits, offset):
        self.bits = bits
        self.offset = offset

    def __repr__(self):
        return "<%d>@%d" % (self.bits, self.offset)
