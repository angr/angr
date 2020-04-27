
from itertools import count

# Type variables and constraints


class Equivalence:
    def __init__(self, type_a, type_b):
        self.type_a = type_a
        self.type_b = type_b

    def __repr__(self):
        return "%s == %s" % (self.type_a, self.type_b)

    def __eq__(self, other):
        return type(other) is Equivalence and (
                self.type_a == other.type_a and self.type_b == other.type_b or
                self.type_b == other.type_a and self.type_a == other.type_b)

    def __hash__(self):
        return hash((Equivalence, tuple(sorted(
            (hash(self.type_a), hash(self.type_b)
             ))
        )))


class Existence:
    def __init__(self, type_):
        self.type_ = type_

    def __repr__(self):
        return "V %s" % self.type_

    def __eq__(self, other):
        return type(other) is Existence and self.type_ == other.type_

    def __hash__(self):
        return hash((Existence, self.type_))

    def replace(self, replacements):

        if self.type_ in replacements:
            return True, Existence(replacements[self.type_])

        else:
            replaced, new_type = self.type_.replace(replacements)
            if replaced:
                return True, Existence(new_type)
            return False, self


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

    def replace(self, replacements):

        subtype, supertype = None, None

        if self.sub_type in replacements:
            subtype = replacements[self.sub_type]
        else:
            if isinstance(self.sub_type, DerivedTypeVariable):
                r, newtype = self.sub_type.replace(replacements)
                if r:
                    subtype = newtype

        if self.super_type in replacements:
            supertype = replacements[self.super_type]
        else:
            if isinstance(self.super_type, DerivedTypeVariable):
                r, newtype = self.super_type.replace(replacements)
                if r:
                    supertype = newtype

        if subtype is not None or supertype is not None:
            # replacement has happened
            return True, Subtype(supertype if supertype is not None else self.super_type,
                                 subtype if subtype is not None else self.sub_type)
        else:
            return False, self


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
        return "tv_%02d" % self.idx


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

    def replace(self, replacements):

        typevar = None

        if self.type_var in replacements:
            typevar = replacements[self.type_var]
        else:
            if isinstance(self.type_var, DerivedTypeVariable):
                r, t = self.type_var.replace(replacements)
                if r:
                    typevar = t

        if typevar is not None:
            # replacement has happened
            return True, DerivedTypeVariable(typevar, self.label, idx=self.idx)
        else:
            return False, self


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

    def add_type_variable(self, var, codeloc, typevar):  # pylint:disable=unused-argument

        #if var not in self._typevars:
        #    self._typevars[var] = { }

        # assert codeloc not in self._typevars[var]
        # self._typevars[var][codeloc] = typevar
        self._typevars[var] = typevar

    def get_type_variable(self, var, codeloc):  # pylint:disable=unused-argument

        return self._typevars[var] #[codeloc]

    def has_type_variable_for(self, var, codeloc):  # pylint:disable=unused-argument
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


class ConvertTo(BaseLabel):

    __slots__ = ('to_bits', )

    def __init__(self, to_bits):
        self.to_bits = to_bits

    def __repr__(self):
        return "conv(%d)" % self.to_bits


class HasField(BaseLabel):

    __slots__ = ('bits', 'offset', )

    def __init__(self, bits, offset):
        self.bits = bits
        self.offset = offset

    def __repr__(self):
        return "<%d>@%d" % (self.bits, self.offset)
