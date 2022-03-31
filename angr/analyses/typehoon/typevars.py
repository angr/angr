# pylint:disable=missing-class-docstring
from typing import Dict, Any, Optional, TYPE_CHECKING
from itertools import count

from ...utils.cowdict import ChainMapCOW

if TYPE_CHECKING:
    from angr.sim_variable import SimVariable


# Type variables and constraints

class TypeConstraint:

    __slots__ = ()

    def pp_str(self, mapping: Dict['TypeVariable',Any]) -> str:
        raise NotImplementedError()


class Equivalence(TypeConstraint):

    __slots__ = ('type_a', 'type_b', )

    def __init__(self, type_a, type_b):
        self.type_a = type_a
        self.type_b = type_b

    def pp_str(self, mapping: Dict['TypeVariable',Any]) -> str:
        return "{} == {}".format(self.type_a.pp_str(mapping), self.type_b.pp_str(mapping))

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


class Existence(TypeConstraint):

    __slots__ = ('type_', )

    def __init__(self, type_):
        self.type_ = type_

    def pp_str(self, mapping: Dict['TypeVariable',Any]) -> str:
        return "V {}".format(self.type_.pp_str(mapping))

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


class Subtype(TypeConstraint):

    __slots__ = ('super_type', 'sub_type', )

    def __init__(self, sub_type, super_type):
        self.super_type = super_type
        self.sub_type = sub_type

    def pp_str(self, mapping: Dict['TypeVariable',Any]) -> str:
        return "{} <: {}".format(self.sub_type.pp_str(mapping), self.super_type.pp_str(mapping))

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
            return True, Subtype(subtype if subtype is not None else self.sub_type,
                                 supertype if supertype is not None else self.super_type)
        else:
            return False, self


class Add(TypeConstraint):
    """
    Describes the constraint that type_r == type0 + type1
    """

    __slots__ = ('type_0', 'type_1', 'type_r', )

    def __init__(self, type_0, type_1, type_r):
        self.type_0 = type_0
        self.type_1 = type_1
        self.type_r = type_r

    def pp_str(self, mapping: Dict['TypeVariable',Any]) -> str:
        return "{} == {} + {}".format(
            self.type_r.pp_str(mapping),
            self.type_0.pp_str(mapping),
            self.type_1.pp_str(mapping),
        )

    def __repr__(self):
        return "%r == %r + %r" % (self.type_r, self.type_0, self.type_1)

    def __eq__(self, other):
        return type(other) is Add \
               and self.type_0 == other.type_0 \
               and self.type_1 == other.type_1 \
               and self.type_r == other.type_r

    def __hash__(self):
        return hash((Add, self.type_0, self.type_1, self.type_r))

    def replace(self, replacements):

        t0, t1, tr = None, None, None

        if self.type_0 in replacements:
            t0 = replacements[self.type_0]
        elif isinstance(self.type_0, DerivedTypeVariable):
            r, newtype = self.type_0.replace(replacements)
            if r:
                t0 = newtype

        if self.type_1 in replacements:
            t1 = replacements[self.type_1]
        elif isinstance(self.type_1, DerivedTypeVariable):
            r, newtype = self.type_1.replace(replacements)
            if r:
                t1 = newtype

        if self.type_r in replacements:
            tr = replacements[self.type_r]
        elif isinstance(self.type_r, DerivedTypeVariable):
            r, newtype = self.type_r.replace(replacements)
            if r:
                tr = newtype

        if t0 is not None or t1 is not None or tr is not None:
            # replacement has happened
            return True, Add(t0 if t0 is not None else self.type_0,
                             t1 if t1 is not None else self.type_1,
                             tr if tr is not None else self.type_r)
        else:
            return False, self


class Sub(TypeConstraint):
    """
    Describes the constraint that type_r == type0 - type1
    """

    __slots__ = ('type_0', 'type_1', 'type_r',)

    def __init__(self, type_0, type_1, type_r):
        self.type_0 = type_0
        self.type_1 = type_1
        self.type_r = type_r

    def pp_str(self, mapping: Dict['TypeVariable',Any]) -> str:
        return "{} == {} - {}".format(
            self.type_r.pp_str(mapping),
            self.type_0.pp_str(mapping),
            self.type_1.pp_str(mapping),
        )

    def __repr__(self):
        return "%r == %r - %r" % (self.type_r, self.type_0, self.type_1)

    def __eq__(self, other):
        return type(other) is Sub \
               and self.type_0 == other.type_0 \
               and self.type_1 == other.type_1 \
               and self.type_r == other.type_r

    def __hash__(self):
        return hash((Sub, self.type_0, self.type_1, self.type_r))

    def replace(self, replacements):
        t0, t1, tr = None, None, None

        if self.type_0 in replacements:
            t0 = replacements[self.type_0]
        elif isinstance(self.type_0, DerivedTypeVariable):
            r, newtype = self.type_0.replace(replacements)
            if r:
                t0 = newtype

        if self.type_1 in replacements:
            t1 = replacements[self.type_1]
        elif isinstance(self.type_1, DerivedTypeVariable):
            r, newtype = self.type_1.replace(replacements)
            if r:
                t1 = newtype

        if self.type_r in replacements:
            tr = replacements[self.type_r]
        elif isinstance(self.type_r, DerivedTypeVariable):
            r, newtype = self.type_r.replace(replacements)
            if r:
                tr = newtype

        if t0 is not None or t1 is not None or tr is not None:
            # replacement has happened
            return True, Sub(t0 if t0 is not None else self.type_0,
                             t1 if t1 is not None else self.type_1,
                             tr if tr is not None else self.type_r)
        else:
            return False, self


_typevariable_counter = count()


class TypeVariable:

    __slots__ = ('idx', )

    def __init__(self, idx: Optional[int]=None):
        if idx is None:
            self.idx: int = next(_typevariable_counter)
        else:
            self.idx: int = idx

    def pp_str(self, mapping: Dict['TypeVariable',Any]) -> str:
        varname = mapping.get(self, None)
        if varname is None:
            return repr(self)
        return f"{varname} ({repr(self)})"

    def __eq__(self, other):
        return type(other) is TypeVariable and other.idx == self.idx

    def __hash__(self):
        return hash((TypeVariable, self.idx))

    def __repr__(self):
        return "tv_%02d" % self.idx


class DerivedTypeVariable(TypeVariable):

    __slots__ = ('type_var', 'label', )

    def __init__(self, type_var, label, idx=None):
        super().__init__(idx=idx)
        self.type_var = type_var
        self.label = label

    def pp_str(self, mapping: Dict['TypeVariable',Any]) -> str:
        return "{}.{}".format(self.type_var.pp_str(mapping), self.label)

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

    __slots__ = ('_typevars', )

    def __init__(self):
        self._typevars: Dict['SimVariable',TypeVariable] = ChainMapCOW(collapse_threshold=25)

    def merge(self, tvs):
        merged = TypeVariables()

        # TODO: Replace this with a real lattice-based merging
        merged._typevars = self._typevars.copy()
        if tvs._typevars:
            merged._typevars = merged._typevars.clean()
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

    def add_type_variable(self, var: 'SimVariable', codeloc, typevar: TypeVariable):  # pylint:disable=unused-argument

        #if var not in self._typevars:
        #    self._typevars[var] = { }

        # assert codeloc not in self._typevars[var]
        # self._typevars[var][codeloc] = typevar
        self._typevars = self._typevars.clean()
        self._typevars[var] = typevar

    def get_type_variable(self, var, codeloc):  # pylint:disable=unused-argument

        return self._typevars[var] #[codeloc]

    def has_type_variable_for(self, var: 'SimVariable', codeloc):  # pylint:disable=unused-argument
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


class ReinterpretAs(BaseLabel):

    __slots__ = ('to_type', 'to_bits', )

    def __init__(self, to_type, to_bits):
        self.to_type = to_type
        self.to_bits = to_bits

    def __repr__(self):
        return f"reinterpret({self.to_type}{self.to_bits})"


class HasField(BaseLabel):

    __slots__ = ('bits', 'offset', )

    def __init__(self, bits, offset):
        self.bits = bits
        self.offset = offset

    def __repr__(self):
        return "<%d>@%d" % (self.bits, self.offset)


class IsArray(BaseLabel):

    def __repr__(self):
        return "is_array"
