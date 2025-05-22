# pylint:disable=missing-class-docstring
from __future__ import annotations
from typing import Any, Union, TYPE_CHECKING

from collections.abc import Sequence, Iterable
from itertools import count

from angr.utils.constants import MAX_POINTSTO_BITS
from .variance import Variance

if TYPE_CHECKING:
    from angr.sim_variable import SimVariable
    from .typeconsts import TypeConstant


# Type variables and constraints

TypeType = Union["TypeConstant", "TypeVariable", "DerivedTypeVariable"]


class TypeConstraint:
    __slots__ = ()

    def pp_str(self, mapping: dict[TypeVariable, Any]) -> str:
        raise NotImplementedError


class Equivalence(TypeConstraint):
    __slots__ = (
        "_cached_hash",
        "type_a",
        "type_b",
    )

    def __init__(self, type_a, type_b):
        self.type_a = type_a
        self.type_b = type_b
        self._cached_hash = hash((Equivalence, self.type_a, self.type_b))

    def pp_str(self, mapping: dict[TypeVariable, Any]) -> str:
        return f"{self.type_a.pp_str(mapping)} == {self.type_b.pp_str(mapping)}"

    def __repr__(self):
        return f"{self.type_a} == {self.type_b}"

    def __eq__(self, other):
        return type(other) is Equivalence and (
            (self.type_a == other.type_a and self.type_b == other.type_b)
            or (self.type_b == other.type_a and self.type_a == other.type_b)
        )

    def __hash__(self):
        return self._cached_hash


class Existence(TypeConstraint):
    __slots__ = ("_cached_hash", "type_")

    def __init__(self, type_):
        self.type_ = type_
        self._cached_hash = hash((Existence, self.type_))

    def pp_str(self, mapping: dict[TypeVariable, Any]) -> str:
        return f"V {self.type_.pp_str(mapping)}"

    def __repr__(self):
        return f"V {self.type_}"

    def __eq__(self, other):
        return type(other) is Existence and self.type_ == other.type_

    def __hash__(self):
        return self._cached_hash

    def replace(self, replacements):
        if self.type_ in replacements:
            return True, Existence(replacements[self.type_])

        replaced, new_type = self.type_.replace(replacements)
        if replaced:
            return True, Existence(new_type)
        return False, self


class Subtype(TypeConstraint):
    __slots__ = (
        "_cached_hash",
        "sub_type",
        "super_type",
    )

    def __init__(self, sub_type: TypeType, super_type: TypeType):
        self.super_type = super_type
        self.sub_type = sub_type
        self._cached_hash = hash((Subtype, self.sub_type, self.super_type))

    def pp_str(self, mapping: dict[TypeVariable, Any]) -> str:
        return f"{self.sub_type.pp_str(mapping)} <: {self.super_type.pp_str(mapping)}"

    def __repr__(self):
        return f"{self.sub_type} <: {self.super_type}"

    def __eq__(self, other):
        return type(other) is Subtype and self.sub_type == other.sub_type and self.super_type == other.super_type

    def __hash__(self):
        return self._cached_hash

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
            return True, Subtype(
                subtype if subtype is not None else self.sub_type,
                supertype if supertype is not None else self.super_type,
            )
        return False, self


class Add(TypeConstraint):
    """
    Describes the constraint that type_r == type0 + type1
    """

    __slots__ = (
        "_cached_hash",
        "type_0",
        "type_1",
        "type_r",
    )

    def __init__(self, type_0, type_1, type_r):
        self.type_0 = type_0
        self.type_1 = type_1
        self.type_r = type_r
        self._cached_hash = hash((Add, self.type_0, self.type_1, self.type_r))

    def pp_str(self, mapping: dict[TypeVariable, Any]) -> str:
        return f"{self.type_r.pp_str(mapping)} == {self.type_0.pp_str(mapping)} + {self.type_1.pp_str(mapping)}"

    def __repr__(self):
        return f"{self.type_r!r} == {self.type_0!r} + {self.type_1!r}"

    def __eq__(self, other):
        return (
            type(other) is Add
            and self.type_0 == other.type_0
            and self.type_1 == other.type_1
            and self.type_r == other.type_r
        )

    def __hash__(self):
        return self._cached_hash

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
            return True, Add(
                t0 if t0 is not None else self.type_0,
                t1 if t1 is not None else self.type_1,
                tr if tr is not None else self.type_r,
            )
        return False, self


class Sub(TypeConstraint):
    """
    Describes the constraint that type_r == type0 - type1
    """

    __slots__ = (
        "_cached_hash",
        "type_0",
        "type_1",
        "type_r",
    )

    def __init__(self, type_0, type_1, type_r):
        self.type_0 = type_0
        self.type_1 = type_1
        self.type_r = type_r
        self._cached_hash = hash((Sub, self.type_0, self.type_1, self.type_r))

    def pp_str(self, mapping: dict[TypeVariable, Any]) -> str:
        return f"{self.type_r.pp_str(mapping)} == {self.type_0.pp_str(mapping)} - {self.type_1.pp_str(mapping)}"

    def __repr__(self):
        return f"{self.type_r!r} == {self.type_0!r} - {self.type_1!r}"

    def __eq__(self, other):
        return (
            type(other) is Sub
            and self.type_0 == other.type_0
            and self.type_1 == other.type_1
            and self.type_r == other.type_r
        )

    def __hash__(self):
        return self._cached_hash

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
            return True, Sub(
                t0 if t0 is not None else self.type_0,
                t1 if t1 is not None else self.type_1,
                tr if tr is not None else self.type_r,
            )
        return False, self


_typevariable_counter = count()


class TypeVariable:
    __slots__ = ("_cached_hash", "idx", "name")

    def __init__(self, idx: int | None = None, name: str | None = None):
        if idx is None:
            self.idx: int = next(_typevariable_counter)
        else:
            self.idx: int = idx
        self.name = name

        self._cached_hash = hash((TypeVariable, self.name if self.name else self.idx))

    def pp_str(self, mapping: dict[TypeVariable, Any]) -> str:
        varname = mapping.get(self, self.name)
        if varname is None:
            return repr(self)
        return f"{varname} ({self!r})"

    def __eq__(self, other):
        if type(other) is not TypeVariable:
            return False
        if self.name or other.name:
            return self.name == other.name
        return self.idx == other.idx

    def _hash(self, visited=None):  # pylint:disable=unused-argument
        return self._cached_hash

    def __hash__(self):
        return self._cached_hash

    def __repr__(self):
        if self.name:
            return f"{self.name}|tv_{self.idx:02d}"
        return f"tv_{self.idx:02d}"


class DerivedTypeVariable(TypeVariable):
    __slots__ = ("labels", "type_var")

    type_var: TypeVariable
    labels: tuple[BaseLabel, ...]

    def __init__(
        self,
        type_var: TypeVariable | DerivedTypeVariable,
        label: BaseLabel | None,
        labels: Iterable[BaseLabel] | None = None,
        idx=None,
    ):
        super().__init__(idx=idx)
        if isinstance(type_var, DerivedTypeVariable):
            existing_labels = type_var.labels
            self.type_var = type_var.type_var
            assert not isinstance(self.type_var, DerivedTypeVariable)
        else:
            existing_labels = ()
            self.type_var = type_var

        if label is not None and labels:
            raise TypeError("You cannot specify both label and labels at the same time")

        if label is not None:
            self.labels = (*existing_labels, label)
        elif labels is not None:
            self.labels = existing_labels + tuple(labels)
        else:
            self.labels = existing_labels

        if not self.labels:
            raise ValueError("A DerivedTypeVariable must have at least one label")

        self._cached_hash = hash((DerivedTypeVariable, self.type_var, self.labels))

    def one_label(self) -> BaseLabel | None:
        return self.labels[0] if len(self.labels) == 1 else None

    def path(self) -> tuple[BaseLabel, ...]:
        return self.labels

    def longest_prefix(self) -> TypeType | None:
        if not self.labels:
            return None
        if len(self.labels) == 1:
            return self.type_var
        return DerivedTypeVariable(self.type_var, None, labels=self.labels[:-1])

    def pp_str(self, mapping: dict[TypeVariable, Any]) -> str:
        return ".".join([self.type_var.pp_str(mapping)] + [repr(lbl) for lbl in self.labels])

    def __eq__(self, other):
        return (
            isinstance(other, DerivedTypeVariable) and self.type_var == other.type_var and self.labels == other.labels
        )

    def _hash(self, visited=None):
        return self._cached_hash

    def __hash__(self):
        return self._cached_hash

    def __repr__(self):
        return ".".join([repr(self.type_var)] + [repr(lbl) for lbl in self.labels])

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
            return True, DerivedTypeVariable(typevar, None, labels=self.labels, idx=self.idx)
        return False, self


class TypeVariables:
    __slots__ = (
        "_last_typevars",
        "_typevar2var",
        "_typevars",
    )

    def __init__(self):
        self._typevars: dict[SimVariable, set[TypeVariable]] = {}
        self._typevar2var: dict[TypeVariable, SimVariable] = {}
        self._last_typevars: dict[SimVariable, TypeVariable] = {}

    def copy(self):
        copied = TypeVariables()
        for var, typevars in self._typevars.items():
            copied._typevars[var] = typevars.copy()
        copied._last_typevars = self._last_typevars.copy()
        return copied

    def __repr__(self):
        # return "{TypeVars: %d items for %d variables}" % (
        #    sum(len(v) for v in self._typevars.items()),
        #    len(self._typevars),
        # )
        return f"{{TypeVars: {len(self._typevars)} items}}"

    def add_type_variable(self, var: SimVariable, typevar: TypeVariable, latest: bool = True):
        if var not in self._typevars:
            self._typevars[var] = set()
        elif typevar in self._typevars[var]:
            return
        self._typevars[var].add(typevar)
        if latest:
            self._last_typevars[var] = typevar
        self._typevar2var[typevar] = var

    def get_type_variable(self, var):  # pylint:disable=unused-argument
        return self._last_typevars[var]

    def has_type_variable_for(self, var: SimVariable):  # pylint:disable=unused-argument
        return var in self._typevars

    def typevar_to_variable(self, typevar: TypeVariable) -> SimVariable | None:
        return self._typevar2var.get(typevar, None)

    def __getitem__(self, var):
        return self._last_typevars[var]

    def __contains__(self, var):
        return var in self._typevars


#
# Labels
#


class BaseLabel:
    __slots__ = ("_cached_hash",)

    def __init__(self):
        self._cached_hash = hash((type(self), *tuple(getattr(self, k) for k in self.__slots__ if k != "_cached_hash")))

    def __eq__(self, other):
        return type(self) is type(other) and self._cached_hash == other._cached_hash

    def __hash__(self):
        return self._cached_hash

    @property
    def variance(self) -> Variance:
        return Variance.COVARIANT


class FuncIn(BaseLabel):
    __slots__ = ("loc",)

    def __init__(self, loc):
        self.loc = loc
        super().__init__()

    def __repr__(self):
        return f"in<{self.loc}>"


class FuncOut(BaseLabel):
    __slots__ = ("loc",)

    def __init__(self, loc):
        self.loc = loc
        super().__init__()

    def __repr__(self):
        return f"out<{self.loc}>"


class Load(BaseLabel):
    __slots__ = ()

    def __repr__(self):
        return "load"


class Store(BaseLabel):
    __slots__ = ()

    def __repr__(self):
        return "store"

    @property
    def variance(self) -> Variance:
        return Variance.CONTRAVARIANT


class AddN(BaseLabel):
    __slots__ = ("n",)

    def __init__(self, n):
        self.n = n
        super().__init__()

    def __repr__(self):
        return f"+{self.n}"


class SubN(BaseLabel):
    __slots__ = ("n",)

    def __init__(self, n):
        self.n = n
        super().__init__()

    def __repr__(self):
        return f"-{self.n}"


class ConvertTo(BaseLabel):
    __slots__ = ("to_bits",)

    def __init__(self, to_bits):
        self.to_bits = to_bits
        super().__init__()

    def __repr__(self):
        return f"conv({self.to_bits})"


class ReinterpretAs(BaseLabel):
    __slots__ = (
        "to_bits",
        "to_type",
    )

    def __init__(self, to_type, to_bits):
        self.to_type = to_type
        self.to_bits = to_bits
        super().__init__()

    def __repr__(self):
        return f"reinterpret({self.to_type}{self.to_bits})"


class HasField(BaseLabel):
    __slots__ = (
        "bits",
        "offset",
    )

    def __init__(self, bits, offset):
        self.bits = bits
        self.offset = offset
        super().__init__()

    def __repr__(self):
        if self.bits == MAX_POINTSTO_BITS:
            return f"<MAX_POINTSTO_BITS>@{self.offset}"
        return f"<{self.bits} bits>@{self.offset}"


class IsArray(BaseLabel):
    def __repr__(self):
        return "is_array"


def new_dtv(
    type_var: TypeVariable,
    *,
    label: BaseLabel | None = None,
    labels: Sequence[BaseLabel] | None = None,
) -> TypeVariable | DerivedTypeVariable:
    """
    Create a new DerivedTypeVariable with the given type variable (or DerivedTypeVariable) and labels.
    """

    if label is None and labels is None:
        raise ValueError("Either label or labels must be specified")
    new_labels = (label,) if label is not None else tuple(labels)  # type: ignore[reportArgumentType]
    if isinstance(type_var, DerivedTypeVariable):
        base_typevar = type_var.type_var
        new_labels = type_var.labels + new_labels
    else:
        base_typevar = type_var

    # condense the last N labels if they are AddN and SubN
    off = 1
    while off <= len(new_labels) and isinstance(new_labels[-off], (AddN, SubN)):
        off += 1
    if off <= len(new_labels) and not isinstance(new_labels[-off], (AddN, SubN)):
        off -= 1

    if off >= 2:
        new_n = 0
        for lbl in new_labels[-off:]:
            if isinstance(lbl, AddN):
                new_n += lbl.n
            elif isinstance(lbl, SubN):
                new_n -= lbl.n
        new_labels = new_labels[:-off]
        if new_n > 0:
            new_labels += (AddN(new_n),)
        elif new_n < 0:
            new_labels += (SubN(-new_n),)

    return DerivedTypeVariable(base_typevar, None, labels=new_labels) if new_labels else base_typevar
