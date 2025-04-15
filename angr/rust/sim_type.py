from typing import Optional, Dict, List, Union, Tuple
from collections import OrderedDict

from ..analyses.typehoon.translator import SimTypeTempRef
from ..sim_type import (
    SimType,
    SimTypeBottom,
    SimTypeInt,
    SimTypeFunction,
    SimTypePointer,
    SimTypeArray,
    SimStruct,
    SimTypeNumOffset,
    SimTypeNum,
)


def is_composite_type(ty):
    return isinstance(ty, RustSimStruct) or isinstance(ty, RustSimEnum)


class RustSimType:
    def repr(self, name=None, full=0, memo=None, indent=0):
        raise NotImplementedError()

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        return self.repr(name, full, memo, indent)


class RustSimTypeInt(RustSimType, SimTypeInt):
    def __init__(self, size=32, signed=True, label=None):
        super().__init__(signed, label)
        self._size = size

    def repr(self, name=None, full=0, memo=None, indent=0):
        if name is None or len(name) == 0:
            return self.__repr__()
        return f"{name}: {self.__repr__()}"

    @property
    def size(self):
        return self._size

    def __repr__(self):
        name = "i" if self.signed else "u"
        name += str(self.size)
        return name


class RustSimTypeSize(RustSimTypeInt):
    def __init__(self, label=None):
        super().__init__(size=0, signed=False)

    @property
    def size(self):
        if self._arch is None:
            raise ValueError("Can't tell my size without an arch!")
        return self._arch.bits


class RustSimTypeFunction(RustSimType, SimTypeFunction):
    """
    SimTypeFunction is a type that specifies an actual function (i.e. not a pointer) with certain types of arguments and
    a certain return value.
    """

    args: List[RustSimType]
    returnty: Optional[RustSimType]

    base = False

    def __init__(
        self,
        args: List[RustSimType],
        returnty: Optional[RustSimType],
        label=None,
        arg_names=None,
        variadic=False,
        is_arg0_retbuf=False,
        is_class_member_function=False,
    ):
        """
        :param label:    The type label
        :param args:     A tuple of types representing the arguments to the function
        :param returnty: The return type of the function, or none for void
        :param variadic: Whether the function accepts varargs
        """
        super().__init__(args, returnty, label, arg_names, variadic)
        self.is_arg0_retbuf = is_arg0_retbuf
        self.is_class_member_function = is_class_member_function

    def __repr__(self):
        argstrs = [str(a) for a in self.args]
        if self.variadic:
            argstrs.append("...")
        returnty = self.returnty
        if self.is_arg0_retbuf:
            returnty = self.args[0]
            if isinstance(returnty, RustSimTypeReference):
                returnty = returnty.pts_to
            argstrs = argstrs[1:]
        return "({}) -> {}".format(", ".join(argstrs), returnty)

    def _repr(self, name=None, full=0, memo=None, indent=0):
        formatted_args = [
            a.c_repr(n, full - 1, memo, indent)
            for a, n in zip(self.args, self.arg_names if self.arg_names and full else (None,) * len(self.args))
        ]
        if self.variadic:
            formatted_args.append("...")
        proto = f"({name or ''})({', '.join(formatted_args)})"
        return f"void {proto}" if self.returnty is None else self.returnty.c_repr(proto, full, memo, indent)

    @property
    def size(self):
        return 4096  # ???????????

    def _with_arch(self, arch):
        out = RustSimTypeFunction(
            [a.with_arch(arch) for a in self.args],
            self.returnty.with_arch(arch) if self.returnty is not None else None,
            label=self.label,
            arg_names=self.arg_names,
            variadic=self.variadic,
            is_arg0_retbuf=self.is_arg0_retbuf,
            is_class_member_function=self.is_class_member_function,
        )
        out._arch = arch
        return out

    def _arg_names_str(self, show_variadic=True):
        argnames = list(self.arg_names)
        if self.variadic and show_variadic:
            argnames.append("...")
        return ", ".join('"%s"' % arg_name for arg_name in argnames)

    def _init_str(self):
        return "{}([{}], {}{}{}{})".format(
            self.__class__.__name__,
            ", ".join([arg._init_str() for arg in self.args]),
            self.returnty._init_str(),
            (', label="%s"' % self.label) if self.label else "",
            (", arg_names=[%s]" % self._arg_names_str(show_variadic=False)) if self.arg_names else "",
            ", variadic=True" if self.variadic else "",
        )

    def normalize(self):
        if (
            self.is_arg0_retbuf
            and self.args
            and isinstance(self.args[0], RustSimTypeReference)
            and is_composite_type(self.args[0].pts_to)
        ):
            prototype = self.copy()
            prototype.returnty = self.args[0].pts_to
            prototype.args = self.args[1:]
            prototype.is_arg0_retbuf = False
            return prototype
        return self

    def copy(self):
        return RustSimTypeFunction(
            self.args,
            self.returnty,
            label=self.label,
            arg_names=self.arg_names,
            variadic=self.variadic,
            is_arg0_retbuf=self.is_arg0_retbuf,
            is_class_member_function=self.is_class_member_function,
        )


class RustSimTypeReference(RustSimType, SimTypePointer):
    """
    SimTypePointer is a type that specifies a pointer to some other type.
    """

    def __init__(self, pts_to, label=None, offset=0):
        """
        :param label:   The type label.
        :param pts_to:  The type to which this pointer points.
        """
        super().__init__(pts_to, label, offset)

    def __repr__(self):
        return f"&{self.pts_to}"

    def repr(self, name=None, full=0, memo=None, indent=0):
        # if pts_to is SimTypeBottom, we return a void*
        if isinstance(self.pts_to, SimTypeBottom):
            out = "void*"
            if name is None:
                return out
            return f"{out} {name}"
        # if it points to an array, we do not need to add a *
        out = "&" + self.pts_to.c_repr(None, full, memo, indent)
        if name is None:
            return out
        return f"{name}: {out}"

    @property
    def size(self):
        if self._arch is None:
            raise ValueError("Can't tell my size without an arch!")
        # Normally the size of a reference type is arch.bits
        # But if it's a reference to an array type, then the size will be arch.bits * 2
        if isinstance(self.pts_to, RustSimTypeArray) or isinstance(self.pts_to, RustSimTypeStr):
            return self._arch.bits * 2
        return self._arch.bits

    def _with_arch(self, arch):
        out = RustSimTypeReference(self.pts_to.with_arch(arch), self.label)
        out._arch = arch
        return out

    def copy(self):
        return RustSimTypeReference(self.pts_to, label=self.label, offset=self.offset).with_arch(self._arch)


class RustSimTypeArray(RustSimType, SimTypeArray):
    """
    SimTypeArray is a type that specifies a series of data laid out in sequence.
    """

    _fields = ("elem_type", "length")

    def __init__(self, elem_type, length=None, label=None):
        """
        :param label:       The type label.
        :param elem_type:   The type of each element in the array.
        :param length:      An expression of the length of the array, if known.
        """
        super().__init__(elem_type, length, label)

    def __repr__(self):
        return "[{}{}]".format(self.elem_type, "" if self.length is None else f"; {self.length}")

    def repr(self, name=None, full=0, memo=None, indent=0):
        if name is None:
            return repr(self)

        return f"{name}: {repr(self)}"

    def _with_arch(self, arch):
        out = RustSimTypeArray(self.elem_type.with_arch(arch), self.length, self.label)
        out._arch = arch
        return out

    def copy(self):
        return RustSimTypeArray(self.elem_type, length=self.length, label=self.label)


class RustSimStruct(RustSimType, SimStruct):
    _fields = ("name", "fields")

    def __init__(self, fields: Union[Dict[str, SimType], OrderedDict], name=None, pack=False, align=None):
        SimStruct.__init__(self, fields, name, pack, align)

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = RustSimStruct(OrderedDict(), name=self.name, pack=self._pack, align=self._align)
        out._arch = arch
        self._arch_memo[arch.name] = out

        out.fields = OrderedDict((k, v.with_arch(arch)) for k, v in self.fields.items())

        # Fixup the offsets to byte aligned addresses for all SimTypeNumOffset types
        offset_so_far = 0
        for name, ty in out.fields.items():
            if isinstance(ty, RustSimTypeNumOffset):
                out._pack = True
                ty.offset = offset_so_far % arch.byte_width
                offset_so_far += ty.size
        return out

    @property
    def size(self):
        if not self.fields:
            return 0
        size = super().size
        if size % self.alignment != 0:
            size += self.alignment - (size % self.alignment)
        return size

    def repr(self, name=None, full=0, memo=None, indent=0):
        if not full or (memo is not None and self in memo):
            if name is None:
                return repr(self)
            else:
                return f"{name}: {repr(self)}"

        indented = " " * indent if indent is not None else ""
        new_indent = indent + 4 if indent is not None else None
        new_indented = " " * new_indent if indent is not None else ""
        newline = "\n" if indent is not None else " "
        new_memo = (self,) + (memo if memo is not None else ())
        members = newline.join(
            new_indented + v.c_repr(k, full - 1, new_memo, new_indent) + ";" for k, v in self.fields.items()
        )
        return "struct {} {{{}{}{}{}}}{}".format(
            self.name, newline, members, newline, indented, "" if name is None else " " + name
        )

    def __repr__(self):
        return self.name

    def copy(self):
        return RustSimStruct(dict(self.fields), name=self.name, pack=self._pack, align=self._align)

    def match(self, field_exprs, **kwargs) -> bool:
        return False


class RustSimTypeNumOffset(RustSimType, SimTypeNumOffset):
    """
    like SimTypeNum, but supports an offset of 1 to 7 to a byte aligned address to allow structs with bitfields
    """

    _fields = SimTypeNum._fields + ("offset",)

    def __init__(self, size, signed=True, label=None, offset=0):
        super().__init__(size, signed, label, offset)

    def repr(self, name=None, full=0, memo=None, indent=0):
        super(SimTypeNumOffset, self).c_repr(name, full, memo, indent)


class RustSimTypeTempRef(RustSimType, SimTypeTempRef):
    def __init__(self, typevar):
        super().__init__(typevar)

    def repr(self, name=None, full=0, memo=None, indent=0):
        return "<RustSimTypeTempRef>"


class RustSimTypeStr(RustSimStruct, SimType):
    def __init__(self, label=None, arch=None):
        RustSimStruct.__init__(
            self,
            {
                "ptr": RustSimTypeReference(pts_to=RustSimTypeInt(size=8, signed=False).with_arch(arch)).with_arch(
                    arch
                ),
                "len": RustSimTypeInt(size=64, signed=False).with_arch(arch),
            },
            name="str",
        )
        SimType.__init__(self, label)

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = RustSimTypeStr(label=self.label, arch=arch)
        out._arch = arch
        self._arch_memo[arch.name] = out

        return out

    def repr(self, name=None, full=0, memo=None, indent=0):
        if name is None or len(name) == 0:
            return self.__repr__()
        return f"{name}: {self.__repr__()}"

    def copy(self):
        return RustSimTypeStr(self.label).with_arch(self._arch)

    @property
    def size(self):
        return self._arch.bits * 2

    def __repr__(self):
        return "str"


class RustSimTypeString(RustSimStruct, SimType):
    def __init__(self, label=None, arch=None):
        RustSimStruct.__init__(
            self,
            {
                "ptr": RustSimTypeReference(pts_to=RustSimTypeInt(size=8, signed=False)).with_arch(arch),
                "cap": RustSimTypeInt(size=64, signed=False).with_arch(arch),
                "len": RustSimTypeInt(size=64, signed=False).with_arch(arch),
            },
            name="String",
        )
        SimType.__init__(self, label)

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = RustSimTypeString(label=self.label, arch=arch)
        out._arch = arch
        self._arch_memo[arch.name] = out

        return out

    def copy(self):
        return RustSimTypeString(self.label).with_arch(self._arch)

    def repr(self, name=None, full=0, memo=None, indent=0):
        if name is None or len(name) == 0:
            return self.__repr__()
        return f"{name}: {self.__repr__()}"

    def __repr__(self):
        return "String"


DEFAULT_VEC_FIELDS_ORDER = ("cap", "ptr", "len")


class RustSimTypeVec(RustSimStruct, SimType):
    def __init__(self, element_type, order=DEFAULT_VEC_FIELDS_ORDER, label=None, arch=None):
        unordered_fields = {
            "ptr": RustSimTypeReference(pts_to=element_type).with_arch(arch),
            "cap": RustSimTypeSize().with_arch(arch),
            "len": RustSimTypeSize().with_arch(arch),
        }
        fields = OrderedDict()
        for field_name in order:
            fields[field_name] = unordered_fields[field_name]
        RustSimStruct.__init__(
            self,
            fields,
            name=f"Vec<{repr(element_type)}>",
        )
        SimType.__init__(self, label)
        self.element_type = element_type
        self.order = order

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = RustSimTypeVec(self.element_type, self.order, label=self.label, arch=arch)
        out._arch = arch
        self._arch_memo[arch.name] = out

        return out

    def repr(self, name=None, full=0, memo=None, indent=0):
        if name is None or len(name) == 0:
            return self.__repr__()
        return f"{name}: {self.__repr__()}"

    def __repr__(self):
        return self.name


class RustSimTypeBottom(RustSimType, SimTypeBottom):
    pass


class EnumVariant:
    def __init__(self, name, fields, discriminant, discriminant_size):
        self.name = name
        self.fields: List[Tuple[SimType, Optional[str]]] = fields
        self.discriminant = discriminant
        self.discriminant_size = discriminant_size

        self._arch = None

    @staticmethod
    def from_no_data(name, discriminant, discriminant_size):
        return EnumVariant(name, (), discriminant, discriminant_size)

    @staticmethod
    def from_single_field_ty(name, field_ty, discriminant, discriminant_size):
        return EnumVariant(name, [(field_ty, None)], discriminant, discriminant_size)

    def has_fields(self):
        return len(self.fields) > 0

    @property
    def first_field_offset(self):
        if self.has_fields():
            field_ty = self.fields[0][0]
            if self.discriminant_size:
                return max(self.discriminant_size, field_ty.alignment)
        return 0

    @property
    def field_offsets(self):
        struct_ty = self.type
        offsets = {}
        first_field_offset = self.first_field_offset
        for field_name, offset in struct_ty.offsets.items():
            field_ty = struct_ty.fields[field_name]
            offsets[offset + first_field_offset] = field_ty
        return offsets

    @property
    def bits(self):
        return self.type.size + self.first_field_offset * 8

    @property
    def size(self):
        return self.bits // 8

    @property
    def type(self):
        fields = OrderedDict()
        for idx, (field_ty, name) in enumerate(self.fields):
            fields[name or f"field_{idx}"] = field_ty
        result = RustSimStruct(fields, pack=True)
        if self._arch:
            return result.with_arch(self._arch)
        return result

    def with_arch(self, arch):
        fields = [(field_ty.with_arch(arch), name) for field_ty, name in self.fields]
        result = EnumVariant(self.name, fields, self.discriminant, self.discriminant_size)
        result._arch = arch
        return result

    def __eq__(self, other):
        return (
            type(self) is type(other)
            and self.name == other.name
            and self.fields == other.fields
            and self.discriminant == other.discriminant
            and self.discriminant_size == other.discriminant_size
        )

    def __hash__(self):
        return hash((self.name, tuple(self.fields), self.discriminant, self.discriminant_size))

    def __repr__(self):
        return f"{self.name}(...)"


class RustSimEnum(RustSimType, SimType):
    def __init__(self, name, variants: List[EnumVariant]):
        super().__init__()
        self.name = name
        self.variants = variants

    @property
    def size(self) -> int:
        return max(variant.bits for variant in self.variants)

    def copy(self):
        return RustSimEnum(self.name, self.variants).with_arch(self._arch)

    def _with_arch(self, arch):
        out = RustSimEnum(self.name, [variant.with_arch(arch) for variant in self.variants])
        out._arch = arch
        return out

    def repr(self, name=None, full=0, memo=None, indent=0):
        return f"enum {self.name}"

    def get_variant(self, discriminant) -> Optional[EnumVariant]:
        for variant in self.variants:
            if variant.discriminant == discriminant:
                return variant
        return None

    def num_variants(self):
        return len(self.variants)


class RustSimTypeOption(RustSimEnum):
    def __init__(self, none_discriminant, none_discriminant_size, some_type, some_discriminant, some_discriminant_size):
        self.none_discriminant = none_discriminant
        self.none_discriminant_size = none_discriminant_size
        self.some_type = some_type
        self.some_discriminant = some_discriminant
        self.some_discriminant_size = some_discriminant_size

        name = f"Option<{self.some_type}>"
        variants = [
            EnumVariant.from_no_data("None", none_discriminant, none_discriminant_size),
            EnumVariant.from_single_field_ty("Some", some_type, some_discriminant, some_discriminant_size),
        ]
        super().__init__(name, variants)

    def copy(self):
        return RustSimTypeOption(
            self.none_discriminant,
            self.none_discriminant_size,
            self.some_type,
            self.some_discriminant,
            self.some_discriminant_size,
        ).with_arch(self._arch)

    def _with_arch(self, arch):
        out = RustSimTypeOption(
            self.none_discriminant,
            self.none_discriminant_size,
            self.some_type.with_arch(arch),
            self.some_discriminant,
            self.some_discriminant_size,
        )
        out._arch = arch
        out.variants = [variant.with_arch(arch) for variant in out.variants]
        return out

    def repr(self, name=None, full=0, memo=None, indent=0):
        return self.name

    def __repr__(self):
        return self.repr()


class RustSimTypeResult(RustSimEnum):
    def __init__(
        self, ok_type, ok_discriminant, ok_discriminant_size, err_type, err_discriminant, err_discriminant_size
    ):
        self.ok_type = ok_type
        self.ok_discriminant = ok_discriminant
        self.ok_discriminant_size = ok_discriminant_size
        self.err_type = err_type
        self.err_discriminant = err_discriminant
        self.err_discriminant_size = err_discriminant_size

        name = f"Result<{self.ok_type}, {self.err_type}>"
        variants = [
            EnumVariant.from_single_field_ty("Ok", ok_type, ok_discriminant, ok_discriminant_size),
            EnumVariant.from_single_field_ty("Err", err_type, err_discriminant, err_discriminant_size),
        ]
        super().__init__(name, variants)

    def copy(self):
        return RustSimTypeResult(
            self.ok_type,
            self.ok_discriminant,
            self.ok_discriminant_size,
            self.err_type,
            self.err_discriminant,
            self.err_discriminant_size,
        ).with_arch(self._arch)

    def _with_arch(self, arch):
        out = RustSimTypeResult(
            self.ok_type.with_arch(arch),
            self.ok_discriminant,
            self.ok_discriminant_size,
            self.err_type.with_arch(arch),
            self.err_discriminant,
            self.err_discriminant_size,
        )
        out._arch = arch
        out.variants = [variant.with_arch(arch) for variant in out.variants]
        return out

    def repr(self, name=None, full=0, memo=None, indent=0):
        return self.name

    def __repr__(self):
        return self.repr()
