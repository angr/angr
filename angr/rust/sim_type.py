from typing import Optional, Dict, List, Union
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
        is_returnty_struct=False,
        is_class_member_function=False,
    ):
        """
        :param label:    The type label
        :param args:     A tuple of types representing the arguments to the function
        :param returnty: The return type of the function, or none for void
        :param variadic: Whether the function accepts varargs
        """
        super().__init__(args, returnty, label, arg_names, variadic)
        self.is_arg0_retbuf = is_returnty_struct
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
            is_returnty_struct=self.is_arg0_retbuf,
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

    def normalize(self) -> Optional["RustSimTypeFunction"]:
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
        return None

    def copy(self):
        return RustSimTypeFunction(
            self.args,
            self.returnty,
            label=self.label,
            arg_names=self.arg_names,
            variadic=self.variadic,
            is_returnty_struct=self.is_arg0_retbuf,
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

    @property
    def size(self):
        if not self.fields:
            return 0
        return super().size

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


class RustSimTypeVec(RustSimStruct, SimType):
    def __init__(self, label=None, arch=None):
        RustSimStruct.__init__(
            self,
            {
                "ptr": RustSimTypeReference(pts_to=RustSimTypeInt(size=8, signed=False)).with_arch(arch),
                "cap": RustSimTypeInt(size=64, signed=False).with_arch(arch),
                "len": RustSimTypeInt(size=64, signed=False).with_arch(arch),
            },
            name="Vec",
        )
        SimType.__init__(self, label)

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = RustSimTypeVec(label=self.label, arch=arch)
        out._arch = arch
        self._arch_memo[arch.name] = out

        return out

    def repr(self, name=None, full=0, memo=None, indent=0):
        if name is None or len(name) == 0:
            return self.__repr__()
        return f"{name}: {self.__repr__()}"

    def __repr__(self):
        return "Vec"


class RustSimTypeBottom(RustSimType, SimTypeBottom):
    pass


class EnumVariant:
    def __init__(self, name, discriminant, associated_data, discriminant_size):
        self.name = name
        self.discriminant = discriminant
        self.associated_data: OrderedDict[SimType, str] = associated_data
        self.discriminant_size = discriminant_size
        self._type = None

    @staticmethod
    def from_no_data(name, discriminant):
        return EnumVariant(name, discriminant, OrderedDict(), 0)

    @staticmethod
    def from_single_struct(name, discriminant, struct_type, discriminant_size):
        associated_data = OrderedDict([(struct_type, None)])
        return EnumVariant(name, discriminant, associated_data, discriminant_size)

    @property
    def has_associated_data(self):
        return len(self.associated_data) > 0

    @property
    def data_offset(self):
        if self.has_associated_data:
            first_type = list(self.associated_data.items())[0][0]
            if self.discriminant_size:
                return max(self.discriminant_size, first_type.alignment)
        return 0

    @property
    def size(self):
        return sum(ty.size for ty in self.associated_data.keys()) if len(self.associated_data) else 0

    @property
    def type(self):
        if not self._type:
            offset = 0
            fields = {}
            for ty in self.associated_data.keys():
                fields[f"field_{offset}"] = ty
                offset += ty.size
            self._type = RustSimStruct(fields, pack=True)
        return self._type

    def with_arch(self, arch):
        new_associated_data = OrderedDict([(ty.with_arch(arch), name) for ty, name in self.associated_data])
        return EnumVariant(self.name, self.discriminant, new_associated_data)

    def __eq__(self, other):
        return (
            type(self) is type(other)
            and self.name == other.name
            and self.discriminant == other.discriminant
            and self.associated_data == other.associated_data
        )

    def __hash__(self):
        return hash((self.name, self.discriminant, tuple(self.associated_data)))


class RustSimEnum(RustSimType, SimType):
    def __init__(self, variants: List[EnumVariant], discriminant_size=0):
        super().__init__()
        assert len(variants) > 0
        self.variants = variants
        self.discriminant_size = discriminant_size

        self._size = max(variant.size for variant in self.variants)

    def copy(self):
        return RustSimEnum(self.variants, self.discriminant_size).with_arch(self._arch)

    def _with_arch(self, arch):
        out = RustSimEnum([variant.with_arch(arch) for variant in self.variants], self.discriminant_size)
        return out

    def repr(self, name=None, full=0, memo=None, indent=0):
        return "Enum"

    def get_variant(self, discriminant) -> Optional[EnumVariant]:
        for variant in self.variants:
            if variant.discriminant == discriminant:
                return variant
        return None

    def num_variants(self):
        return len(self.variants)


class RustSimTypeOption(RustSimEnum):
    def __init__(self, data_type, none_discriminant, some_discriminant=None, discriminant_size=0):
        self.data_type = data_type
        self.none_discriminant = none_discriminant
        self.some_discriminant = some_discriminant

        variants = [
            EnumVariant.from_no_data("None", none_discriminant),
            EnumVariant.from_single_struct("Some", some_discriminant, data_type, discriminant_size),
        ]
        super().__init__(variants, discriminant_size=discriminant_size)

    def copy(self):
        return RustSimTypeOption(
            self.data_type, self.none_discriminant, self.some_discriminant, self.discriminant_size
        ).with_arch(self._arch)

    def _with_arch(self, arch):
        out = RustSimTypeOption(
            self.data_type.with_arch(arch),
            self.none_discriminant,
            self.some_discriminant,
            self.discriminant_size,
        )
        return out

    def repr(self, name=None, full=0, memo=None, indent=0):
        return f"Option<{self.data_type}>"


class RustSimTypeResult(RustSimEnum):
    def __init__(self, ok_type, err_type, ok_discriminant, err_discriminant, discriminant_size):
        self.ok_type = ok_type
        self.err_type = err_type
        self.ok_discriminant = ok_discriminant
        self.err_discriminant = err_discriminant

        variants = [
            EnumVariant.from_single_struct("Ok", ok_discriminant, ok_type, discriminant_size),
            EnumVariant.from_single_struct("Err", err_discriminant, err_type, discriminant_size),
        ]
        super().__init__(variants, discriminant_size=discriminant_size)

    def copy(self):
        return RustSimTypeResult(
            self.ok_type, self.err_type, self.ok_discriminant, self.err_discriminant, self.discriminant_size
        ).with_arch(self._arch)

    def _with_arch(self, arch):
        out = RustSimTypeResult(
            self.ok_type.with_arch(arch),
            self.err_type.with_arch(arch),
            self.ok_discriminant,
            self.err_discriminant,
            self.discriminant_size,
        )
        return out

    def repr(self, name=None, full=0, memo=None, indent=0):
        return f"Result<{self.ok_type}, {self.err_type}>"
