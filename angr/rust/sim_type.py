from typing import Optional, Dict, Any, Tuple, List, Union
from collections import OrderedDict

import claripy

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


class RustSimTypeFunction(RustSimType, SimTypeFunction):
    """
    SimTypeFunction is a type that specifies an actual function (i.e. not a pointer) with certain types of arguments and
    a certain return value.
    """

    args: List[RustSimType]
    returnty: Optional[RustSimType]

    base = False

    def __init__(
        self, args: List[RustSimType], returnty: Optional[RustSimType], label=None, arg_names=None, variadic=False
    ):
        """
        :param label:    The type label
        :param args:     A tuple of types representing the arguments to the function
        :param returnty: The return type of the function, or none for void
        :param variadic: Whether the function accepts varargs
        """
        super().__init__(args, returnty, label, arg_names, variadic)

    def __repr__(self):
        argstrs = [str(a) for a in self.args]
        if self.variadic:
            argstrs.append("...")
        return "({}) -> {}".format(", ".join(argstrs), self.returnty)

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

    def copy(self):
        return RustSimTypeFunction(
            self.args, self.returnty, label=self.label, arg_names=self.arg_names, variadic=self.variadic
        )


class RustSimTypePointer(RustSimType, SimTypePointer):
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

    def _with_arch(self, arch):
        out = RustSimTypePointer(self.pts_to.with_arch(arch), self.label)
        out._arch = arch
        return out

    def copy(self):
        return RustSimTypePointer(self.pts_to, label=self.label, offset=self.offset).with_arch(self._arch)


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

    def repr(self, name=None, full=0, memo=None, indent=0):
        if name is None:
            return repr(self)

        name = "{}[{}]".format(name, self.length if self.length is not None else "")
        return self.elem_type.c_repr(name, full, memo, indent)

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

        out = RustSimStruct(None, name=self.name, pack=self._pack, align=self._align)
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
                "ptr": RustSimTypePointer(pts_to=RustSimTypeInt(size=8, signed=False).with_arch(arch)).with_arch(arch),
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
                "ptr": RustSimTypePointer(pts_to=RustSimTypeInt(size=8, signed=False).with_arch(arch)).with_arch(arch),
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
                "ptr": RustSimTypePointer(pts_to=RustSimTypeInt(size=8, signed=False).with_arch(arch)).with_arch(arch),
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
