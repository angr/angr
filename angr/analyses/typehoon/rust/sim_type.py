from typing import Optional, Dict, Any, Tuple, List, Union

import claripy

from ....sim_type import SimType, SimTypeBottom, SimTypeInt, SimTypeFunction, SimTypePointer


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
        return f"let {name}: {self.__repr__()}"

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

    _fields = ("args", "returnty")
    base = False

    def __init__(self, args: List[SimType], returnty: Optional[SimType], label=None, arg_names=None, variadic=False):
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
        return f"{self.pts_to}*"

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
        return RustSimTypePointer(self.pts_to, label=self.label, offset=self.offset)
