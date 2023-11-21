from typing import Optional, Dict, Any, Tuple, List, Union

from ....sim_type import SimType, SimTypeReg


class RustSimType(SimType):
    def __init__(self, label=None):
        super().__init__()
        self.label = label

    def repr(self, name=None, full=0, memo=None, indent=0):
        raise NotImplementedError()

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        return self.repr(name, full, memo, indent)


class RustSimTypeInt(SimTypeReg):
    def __init__(self, size, signed, label=None):
        super().__init__(size, label)
        self.signed = signed

    def repr(self, name=None, full=0, memo=None, indent=0):
        if name is None:
            return self.__repr__()
        return f"let {name}: {self.__repr__()}"

    def __repr__(self):
        name = "i" if self.signed else "u"
        name += str(self.size)
        return name


class RustSimTypeFunction(RustSimType):
    """
    SimTypeFunction is a type that specifies an actual function (i.e. not a pointer) with certain types of arguments and
    a certain return value.
    """

    _fields = ("args", "returnty")
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
        super().__init__(label=label)
        self.args: List[RustSimType] = args
        self.returnty: Optional[RustSimType] = returnty
        self.arg_names = arg_names if arg_names else ()
        self.variadic = variadic

    def __repr__(self):
        argstrs = [str(a) for a in self.args]
        if self.variadic:
            argstrs.append("...")
        return "({}) -> {}".format(", ".join(argstrs), self.returnty)

    def c_repr(self, name=None, full=0, memo=None, indent=0):
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
