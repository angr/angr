from typing import Optional, Dict, Any, Tuple, List, Union

import claripy

from ....sim_type import SimType, SimTypeBottom, SimTypeArray


class RustSimType(SimType):
    def __init__(self, label=None):
        super().__init__()
        self.label = label

    def repr(self, name=None, full=0, memo=None, indent=0):
        raise NotImplementedError()

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        return self.repr(name, full, memo, indent)


class RustSimTypeReg(RustSimType):
    """
    SimTypeReg is the base type for all types that are register-sized.
    """

    _fields = ("size",)

    def __init__(self, size, label=None):
        """
        :param label: the type label.
        :param size: the size of the type (e.g. 32bit, 8bit, etc.).
        """
        SimType.__init__(self, label=label)
        self._size = size

    def __repr__(self):
        return f"reg{self.size}_t"

    def extract(self, state, addr, concrete=False):
        # TODO: EDG says this looks dangerously closed-minded. Just in case...
        assert self.size % state.arch.byte_width == 0

        out = state.memory.load(addr, self.size // state.arch.byte_width, endness=state.arch.memory_endness)
        if not concrete:
            return out
        return state.solver.eval(out)

    def store(self, state, addr, value):
        store_endness = state.arch.memory_endness
        try:
            value = value.ast
        except AttributeError:
            pass
        if isinstance(value, claripy.ast.Bits):  # pylint:disable=isinstance-second-argument-not-valid-type
            if value.size() != self.size:
                raise ValueError("size of expression is wrong size for type")
        elif isinstance(value, int):
            value = state.solver.BVV(value, self.size)
        elif isinstance(value, bytes):
            store_endness = "Iend_BE"
        else:
            raise TypeError(f"unrecognized expression type for SimType {type(self).__name__}")

        state.memory.store(addr, value, endness=store_endness)

    def copy(self):
        return self.__class__(self.size, label=self.label)


class RustSimTypeInt(RustSimTypeReg):
    def __init__(self, size, signed, label=None):
        super().__init__(size, label)
        self.signed = signed

    def repr(self, name=None, full=0, memo=None, indent=0):
        print(f"{name=}")
        if name is None or len(name) == 0:
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


class RustSimTypePointer(RustSimTypeReg):
    """
    SimTypePointer is a type that specifies a pointer to some other type.
    """

    _fields = tuple(x for x in RustSimTypeReg._fields if x != "size") + ("pts_to",)

    def __init__(self, pts_to, label=None, offset=0):
        """
        :param label:   The type label.
        :param pts_to:  The type to which this pointer points.
        """
        super().__init__(None, label=label)
        self.pts_to = pts_to
        self.signed = False
        self.offset = offset

    def __repr__(self):
        return f"{self.pts_to}*"

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        # if pts_to is SimTypeBottom, we return a void*
        if isinstance(self.pts_to, SimTypeBottom):
            out = "void*"
            if name is None:
                return out
            return f"{out} {name}"
        # if it points to an array, we do not need to add a *
        deref_chr = "*" if not isinstance(self.pts_to, SimTypeArray) else ""
        name_with_deref = deref_chr if name is None else f"{deref_chr}{name}"
        name_with_deref = None
        print(f"{name_with_deref=}")
        return self.pts_to.c_repr(name_with_deref, full, memo, indent)

    def make(self, pts_to):
        new = type(self)(pts_to)
        new._arch = self._arch
        return new

    @property
    def size(self):
        if self._arch is None:
            raise ValueError("Can't tell my size without an arch!")
        return self._arch.bits

    def _with_arch(self, arch):
        out = SimTypePointer(self.pts_to.with_arch(arch), self.label)
        out._arch = arch
        return out

    def _init_str(self):
        return "%s(%s%s, offset=%d)" % (
            self.__class__.__name__,
            self.pts_to._init_str(),
            (', label="%s"' % self.label) if self.label is not None else "",
            self.offset,
        )

    def copy(self):
        return SimTypePointer(self.pts_to, label=self.label, offset=self.offset)
