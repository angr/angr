from collections import OrderedDict

from ...rust.sim_type import (
    RustSimStruct,
    RustSimTypeReference,
    RustSimTypeSize,
    RustSimTypeStr,
    RustSimTypeBottom,
    RustSimTypeInt,
    RustSimTypeString,
    RustSimTypeOption,
)

PreDefinedStructs = {"String": RustSimTypeString(), "str": RustSimTypeStr()}


class ArrayReference(RustSimStruct):
    def __init__(self, ele_ty):
        name = f"&[{repr(ele_ty)}]"
        super().__init__(fields={"ptr": RustSimTypeReference(ele_ty), "len": RustSimTypeSize()}, name=name)
        PreDefinedStructs[name] = self
        self.ele_ty = ele_ty

    def copy(self):
        return ArrayReference(self.ele_ty).with_arch(self._arch)

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = ArrayReference(self.ele_ty)
        out._arch = arch
        out.fields = OrderedDict((k, v.with_arch(arch)) for k, v in self.fields.items())
        out.ele_ty = out.ele_ty.with_arch(arch)

        self._arch_memo[arch.name] = out

        return out


class StrSlice(RustSimStruct):
    def __init__(self):
        super().__init__(
            fields=OrderedDict((("ptr", RustSimTypeReference(RustSimTypeInt(8))), ("len", RustSimTypeSize()))),
            name="&str",
        )
        PreDefinedStructs["&str"] = self

    def copy(self):
        return StrSlice().with_arch(self._arch)

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = StrSlice()
        out._arch = arch
        out.fields = OrderedDict((k, v.with_arch(arch)) for k, v in self.fields.items())

        self._arch_memo[arch.name] = out

        return out


class SimpleMessage(RustSimStruct):
    def __init__(self):
        super().__init__(fields={"kind": RustSimTypeSize(), "message": StrSlice()}, name="SimpleMessage")

    def copy(self):
        return SimpleMessage().with_arch(self._arch)

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = SimpleMessage()
        out._arch = arch
        out.fields = OrderedDict((k, v.with_arch(arch)) for k, v in self.fields.items())

        self._arch_memo[arch.name] = out

        return out


Argument = RustSimStruct(
    name="Argument",
    fields=OrderedDict(
        (
            ("value", RustSimTypeReference(RustSimTypeBottom())),
            ("formatter", RustSimTypeReference(RustSimTypeBottom())),
        )
    ),
)

Arguments = RustSimStruct(
    name="Arguments",
    fields=OrderedDict(
        (
            ("pieces", ArrayReference(StrSlice())),
            ("fmt", RustSimTypeOption(0, 0, ArrayReference(RustSimTypeBottom()), None, 0)),
            ("args", ArrayReference(Argument)),
        )
    ),
)

Error = RustSimStruct(
    name="Error",
    fields={
        "kind": RustSimTypeSize(),
        "message": StrSlice(),
    },
)

ZeroSizeStruct = RustSimStruct(
    name="()",
    fields=OrderedDict(()),
    align=0,
)
