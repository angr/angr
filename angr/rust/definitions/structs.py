from collections import OrderedDict

from ...rust.sim_type import (
    RustSimStruct,
    RustSimTypeReference,
    RustSimTypeSize,
    RustSimTypeArray,
    RustSimTypeStr,
    RustSimTypeBottom,
    RustSimTypeInt,
    RustSimTypeString,
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


class StrReference(RustSimStruct):
    def __init__(self):
        super().__init__(fields={"ptr": RustSimTypeReference(RustSimTypeInt(8)), "len": RustSimTypeSize()}, name="&str")
        PreDefinedStructs["&str"] = self

    def copy(self):
        return StrReference().with_arch(self._arch)

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = StrReference()
        out._arch = arch
        out.fields = OrderedDict((k, v.with_arch(arch)) for k, v in self.fields.items())

        self._arch_memo[arch.name] = out

        return out


class Option(RustSimStruct):
    def __init__(self, T, overlapping_discriminant=False):
        name = f"Option<{repr(T)}>"
        super().__init__(fields={"discriminant": RustSimTypeSize(), "value": T}, name=f"Option<{repr(T)}>")
        PreDefinedStructs[name] = self
        self.T = T
        self.overlapping_discriminant = overlapping_discriminant

    def copy(self):
        return Option(self.T, overlapping_discriminant=self.overlapping_discriminant).with_arch(self._arch)

    @property
    def offsets(self):
        if self.overlapping_discriminant:
            return {"value": 0}
        return {"discriminant": 0, "value": self._arch.bytes}

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = Option(self.T, overlapping_discriminant=self.overlapping_discriminant)
        out._arch = arch
        out.fields = OrderedDict((k, v.with_arch(arch)) for k, v in self.fields.items())

        self._arch_memo[arch.name] = out

        return out


Argument = RustSimStruct(
    name="Argument",
    fields={"value": RustSimTypeReference(RustSimTypeBottom()), "formatter": RustSimTypeReference(RustSimTypeBottom())},
)

Arguments = RustSimStruct(
    name="Arguments",
    fields={
        "pieces": ArrayReference(StrReference()),
        "args": ArrayReference(Argument),
        "fmt": Option(RustSimTypeInt(64)),
    },
)
