from collections import OrderedDict

from sympy import discriminant

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


Argument = RustSimStruct(
    name="Argument",
    fields={"value": RustSimTypeReference(RustSimTypeBottom()), "formatter": RustSimTypeReference(RustSimTypeBottom())},
)

# Arguments = RustSimStruct(
#     name="Arguments",
#     fields={
#         "pieces": ArrayReference(StrReference()),
#         "args": ArrayReference(Argument),
#         "fmt": RustSimTypeOption(RustSimTypeInt(64), none_discriminant=None),
#     },
# )

Arguments = RustSimStruct(
    name="Arguments",
    fields={
        "pieces": ArrayReference(StrReference()),
        "fmt": RustSimTypeOption(RustSimTypeInt(128), none_discriminant=None),
        "args": ArrayReference(Argument),
    },
)
