from ...rust.sim_type import (
    RustSimStruct,
    RustSimTypeReference,
    RustSimTypeSize,
    RustSimTypeArray,
    RustSimTypeStr,
    RustSimTypeBottom,
)

Option = RustSimStruct(name="Option", fields={"is_some": RustSimTypeSize(), "value": RustSimTypeSize()})

Argument = RustSimStruct(
    name="Argument",
    fields={"value": RustSimTypeReference(RustSimTypeBottom()), "formatter": RustSimTypeReference(RustSimTypeBottom())},
)

Arguments = RustSimStruct(
    name="Arguments",
    fields={
        "pieces": RustSimTypeReference(RustSimTypeArray(RustSimTypeReference(RustSimTypeStr()))),
        "args": RustSimTypeReference(RustSimTypeArray(RustSimTypeReference(Argument))),
        "fmt": Option,
    },
)
