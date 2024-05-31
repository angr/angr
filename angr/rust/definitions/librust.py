from ..sim_type import (
    RustSimTypeFunction,
    RustSimTypeStr,
    RustSimTypeString,
    RustSimTypeInt,
    RustSimTypeReference,
    RustSimStruct,
    RustSimTypeArray,
)
from ...procedures.definitions import SimLibrary

librust = SimLibrary()
librust.set_library_names("librust")

prototypes = {
    "String::from": RustSimTypeFunction(
        args=[RustSimTypeReference(RustSimTypeStr())],
        returnty=RustSimTypeString(),
    ),
    "std::io::stdio::_print": RustSimTypeFunction(
        args=[
            RustSimTypeReference(
                RustSimStruct(
                    name="Arguments",
                    fields={
                        "pieces": RustSimTypeReference(RustSimTypeArray(RustSimTypeReference(RustSimTypeStr()))),
                        "fmt": RustSimTypeInt(),
                        "pieces2": RustSimTypeReference(RustSimTypeArray(RustSimTypeReference(RustSimTypeStr()))),
                    },
                )
            )
        ],
        returnty=None,
    ),
}

for name, prototype in prototypes.items():
    librust.set_prototype(name, prototype)
