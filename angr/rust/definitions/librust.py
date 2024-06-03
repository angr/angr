from .structs import Arguments
from ..sim_type import (
    RustSimTypeFunction,
    RustSimTypeStr,
    RustSimTypeString,
    RustSimTypeInt,
    RustSimTypeReference,
    RustSimStruct,
    RustSimTypeArray,
    RustSimTypeSize,
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
        args=[RustSimTypeReference(Arguments)],
        returnty=None,
    ),
}

for name, prototype in prototypes.items():
    librust.set_prototype(name, prototype)
