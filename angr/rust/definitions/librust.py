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
    "Vec::with_capacity": RustSimTypeFunction(
        args=[RustSimTypeSize()],
        returnty=RustSimTypeString(),
    ),
    "std::io::stdio::_print": RustSimTypeFunction(
        args=[RustSimTypeReference(Arguments)],
        returnty=None,
    ),
    "std::env::args": RustSimTypeFunction(
        args=[RustSimTypeReference(RustSimTypeInt(64))], returnty=None, is_returnty_struct=True
    ),
}

for name, prototype in prototypes.items():
    librust.set_prototype(name, prototype)
