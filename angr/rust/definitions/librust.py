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
        args=[RustSimTypeReference(RustSimTypeString()), RustSimTypeReference(RustSimTypeStr())],
        returnty=None,
        is_returnty_struct=True,
    ),
    "Vec::with_capacity": RustSimTypeFunction(
        args=[RustSimTypeSize()],
        returnty=RustSimTypeString(),
    ),
    "std::io::stdio::_print": RustSimTypeFunction(
        args=[RustSimTypeReference(Arguments)],
        returnty=None,
    ),
    "alloc::fmt::format::format_inner": RustSimTypeFunction(
        args=[RustSimTypeReference(RustSimTypeString()), RustSimTypeReference(Arguments)],
        returnty=None,
        is_returnty_struct=True,
    ),
    "std::io::stdio::_eprint": RustSimTypeFunction(
        args=[RustSimTypeReference(Arguments)],
        returnty=None,
    ),
    "std::env::args": RustSimTypeFunction(
        args=[RustSimTypeReference(Arguments)], returnty=None, is_returnty_struct=True
    ),
    "std::env::Args::len": RustSimTypeFunction(
        args=[RustSimTypeReference(RustSimTypeInt(64))], returnty=RustSimTypeSize(), is_class_member_function=True
    ),
    "std::env::Args::next": RustSimTypeFunction(
        args=[RustSimTypeReference(RustSimTypeInt(64)), RustSimTypeReference(RustSimTypeInt(64))],
        returnty=RustSimTypeSize(),
        is_returnty_struct=True,
        is_class_member_function=True,
    ),
    "core::result::unwrap": RustSimTypeFunction(
        args=[RustSimTypeReference(RustSimTypeInt(64))], returnty=None, is_class_member_function=True
    ),
}

for name, prototype in prototypes.items():
    librust.set_prototype(name, prototype)
