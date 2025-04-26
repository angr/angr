from .structs import ZeroSizeStruct
from ..sim_type import (
    RustSimTypeFunction,
    RustSimTypeStr,
    RustSimTypeString,
    RustSimTypeInt,
    RustSimTypeReference,
    RustSimTypeSize,
    RustSimTypeBottom,
    RustSimTypeResult,
    RustSimTypeSlice,
)
from ..definitions import structs as default_structs


def generate_known_rust_prototypes(project):
    known_structs = project.kb.known_structs
    Arguments = known_structs["Arguments"] or default_structs.Arguments
    return {
        "String::from": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeString()), RustSimTypeReference(RustSimTypeStr())],
            returnty=None,
            is_arg0_retbuf=True,
        ),
        "String::new": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeString())],
            returnty=None,
            is_arg0_retbuf=True,
        ),
        "Vec::with_capacity": RustSimTypeFunction(
            args=[RustSimTypeSize()],
            returnty=RustSimTypeString(),
        ),
        "std::io::stdio::_print": RustSimTypeFunction(
            args=[RustSimTypeReference(Arguments)],
            returnty=None,
        ),
        "core::panicking::panic_fmt": RustSimTypeFunction(
            args=[RustSimTypeReference(Arguments)],
            returnty=None,
        ),
        "alloc::fmt::format::format_inner": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeString()), RustSimTypeReference(Arguments)],
            returnty=None,
            is_arg0_retbuf=True,
        ),
        "alloc::fmt::format": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeString()), RustSimTypeReference(Arguments)],
            returnty=None,
            is_arg0_retbuf=True,
        ),
        "std::io::stdio::_eprint": RustSimTypeFunction(
            args=[RustSimTypeReference(Arguments)],
            returnty=None,
        ),
        "std::env::args": RustSimTypeFunction(
            args=[RustSimTypeReference(Arguments)], returnty=None, is_arg0_retbuf=True
        ),
        "std::env::Args::len": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeInt(64))], returnty=RustSimTypeSize(), is_class_member_function=True
        ),
        "std::env::Args::next": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeInt(64)), RustSimTypeReference(RustSimTypeInt(64))],
            returnty=RustSimTypeSize(),
            is_arg0_retbuf=True,
            is_class_member_function=True,
        ),
        "core::result::unwrap": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeInt(64))], returnty=None, is_class_member_function=True
        ),
        "core::option::unwrap": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeInt(64))], returnty=None, is_class_member_function=True
        ),
        "std::io::Write::write_all": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeBottom()), RustSimTypeSlice(RustSimTypeInt(8))],
            returnty=RustSimTypeResult(
                ZeroSizeStruct, 0, project.arch.bytes, RustSimTypeReference(RustSimTypeBottom()), None, 0
            ),
        ),
        "std::io::Read::read_to_string": RustSimTypeFunction(
            args=[RustSimTypeReference(RustSimTypeBottom()), RustSimTypeReference(RustSimTypeString())],
            returnty=RustSimTypeResult(
                RustSimTypeSize().with_arch(project.arch),
                0,
                project.arch.bytes,
                RustSimTypeReference(RustSimTypeBottom()),
                None,
                0,
            ),
        ),
    }
