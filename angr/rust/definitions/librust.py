from ..sim_type import RustSimTypeFunction, RustSimTypeStr, RustSimTypeString, RustSimTypeInt, RustSimTypePointer
from ...procedures.definitions import SimLibrary

librust = SimLibrary()
librust.set_library_names("librust")

prototypes = {
    "String::from": RustSimTypeFunction(
        args=[RustSimTypePointer(RustSimTypeStr())],
        returnty=RustSimTypeString(),
    ),
    "std::io::stdio::_print": RustSimTypeFunction(
        args=[RustSimTypeInt()],
        returnty=None,
    ),
}

for name, prototype in prototypes.items():
    librust.set_prototype(name, prototype)
