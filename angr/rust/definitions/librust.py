from ..sim_type import RustSimTypeFunction, RustSimTypeStr, RustSimTypeString
from ...procedures.definitions import SimLibrary

librust = SimLibrary()
librust.set_library_names("librust")

prototypes = {
    "String::from": RustSimTypeFunction(
        args=[RustSimTypeStr()],
        returnty=RustSimTypeString(),
    ),
    "std::io::stdio::_print": RustSimTypeFunction(
        args=[RustSimTypeStr()],
        returnty=None,
    ),
}

for name, prototype in prototypes.items():
    librust.set_prototype(name, prototype)
