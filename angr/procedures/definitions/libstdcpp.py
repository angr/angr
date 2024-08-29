from __future__ import annotations
from ...sim_type import SimTypeFunction, SimTypePointer, SimTypeChar, SimTypeBottom
from .. import SIM_PROCEDURES as P
from . import SimCppLibrary


libstdcpp = SimCppLibrary()

libstdcpp.set_library_names('libstdc++.so', 'libstdc++.so.6')
libstdcpp.add_all_from_dict(P["libstdcpp"])


_decls = {
    "std::__throw_logic_error(char const*)": SimTypeFunction([SimTypePointer(SimTypeChar())], SimTypeBottom(label="void"), arg_names=("error",)),
    "std::__throw_length_error(char const*)": SimTypeFunction([SimTypePointer(SimTypeChar())], SimTypeBottom(label="void"), arg_names=("error",)),
}


for name, proto in _decls.items():
    if proto is not None:
        libstdcpp.set_prototype(name, proto)
