
from .. import SIM_PROCEDURES as P
from . import SimCppLibrary


libstdcpp = SimCppLibrary()

libstdcpp.set_library_names('libstdc++.so', 'libstdc++.so.6')
libstdcpp.add_all_from_dict(P["libstdcpp"])
