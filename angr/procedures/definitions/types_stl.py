# pylint:disable=line-too-long
from __future__ import annotations
from collections import OrderedDict

from angr.procedures.definitions import SimTypeCollection
from angr.sim_type import SimCppClass, SimTypePointer, SimTypeChar, SimTypeInt

typelib = SimTypeCollection()
typelib.set_names("cpp::std")
typelib.types = {
    "std::string": SimCppClass(
        unique_name="std::string_gnu",
        name="std::string",
        members=OrderedDict(
            [
                ("m_data", SimTypePointer(SimTypeChar())),
                ("m_size", SimTypeInt(signed=False)),
                ("m_capacity", SimTypeInt(signed=False)),
            ]
        ),
    ),
}
