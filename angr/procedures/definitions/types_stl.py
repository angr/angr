# pylint:disable=line-too-long
from __future__ import annotations

from collections import OrderedDict

from angr.procedures.definitions import SimTypeCollection
from angr.sim_type import SimCppClass, SimTypeChar, SimTypeInt, SimTypeLongLong, SimTypePointer, SimTypeShort

typelib = SimTypeCollection()
typelib.set_names("cpp::std")
typelib.types = {
    "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>": SimCppClass(
        unique_name="class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>",
        name="std::string",
        members=OrderedDict(
            [
                ("m_data", SimTypePointer(SimTypeChar())),
                ("m_size", SimTypeInt(signed=False)),
                ("m_capacity", SimTypeInt(signed=False)),
            ]
        ),
    ),
    "class std::vector<int, class std::allocator<int>>": SimCppClass(
        unique_name="class std::vector<int, class std::allocator<int>>",
        name="std::vector<int>",
        members=OrderedDict(
            [
                ("m_start", SimTypePointer(SimTypeInt())),
                ("m_finish", SimTypePointer(SimTypeInt())),
                ("m_end_of_storage", SimTypePointer(SimTypeInt())),
            ]
        ),
    ),
    "class std::vector<short, class std::allocator<short>>": SimCppClass(
        unique_name="class std::vector<short, class std::allocator<short>>",
        name="std::vector<short>",
        members=OrderedDict(
            [
                ("m_start", SimTypePointer(SimTypeShort())),
                ("m_finish", SimTypePointer(SimTypeShort())),
                ("m_end_of_storage", SimTypePointer(SimTypeShort())),
            ]
        ),
    ),
    "class std::vector<long long, class std::allocator<long long>>": SimCppClass(
        unique_name="class std::vector<long long, class std::allocator<long long>>",
        name="std::vector<long long>",
        members=OrderedDict(
            [
                ("m_start", SimTypePointer(SimTypeLongLong())),
                ("m_finish", SimTypePointer(SimTypeLongLong())),
                ("m_end_of_storage", SimTypePointer(SimTypeLongLong())),
            ]
        ),
    ),
}
