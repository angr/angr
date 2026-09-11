"""Named accessors for fields of the C++ STL classes registered in the
``cpp::std`` :class:`SimTypeCollection`.

The KnownPattern machinery (see :mod:`angr.analyses.decompiler.known_patterns`)
recognizes inlined STL idioms *structurally*, before variable recovery, and
outlines them into calls such as ``std::string::length(s)``. That approach has a
hard floor: the smallest accessors compile to a single word-sized load at a
fixed offset. ``std::string::c_str()`` on libstdc++ is exactly ``mov (%rcx),
%rcx`` -- byte-identical to ``std::vector<T>::data()``, ``unique_ptr::get()``,
and every other pointer-field dereference in the program. No structural pattern
can tell them apart, and one that tried would fire on unrelated code constantly.

The information that *does* distinguish them only exists later: once an anchor
pattern (``length``/``capacity``/``empty``/...) has fired anywhere in the
function, Typehoon types the container pointer as the corresponding ``cpp::std``
class, and every other access to it is resolved to a named field. Naming those
accesses after their accessors adds no guess of its own -- it inherits exactly
the confidence of the recovered type, so it can never fire on a pointer that
type inference did not already call an STL container (and, conversely, it does
inherit a wrong type: where an anchor pattern mistyped the container, the
accessor name is wrong in the same way the field name was).

This module holds the field -> accessor table used to name those already-typed
accesses. Only fields whose value *is* the accessor's return value are listed:

* ``m_capacity`` is libstdc++'s ``_M_allocated_capacity``, which is the active
  member of a union only for heap-allocated strings, so a raw read of it is not
  ``capacity()``.
* ``m_end_of_storage`` has no accessor of its own (``capacity()`` is a
  subtraction), so it is not listed either.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.procedures.definitions import SIM_TYPE_COLLECTIONS
from angr.sim_type import SimCppClass

if TYPE_CHECKING:
    from angr.sim_type import SimType


CPP_STD_TYPE_COLLECTION = "cpp::std"

STD_BASIC_STRING = "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>"
STD_VECTOR_PREFIX = "class std::vector<"

# field name -> accessor member name, per class family
_STRING_ACCESSORS = {
    "m_data": "c_str",
    "m_size": "length",
}
_VECTOR_ACCESSORS = {
    "m_start": "data",
    "m_finish": "end",
}


def _accessor_table(unique_name: str) -> dict[str, str] | None:
    if unique_name == STD_BASIC_STRING:
        return _STRING_ACCESSORS
    if unique_name.startswith(STD_VECTOR_PREFIX):
        return _VECTOR_ACCESSORS
    return None


def stl_accessor_name(ty: SimType, field_name: str) -> str | None:
    """
    Return the fully qualified accessor name for reading ``field_name`` out of ``ty``, e.g.
    ``"std::string::c_str"`` for the ``m_data`` field of ``std::string``, or ``None`` when ``ty`` is not a registered
    ``cpp::std`` class or the field has no equivalent accessor.

    The lookup is keyed on :attr:`SimCppClass.unique_name` and additionally requires that name to be registered in the
    ``cpp::std`` type collection, so a user-defined struct that happens to have a field called ``m_data`` can never
    match.
    """

    if not isinstance(ty, SimCppClass):
        return None
    unique_name = ty.unique_name
    if not unique_name or not ty.name:
        return None
    collection = SIM_TYPE_COLLECTIONS.get(CPP_STD_TYPE_COLLECTION)
    if collection is None or unique_name not in collection:
        return None
    table = _accessor_table(unique_name)
    if table is None:
        return None
    accessor = table.get(field_name)
    if accessor is None:
        return None
    return f"{ty.name}::{accessor}"
