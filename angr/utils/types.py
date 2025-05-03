from __future__ import annotations
from typing import TYPE_CHECKING
from collections import OrderedDict

from angr.sim_type import (
    TypeRef,
    SimType,
    SimTypePointer,
    SimTypeArray,
    SimTypeFixedSizeArray,
    SimTypeRef,
    SimStruct,
    SimUnion,
    SimTypeFunction,
)
from angr.errors import AngrMissingTypeError
from angr import SIM_TYPE_COLLECTIONS, SIM_LIBRARIES

if TYPE_CHECKING:
    from angr.procedures.definitions import SimTypeCollection


def unpack_typeref(ty):
    if isinstance(ty, TypeRef):
        return ty.type
    return ty


def unpack_pointer(ty: SimType, iterative: bool = False) -> SimType | None:
    if isinstance(ty, SimTypePointer):
        if iterative:
            inner = unpack_pointer(ty.pts_to, iterative=True)
            return inner if inner is not None else ty.pts_to
        return ty.pts_to
    return None


def unpack_pointer_and_array(ty: SimType, iterative: bool = False) -> SimType | None:
    if isinstance(ty, SimTypePointer):
        if iterative:
            inner = unpack_pointer(ty.pts_to, iterative=True)
            return inner if inner is not None else ty.pts_to
        return ty.pts_to
    if isinstance(ty, SimTypeArray):
        return ty.elem_type
    return None


def replace_pointer_pts_to(ty: SimType, old_pts_to: SimType, new_pts_to: SimType) -> SimTypePointer | None:
    if isinstance(ty, SimTypePointer):
        if ty.pts_to is old_pts_to:
            inner = new_pts_to
        elif isinstance(ty.pts_to, SimTypePointer):
            # recursively replace pts_to inside
            inner = replace_pointer_pts_to(ty.pts_to, old_pts_to, new_pts_to)
        else:
            return None
        return SimTypePointer(inner, label=ty.label, offset=ty.offset)
    return None


def unpack_array(ty) -> SimType | None:
    if isinstance(ty, SimTypeArray):
        return ty.elem_type
    if isinstance(ty, SimTypeFixedSizeArray):
        return ty.elem_type
    return None


def squash_array_reference(ty):
    pointed_to = unpack_pointer(ty)
    if pointed_to:
        array_of = unpack_array(pointed_to)
        if array_of:
            return SimTypePointer(array_of)
    return ty


def dereference_simtype(
    t: SimType, type_collections: list[SimTypeCollection], memo: dict[str, SimType] | None = None
) -> SimType:
    if memo is None:
        memo = {}

    if isinstance(t, SimTypeRef):
        real_type = None

        if t.name in memo:
            return memo[t.name]

        if type_collections and t.name is not None:
            for tc in type_collections:
                try:
                    real_type = tc.get(t.name)
                    break
                except AngrMissingTypeError:
                    continue
        if real_type is None:
            raise AngrMissingTypeError(f"Missing type {t.name}")
        return dereference_simtype(real_type, type_collections, memo=memo)

    # the following code prepares a real_type SimType object that will be returned at the end of this method
    if isinstance(t, SimStruct):
        if t.name in memo:
            return memo[t.name]

        real_type = t.copy()
        if not t.anonymous:
            memo[t.name] = real_type
        fields = OrderedDict((k, dereference_simtype(v, type_collections, memo=memo)) for k, v in t.fields.items())
        real_type.fields = fields
    elif isinstance(t, SimTypePointer):
        real_pts_to = dereference_simtype(t.pts_to, type_collections, memo=memo)
        real_type = t.copy()
        real_type.pts_to = real_pts_to
    elif isinstance(t, SimTypeArray):
        real_elem_type = dereference_simtype(t.elem_type, type_collections, memo=memo)
        real_type = t.copy()
        real_type.elem_type = real_elem_type
    elif isinstance(t, SimUnion):
        real_members = {k: dereference_simtype(v, type_collections, memo=memo) for k, v in t.members.items()}
        real_type = t.copy()
        real_type.members = real_members
    elif isinstance(t, SimTypeFunction):
        real_args = [dereference_simtype(arg, type_collections, memo=memo) for arg in t.args]
        real_return_type = (
            dereference_simtype(t.returnty, type_collections, memo=memo) if t.returnty is not None else None
        )
        real_type = t.copy()
        real_type.args = tuple(real_args)
        real_type.returnty = real_return_type
    else:
        return t

    if t._arch is not None:
        real_type = real_type.with_arch(t._arch)
    return real_type


def dereference_simtype_by_lib(t: SimType, libname: str) -> SimType:
    if libname not in SIM_LIBRARIES:
        return t

    type_collections = []
    for prototype_lib in SIM_LIBRARIES[libname]:
        if prototype_lib.type_collection_names:
            for typelib_name in prototype_lib.type_collection_names:
                type_collections.append(SIM_TYPE_COLLECTIONS[typelib_name])
    if type_collections:
        return dereference_simtype(t, type_collections)
    return t
