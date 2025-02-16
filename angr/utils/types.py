from __future__ import annotations

from angr.sim_type import TypeRef, SimType, SimTypePointer, SimTypeArray, SimTypeFixedSizeArray


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
