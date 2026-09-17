from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable
from typing import TYPE_CHECKING

from angr.errors import AngrMissingTypeError
from angr.procedures import SIM_LIBRARIES, SIM_TYPE_COLLECTIONS
from angr.sim_type import (
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypePointer,
    SimTypeRef,
    SimUnion,
    TypeRef,
)

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
    t: SimType,
    type_collections: list[SimTypeCollection],
    memo: dict[str | int, SimType] | None = None,
    keep_missing: bool = False,
) -> SimType:
    """
    Replace every SimTypeRef inside `t` with the real type from `type_collections`.

    :param keep_missing:    Leave a SimTypeRef in place when no collection defines it, instead of raising
                            AngrMissingTypeError.
    """
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
            if keep_missing:
                return t
            raise AngrMissingTypeError(t.name)
        if t._arch is not None:
            real_type = real_type.with_arch(t._arch)
        return dereference_simtype(real_type, type_collections, memo=memo, keep_missing=keep_missing)

    # the following code prepares a real_type SimType object that will be returned at the end of this method
    if isinstance(t, SimStruct):
        if t.name in memo or (t.anonymous and id(t) in memo):
            return memo[t.name if not t.anonymous else id(t)]

        real_type = t.copy()
        memo[t.name if not t.anonymous else id(t)] = real_type
        fields = OrderedDict(
            (k, dereference_simtype(v, type_collections, memo=memo, keep_missing=keep_missing))
            for k, v in t.fields.items()
        )
        real_type.fields = fields
    elif isinstance(t, SimTypePointer):
        real_pts_to = dereference_simtype(t.pts_to, type_collections, memo=memo, keep_missing=keep_missing)
        real_type = t.copy()
        real_type.pts_to = real_pts_to
    elif isinstance(t, SimTypeArray):
        real_elem_type = dereference_simtype(t.elem_type, type_collections, memo=memo, keep_missing=keep_missing)
        real_type = t.copy()
        real_type.elem_type = real_elem_type
    elif isinstance(t, SimUnion):
        memo[t.name] = t
        real_members = {
            k: dereference_simtype(v, type_collections, memo=memo, keep_missing=keep_missing)
            for k, v in t.members.items()
        }
        real_type = t.copy()
        real_type.members = real_members
    elif isinstance(t, SimTypeFunction):
        real_args = [dereference_simtype(arg, type_collections, memo=memo, keep_missing=keep_missing) for arg in t.args]
        real_return_type = (
            dereference_simtype(t.returnty, type_collections, memo=memo, keep_missing=keep_missing)
            if t.returnty is not None
            else None
        )
        real_type = t.copy()
        real_type.args = tuple(real_args)
        real_type.returnty = real_return_type
    else:
        return t

    if t._arch is not None:
        real_type = real_type.with_arch(t._arch)
    return real_type


def type_collections_for_lib(libname: str | None) -> list[SimTypeCollection]:
    """
    The type collections that prototypes of library `libname` refer to. Falls back to every loaded type collection
    when the library is unknown or declares no type collections.
    """
    type_collections: list[SimTypeCollection] = []
    if libname is not None and libname in SIM_LIBRARIES:
        for prototype_lib in SIM_LIBRARIES[libname]:
            for typelib_name in prototype_lib.type_collection_names:
                if typelib_name in SIM_TYPE_COLLECTIONS:
                    type_collections.append(SIM_TYPE_COLLECTIONS[typelib_name])
    if not type_collections:
        seen: set[int] = set()
        for tc in SIM_TYPE_COLLECTIONS.values():
            if id(tc) not in seen:
                seen.add(id(tc))
                type_collections.append(tc)
    return type_collections


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


def relink_typerefs(t: SimType, typerefs: dict[str, TypeRef], _seen: dict[int, SimType] | None = None) -> SimType:
    """
    Replace every TypeRef inside `t` whose name is in `typerefs` with the TypeRef object from `typerefs`, so that
    deserialized types share the TypeRef objects owned by a TypesStore again. The TypeRef targets themselves are not
    descended into; `t` is updated in place.
    """
    if _seen is None:
        _seen = {}
    if id(t) in _seen:
        return _seen[id(t)]
    _seen[id(t)] = t

    if isinstance(t, TypeRef):
        if t.name in typerefs:
            _seen[id(t)] = typerefs[t.name]
            return typerefs[t.name]
        return t
    if isinstance(t, SimStruct):
        t.fields = OrderedDict((k, relink_typerefs(v, typerefs, _seen)) for k, v in t.fields.items())
    elif isinstance(t, SimUnion):
        t.members = {k: relink_typerefs(v, typerefs, _seen) for k, v in t.members.items()}
    elif isinstance(t, SimTypePointer):
        t.pts_to = relink_typerefs(t.pts_to, typerefs, _seen)
    elif isinstance(t, SimTypeArray):
        t.elem_type = relink_typerefs(t.elem_type, typerefs, _seen)
    elif isinstance(t, SimTypeFunction):
        t.args = tuple(relink_typerefs(arg, typerefs, _seen) for arg in t.args)
        if t.returnty is not None:
            t.returnty = relink_typerefs(t.returnty, typerefs, _seen)
    return t


def find_type_refs(t: SimType, _seen: set[int] | None = None) -> set[str]:
    """
    Collect the names of all SimTypeRef nodes reachable from `t`.
    """
    if _seen is None:
        _seen = set()
    if id(t) in _seen:
        return set()
    _seen.add(id(t))

    if isinstance(t, SimTypeRef):
        return {t.name} if t.name is not None else {""}
    if isinstance(t, SimStruct):
        subtypes: Iterable[SimType] = t.fields.values()
    elif isinstance(t, SimUnion):
        subtypes = t.members.values()
    elif isinstance(t, SimTypePointer):
        subtypes = (t.pts_to,)
    elif isinstance(t, SimTypeArray):
        subtypes = (t.elem_type,)
    elif isinstance(t, SimTypeFunction):
        subtypes = (*t.args, t.returnty) if t.returnty is not None else t.args
    else:
        return set()

    refs: set[str] = set()
    for sub in subtypes:
        refs |= find_type_refs(sub, _seen)
    return refs


def make_type_reference(
    t: SimType,
    memo: dict[str, SimTypeRef] | None = None,
    type_collections: list[SimTypeCollection] | None = None,
) -> SimType:
    """
    Take a SimType and convert named SimStruct instances to SimTypeRefs.

    :param t:                   The SimType instance to convert.
    :param type_collections:    Only structs defined in one of these collections are converted, so that the references
                                can be resolved later. None converts every named struct.
    :return:                    A converted SimType instance.
    """

    if memo is None:
        memo = {}

    if type(t) is SimStruct and t.name and (type_collections is None or any(t.name in tc for tc in type_collections)):
        if t.name in memo:
            ref_t = memo[t.name]
        else:
            ref_t = SimTypeRef(t.name, SimStruct)
            memo[t.name] = ref_t
    elif isinstance(t, SimTypePointer):
        ref_pts_to = make_type_reference(t.pts_to, memo=memo, type_collections=type_collections)
        ref_t = t.copy()
        ref_t.pts_to = ref_pts_to
    elif isinstance(t, SimTypeArray):
        ref_elem_type = make_type_reference(t.elem_type, memo=memo, type_collections=type_collections)
        ref_t = t.copy()
        ref_t.elem_type = ref_elem_type
    elif isinstance(t, SimUnion):
        ref_members = {
            k: make_type_reference(v, memo=memo, type_collections=type_collections) for k, v in t.members.items()
        }
        ref_t = SimUnion(ref_members, label=t.label)
    elif isinstance(t, SimTypeFunction):
        ref_args = [make_type_reference(arg, memo=memo, type_collections=type_collections) for arg in t.args]
        ref_return_type = (
            make_type_reference(t.returnty, memo=memo, type_collections=type_collections)
            if t.returnty is not None
            else None
        )
        ref_t = t.copy()
        ref_t.args = tuple(ref_args)
        ref_t.returnty = ref_return_type
    else:
        return t

    if t._arch is not None:
        ref_t = ref_t.with_arch(t._arch)
    return ref_t
