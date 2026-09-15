from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable
from typing import TYPE_CHECKING, cast

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
    from archinfo import Arch

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
    arch: Arch | None = None,
) -> SimType:
    """
    Replace every SimTypeRef inside `t` with the real type from `type_collections`.

    When arch is not None, memo holds the with_arch() copies of every dereferenced struct and union. This way we can
    avoid creating duplicate arch-ed copies of the same type.

    :param keep_missing:    Leave a SimTypeRef in place when no collection defines it, instead of raising
                            AngrMissingTypeError.
    """
    if memo is None:
        memo = {}
    arch = t._arch if t._arch is not None else arch

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
            raise AngrMissingTypeError(t.name if t.name is not None else str(t))
        return dereference_simtype(real_type, type_collections, memo=memo, keep_missing=keep_missing, arch=arch)

    def _memo_key(ty: SimStruct | SimUnion) -> str | int:
        anonymous = (isinstance(ty, SimStruct) and ty.anonymous) or ty.name is None or ty.name == "<anon>"
        return id(ty) if anonymous else ty.name

    def _archify(ty: SimType) -> SimType:
        copied = ty.copy()
        return copied if arch is None else copied.with_arch(arch)

    if isinstance(t, SimStruct):
        key = _memo_key(t)
        if key in memo:
            return memo[key]
        real_struct = cast(SimStruct, _archify(t))
        real_struct._def_order = t._def_order
        memo[key] = real_struct
        real_struct.fields = OrderedDict(
            (k, dereference_simtype(v, type_collections, memo=memo, keep_missing=keep_missing, arch=arch))
            for k, v in t.fields.items()
        )
        if arch is not None:
            real_struct.fixup_bitfield_offsets(arch)
        return real_struct
    if isinstance(t, SimUnion):
        key = _memo_key(t)
        if key in memo:
            return memo[key]
        real_union = cast(SimUnion, _archify(t))
        memo[key] = real_union
        real_union.members = {
            k: dereference_simtype(v, type_collections, memo=memo, keep_missing=keep_missing, arch=arch)
            for k, v in t.members.items()
        }
        return real_union
    if isinstance(t, SimTypePointer):
        real_ptr = cast(SimTypePointer, _archify(t))
        real_ptr.pts_to = dereference_simtype(
            t.pts_to, type_collections, memo=memo, keep_missing=keep_missing, arch=arch
        )
        return real_ptr
    if isinstance(t, SimTypeArray):
        real_arr = cast(SimTypeArray, _archify(t))
        real_arr.elem_type = dereference_simtype(
            t.elem_type, type_collections, memo=memo, keep_missing=keep_missing, arch=arch
        )
        return real_arr
    if isinstance(t, SimTypeFunction):
        real_func = cast(SimTypeFunction, _archify(t))
        real_func.args = tuple(
            dereference_simtype(arg, type_collections, memo=memo, keep_missing=keep_missing, arch=arch)
            for arg in t.args
        )
        real_func.returnty = (
            dereference_simtype(t.returnty, type_collections, memo=memo, keep_missing=keep_missing, arch=arch)
            if t.returnty is not None
            else None
        )
        return real_func
    return t if arch is None else t.with_arch(arch)


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


def _defined_in_collections(name: str, type_collections: list[SimTypeCollection]) -> SimType | None:
    """
    The type that dereference_simtype resolves `name` to: its definition in the first collection that has it.
    """
    for tc in type_collections:
        try:
            return tc.get(name)
        except AngrMissingTypeError:
            continue
    return None


def _field_type_shape(t: SimType, type_collections: list[SimTypeCollection]) -> tuple:
    """
    Describe the type of a struct field: a nested struct or union by the names of its own members, a SimTypeRef by
    what the reader would resolve it to, and everything else by what it is. Nested aggregates are described one level
    deep and their members' types are not entered, which keeps the description finite on a recursive type.
    """
    if isinstance(t, SimTypeRef):
        defined = _defined_in_collections(t.name, type_collections) if t.name is not None else None
        if defined is None or isinstance(defined, SimTypeRef):
            return "named", t.name
        return _field_type_shape(defined, type_collections)
    if isinstance(t, SimStruct):
        return "struct", tuple(t.fields)
    if isinstance(t, SimUnion):
        return "union", tuple(t.members)
    if isinstance(t, SimTypePointer):
        return "pointer", t.label, _field_type_shape(t.pts_to, type_collections)
    if isinstance(t, SimTypeArray):
        return "array", t.label, t.length, _field_type_shape(t.elem_type, type_collections)
    if isinstance(t, SimTypeFunction):
        args = tuple(_field_type_shape(arg, type_collections) for arg in t.args)
        returnty = _field_type_shape(t.returnty, type_collections) if t.returnty is not None else None
        return "function", t.variadic, args, returnty
    return type(t).__name__, t.label, getattr(t, "_name", None), getattr(t, "signed", None), getattr(t, "_size", None)


def _struct_shape(t: SimStruct, type_collections: list[SimTypeCollection]) -> tuple:
    return t.pack, t.align, tuple((k, _field_type_shape(v, type_collections)) for k, v in t.fields.items())


def same_struct_in_collections(t: SimStruct, type_collections: list[SimTypeCollection]) -> bool:
    """
    Whether a SimTypeRef to `t.name` dereferenced against `type_collections` restores `t`: the first collection that
    defines the name, which is the one dereference_simtype consults, defines a struct whose fields match, with a
    nested struct or union matched on its own members' names.

    A struct that only shares its name with a definition must be kept as it is, or the reader would restore the
    definition's body in its place. The win32 generator names every inline anonymous struct `_Anonymous_e__Struct`,
    and libc's `netent` and winsock's differ in a field width.
    """
    if t.anonymous:
        # its name is not an identity, whatever it happens to be
        return False
    defined = _defined_in_collections(t.name, type_collections)
    return isinstance(defined, SimStruct) and _struct_shape(defined, type_collections) == _struct_shape(
        t, type_collections
    )


def make_type_reference(
    t: SimType,
    memo: dict[str, SimTypeRef] | None = None,
    type_collections: list[SimTypeCollection] | None = None,
) -> SimType:
    """
    Take a SimType and convert named SimStruct instances to SimTypeRefs.

    :param t:                   The SimType instance to convert.
    :param type_collections:    Only a struct that one of these collections defines the same way is converted, so that
                                dereferencing the reference gives back the struct that was there. A struct that only
                                shares its name with a collection's definition is kept. None converts every named
                                struct.
    :return:                    A converted SimType instance.
    """

    if memo is None:
        memo = {}

    if (
        type(t) is SimStruct
        and t.name
        and (type_collections is None or same_struct_in_collections(t, type_collections))
    ):
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
