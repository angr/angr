# Utilities for unioning partial struct layouts recovered for the same value across multiple functions.
from __future__ import annotations

from angr.sim_type import (
    SimStruct,
    SimType,
    SimTypeBottom,
    SimTypeChar,
    SimTypeFixedSizeArray,
    SimTypePointer,
    TypeRef,
)


def _resolve(ty: SimType | None) -> SimType | None:
    """Resolve a TypeRef to the type it points to."""
    seen = set()
    while isinstance(ty, TypeRef):
        if id(ty) in seen:
            break
        seen.add(id(ty))
        ty = ty.ty
    return ty


def _byte_size(ty: SimType, arch) -> int | None:
    try:
        size = ty.size
    except Exception:  # pylint:disable=broad-except
        return None
    if size is None:
        return None
    return size // arch.byte_width


def _pointee_fields(ptr_ty: SimType, arch) -> dict[int, SimType] | None:
    """
    Given a pointer type, return a mapping of byte offset -> field type for the pointed-to object. A pointer to a scalar
    is treated as a single field at offset 0. A pointer to ``void`` (or a sizeless/bottom type) contributes no fields.
    Returns ``None`` if the type is not a pointer.
    """
    if not isinstance(ptr_ty, SimTypePointer):
        return None
    pts_to = _resolve(ptr_ty.pts_to)
    if pts_to is None or isinstance(pts_to, SimTypeBottom):
        return {}
    if isinstance(pts_to, SimStruct):
        fields: dict[int, SimType] = {}
        offsets = pts_to.offsets
        for name, field_ty in pts_to.fields.items():
            if name.startswith("padding_"):
                continue
            offset = offsets.get(name)
            if offset is None:
                continue
            resolved = _resolve(field_ty)
            if resolved is not None:
                fields[offset] = resolved
        return fields
    if _byte_size(pts_to, arch):
        return {0: pts_to}
    return {}


def _field_rank(ty: SimType) -> int:
    inner = _resolve(ty)
    if isinstance(inner, SimStruct):
        return 2
    if isinstance(inner, SimTypePointer):
        return 1
    return 0


def _best_field(candidates: list[SimType], arch) -> SimType:
    """Pick the most informative candidate for a field: prefer larger size, then struct/pointer over scalar."""
    return max(candidates, key=lambda t: (_byte_size(t, arch) or 0, _field_rank(t)))


def _resolve_overlaps(fields: dict[int, SimType], arch) -> dict[int, SimType]:
    """Drop fields that are fully covered by a larger field starting at a lower-or-equal offset."""
    chosen: dict[int, SimType] = {}
    covered_end = None
    for offset in sorted(fields):
        if covered_end is not None and offset < covered_end:
            # overlapped by an earlier, larger field; skip it
            continue
        field_ty = fields[offset]
        chosen[offset] = field_ty
        size = _byte_size(field_ty, arch) or 1
        covered_end = offset + size
    return chosen


def _array_element(fields: dict[int, SimType], arch) -> SimType | None:
    """
    Recognize a layout that is really a run of array elements rather than a struct: every field has the same scalar type
    and the fields sit back to back from offset 0. A run of ``char`` (``s[0]``, ``s[1]``) is a string as soon as it has
    two elements; wider scalars need three back-to-back elements before a struct of equally typed members (``{int x;
    int y;}``) is given up for an array. Returns the element type, or ``None`` if the layout is not array-like.
    """
    if len(fields) < 2:
        return None
    offsets = sorted(fields)
    if offsets[0] != 0:
        return None
    first = _resolve(fields[0])
    if first is None or isinstance(first, (SimStruct, SimTypePointer, SimTypeFixedSizeArray)):
        return None
    size = _byte_size(first, arch)
    if not size:
        return None
    try:
        first_repr = first.c_repr()
    except Exception:  # pylint:disable=broad-except
        return None
    for idx, offset in enumerate(offsets):
        if offset != idx * size:
            return None
        ty = _resolve(fields[offset])
        try:
            same = ty is not None and ty.c_repr() == first_repr and _byte_size(ty, arch) == size
        except Exception:  # pylint:disable=broad-except
            return None
        if not same:
            return None
    if size > 1 and len(offsets) < 3:
        return None
    return first


def _build_struct(fields: dict[int, SimType], arch, name: str | None) -> SimStruct:
    """Build a SimStruct with explicit offsets, inserting char-array padding for gaps (mirrors TypeTranslator)."""
    s = SimStruct({}, name=name).with_arch(arch)
    next_offset = 0
    for offset in sorted(fields):
        if offset > next_offset:
            s.fields[f"padding_{next_offset:x}"] = SimTypeFixedSizeArray(
                SimTypeChar(signed=False).with_arch(arch), offset - next_offset
            ).with_arch(arch)
        field_ty = fields[offset]
        s.fields[f"field_{offset:x}"] = field_ty
        next_offset = offset + (_byte_size(field_ty, arch) or 1)
    return s


def pointer_to_layout(fields: dict[int, SimType], arch) -> SimTypePointer:
    """Build a pointer to a struct with the given byte offset -> field type layout (padding filled in)."""
    return SimTypePointer(_build_struct(fields, arch, None)).with_arch(arch)


def union_pointer_struct_types(types: list[SimType], arch, name: str | None = None) -> SimTypePointer | None:
    """
    Union partial struct layouts recovered for the same pointer value across multiple callees.

    Each input is expected to be a pointer type (pointer-to-struct or pointer-to-scalar). The pointed-to layouts are
    merged field-by-field by offset: at each offset the most informative (largest / most-specific) field wins, and
    fields fully covered by a larger field are dropped. Returns a ``SimTypePointer`` to the combined struct, a pointer
    to the element type when the combined layout is a run of array elements, or ``None`` if no fields could be
    recovered (e.g. all inputs were ``void*``).
    """
    collected: dict[int, list[SimType]] = {}
    for ty in types:
        fields = _pointee_fields(ty, arch)
        if not fields:
            continue
        for offset, field_ty in fields.items():
            collected.setdefault(offset, []).append(field_ty)

    if not collected:
        return None

    best = {offset: _best_field(cands, arch) for offset, cands in collected.items()}
    resolved = _resolve_overlaps(best, arch)
    if not resolved:
        return None

    # back-to-back equally typed scalars are array elements, not struct members: return a pointer to the element type
    element = _array_element(resolved, arch)
    if element is not None:
        return SimTypePointer(element).with_arch(arch)

    struct = _build_struct(resolved, arch, name)
    return SimTypePointer(struct).with_arch(arch)
