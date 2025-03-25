from __future__ import annotations
from typing import TYPE_CHECKING

from angr.sim_type import (
    SimType,
    SimTypeChar,
    SimTypeShort,
    SimTypeInt,
    SimTypeLong,
    SimTypeLongLong,
    SimTypePointer,
    SimStruct,
    SimTypeArray,
    SimTypeFloat,
    SimTypeDouble,
    SimCppClass,
)
from .typeconsts import BottomType, Int8, Int16, Int32, Int64, Pointer32, Pointer64, Struct, Array, Float32, Float64

if TYPE_CHECKING:
    from .typeconsts import TypeConstant


class TypeLifter:
    """
    Lift SimTypes to type constants.
    """

    __slots__ = ("bits", "memo")

    def __init__(self, bits: int):
        if bits not in (32, 64):
            raise ValueError("TypeLifter only supports 32-bit or 64-bit pointers.")
        self.bits = bits
        self.memo = {}

    def lift(self, ty: SimType):
        handler = _mapping.get(type(ty), None)
        if handler is None:
            return BottomType()

        return handler(self, ty)

    def _lift_SimTypeChar(self, ty):  # pylint:disable=unused-argument,no-self-use
        return Int8()

    def _lift_SimTypeShort(self, ty):  # pylint:disable=unused-argument,no-self-use
        return Int16()

    def _lift_SimTypeInt(self, ty):  # pylint:disable=unused-argument,no-self-use
        return Int32()

    def _lift_SimTypeLongLong(self, ty):  # pylint:disable=unused-argument,no-self-use
        return Int64()

    def _lift_SimTypePointer(self, ty: SimTypePointer):
        if self.bits == 32:
            return Pointer32(self.lift(ty.pts_to))
        if self.bits == 64:
            return Pointer64(self.lift(ty.pts_to))
        raise ValueError(f"Unsupported bits {self.bits}.")

    def _lift_SimStruct(self, ty: SimStruct) -> TypeConstant | BottomType:
        if ty in self.memo:
            return BottomType()

        obj = Struct(fields={}, name=ty.name)
        self.memo[ty] = obj
        converted_fields = {}
        field_names = {}
        ty_offsets = ty.offsets
        for field_name, simtype in ty.fields.items():
            if field_name not in ty_offsets:
                return BottomType()
            converted_fields[ty_offsets[field_name]] = self.lift(simtype)
            field_names[ty_offsets[field_name]] = field_name
        obj.fields = converted_fields
        obj.field_names = field_names
        return obj

    def _lift_SimCppClass(self, ty: SimCppClass) -> TypeConstant | BottomType:
        if ty in self.memo:
            return BottomType()

        obj = Struct(fields={}, name=ty.name, is_cppclass=True)
        self.memo[ty] = obj
        converted_fields = {}
        field_names = {}
        ty_offsets = ty.offsets
        for field_name, simtype in ty.members.items():
            if field_name not in ty_offsets:
                return BottomType()
            converted_fields[ty_offsets[field_name]] = self.lift(simtype)
            field_names[ty_offsets[field_name]] = field_name
        obj.fields = converted_fields
        obj.field_names = field_names
        return obj

    def _lift_SimTypeArray(self, ty: SimTypeArray) -> Array:
        elem_type = self.lift(ty.elem_type)
        return Array(elem_type, count=ty.length)

    def _lift_SimTypeFloat(self, ty: SimTypeFloat) -> Float32:  # pylint:disable=unused-argument,no-self-use
        return Float32()

    def _lift_SimTypeDouble(self, ty: SimTypeDouble) -> Float64:  # pylint:disable=unused-argument,no-self-use
        return Float64()


_mapping = {
    SimTypeChar: TypeLifter._lift_SimTypeChar,
    SimTypeShort: TypeLifter._lift_SimTypeShort,
    SimTypeInt: TypeLifter._lift_SimTypeInt,
    SimTypeLong: TypeLifter._lift_SimTypeInt,
    SimTypeLongLong: TypeLifter._lift_SimTypeLongLong,
    SimTypePointer: TypeLifter._lift_SimTypePointer,
    SimStruct: TypeLifter._lift_SimStruct,
    SimCppClass: TypeLifter._lift_SimCppClass,
    SimTypeArray: TypeLifter._lift_SimTypeArray,
    SimTypeFloat: TypeLifter._lift_SimTypeFloat,
    SimTypeDouble: TypeLifter._lift_SimTypeDouble,
}
