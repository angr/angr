from typing import Union

from ..sim_type import (
    RustSimType,
    RustSimTypeInt,
    RustSimTypeReference,
    RustSimStruct,
    RustSimTypeArray,
    RustSimTypeSize,
    RustSimEnum,
    RustSimTypeOption,
    RustSimTypeResult,
)
from ...analyses.typehoon.lifter import TypeLifter
from ...analyses.typehoon.typeconsts import (
    BottomType,
    Int8,
    Int16,
    Int32,
    Int64,
    Int128,
    TypeConstant,
    Struct,
    Enum,
    EnumVariant,
)


class RustTypeLifter(TypeLifter):
    """
    Lift RustSimTypes to type constants.
    """

    __slots__ = ("bits", "memo")

    def __init__(self, bits: int):
        if bits not in (32, 64):
            raise ValueError("RustTypeLifter only supports 32-bit or 64-bit pointers.")
        self.bits = bits
        self.memo = {}

    def lift(self, ty: RustSimType):
        handler = _mapping.get(RustSimStruct if isinstance(ty, RustSimStruct) else type(ty), None)
        if handler is None:
            return BottomType()

        return handler(self, ty)

    def _lift_SimTypeInt(self, ty: RustSimTypeInt):  # pylint:disable=unused-argument,no-self-use
        if ty.size == 8:
            return Int8()
        elif ty.size == 16:
            return Int16()
        elif ty.size == 32:
            return Int32()
        elif ty.size == 64:
            return Int64()
        elif ty.size == 128:
            return Int128()
        else:
            return BottomType()

    def _lift_SimStruct(self, ty: RustSimStruct) -> Union["TypeConstant", BottomType]:
        if ty in self.memo:
            return self.memo[ty]

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

    def _lift_EnumVariant(self, variant):
        return EnumVariant(
            variant.name,
            [(self.lift(field_ty), field_name) for field_ty, field_name in variant.fields],
            variant.discriminant,
            variant.discriminant_size,
            variant.size,
        )

    def _lift_SimEnum(self, ty: RustSimEnum):
        obj = Enum(ty.name, [self._lift_EnumVariant(variant) for variant in ty.variants])
        self.memo[ty] = obj
        return obj


_mapping = {
    RustSimTypeInt: RustTypeLifter._lift_SimTypeInt,
    RustSimTypeSize: RustTypeLifter._lift_SimTypeInt,
    RustSimTypeReference: RustTypeLifter._lift_SimTypePointer,
    RustSimStruct: RustTypeLifter._lift_SimStruct,
    RustSimTypeArray: RustTypeLifter._lift_SimTypeArray,
    RustSimEnum: RustTypeLifter._lift_SimEnum,
    RustSimTypeResult: RustTypeLifter._lift_SimEnum,
    RustSimTypeOption: RustTypeLifter._lift_SimEnum,
}
