from typing import Union, TYPE_CHECKING

from ...sim_type import (
    SimType,
    SimTypeChar,
    SimTypeShort,
    SimTypeInt,
    SimTypeLong,
    SimTypeLongLong,
    SimTypePointer,
    SimStruct,
)
from .typeconsts import BottomType, Int8, Int16, Int32, Int64, Pointer32, Pointer64, Struct

if TYPE_CHECKING:
    from .typeconsts import TypeConstant


class TypeLifter:
    """
    Lift SimTypes to type constants.
    """

    __slots__ = ("bits",)

    def __init__(self, bits: int):
        if bits not in (32, 64):
            raise ValueError("TypeLifter only supports 32-bit or 64-bit pointers.")
        self.bits = bits

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
        elif self.bits == 64:
            return Pointer64(self.lift(ty.pts_to))
        raise ValueError("Unsupported bits %s." % self.bits)

    def _lift_SimStruct(self, ty: SimStruct) -> Union["TypeConstant", BottomType]:
        converted_fields = {}
        for field_name, simtype in ty.fields.items():
            if field_name not in ty.offsets:
                return BottomType()
            converted_fields[ty.offsets[field_name]] = self.lift(simtype)
        return Struct(fields=converted_fields)


_mapping = {
    SimTypeChar: TypeLifter._lift_SimTypeChar,
    SimTypeShort: TypeLifter._lift_SimTypeShort,
    SimTypeInt: TypeLifter._lift_SimTypeInt,
    SimTypeLong: TypeLifter._lift_SimTypeInt,
    SimTypeLongLong: TypeLifter._lift_SimTypeLongLong,
    SimTypePointer: TypeLifter._lift_SimTypePointer,
    SimStruct: TypeLifter._lift_SimStruct,
}
