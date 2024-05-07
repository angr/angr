from ..sim_type import (
    RustSimType,
    RustSimTypeInt,
    RustSimTypePointer,
    RustSimStruct,
    RustSimTypeArray,
    RustSimTypeStr,
    RustSimTypeString,
)
from ...analyses.typehoon.lifter import TypeLifter
from ...analyses.typehoon.typeconsts import BottomType, Int8, Int16, Int32, Int64


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
        handler = _mapping.get(type(ty), None)
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
        else:
            return BottomType()


_mapping = {
    RustSimTypeInt: RustTypeLifter._lift_SimTypeInt,
    RustSimTypePointer: RustTypeLifter._lift_SimTypePointer,
    RustSimStruct: RustTypeLifter._lift_SimStruct,
    RustSimTypeArray: RustTypeLifter._lift_SimTypeArray,
    RustSimTypeStr: RustTypeLifter._lift_SimStruct,
    RustSimTypeString: RustTypeLifter._lift_SimStruct,
}
