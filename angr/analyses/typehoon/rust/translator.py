from typing import Dict, Union
from itertools import count

from ..translator import TypeTranslator
from .... import sim_type
from ....sim_type import SimType
from .sim_type import RustSimTypeInt
from .. import typeconsts
from ..typeconsts import TypeConstant


class RustTypeTranslator(TypeTranslator):
    """
    Translate type variables to RustSimType equivalence.
    """

    def __init__(self, arch=None):
        self.arch = arch

        self.translated: Dict[TypeConstant, SimType] = {}
        self.translated_simtypes: Dict[SimType, TypeConstant] = {}
        self.structs = {}
        self._struct_ctr = count()

        # will be updated every time .translate() is called
        self._has_nonexistent_ref = False

    def _translate_Int32(self, tc):  # pylint:disable=unused-argument
        return RustSimTypeInt(size=32, signed=False).with_arch(self.arch)

    def _translate_Int64(self, tc):  # pylint:disable=unused-argument
        return RustSimTypeInt(size=64, signed=False).with_arch(self.arch)

    def _tc2simtype(self, tc):
        if tc is None:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        try:
            handler = TypeConstHandlers[tc.__class__]
        except KeyError:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        translated = handler(self, tc)
        return translated

    def ctype2rust(self, simtype: sim_type.SimType):
        tc = self.simtype2tc(simtype)
        return self.tc2simtype(tc)[0]


TypeConstHandlers = {
    typeconsts.Pointer64: RustTypeTranslator._translate_Pointer64,
    typeconsts.Pointer32: RustTypeTranslator._translate_Pointer32,
    typeconsts.Array: RustTypeTranslator._translate_Array,
    typeconsts.Struct: RustTypeTranslator._translate_Struct,
    typeconsts.Int8: RustTypeTranslator._translate_Int8,
    typeconsts.Int16: RustTypeTranslator._translate_Int16,
    typeconsts.Int32: RustTypeTranslator._translate_Int32,
    typeconsts.Int64: RustTypeTranslator._translate_Int64,
    typeconsts.Int128: RustTypeTranslator._translate_Int128,
    typeconsts.TypeVariableReference: RustTypeTranslator._translate_TypeVariableReference,
}
