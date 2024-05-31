from typing import Dict, Union
from itertools import count

from ...analyses.typehoon.translator import TypeTranslator
from ...analyses.typehoon import typeconsts
from ...analyses.typehoon.typeconsts import TypeConstant
from ... import sim_type
from ...sim_type import SimType
from ..sim_type import (
    RustSimTypeInt,
    RustSimTypeReference,
    RustSimType,
    RustSimTypeArray,
    RustSimStruct,
    RustSimTypeTempRef,
    RustSimTypeString,
    RustSimTypeStr,
)


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

    def _translate_Pointer64(self, tc):
        if isinstance(tc.basetype, typeconsts.BottomType):
            # void *
            internal = sim_type.SimTypeBottom(label="void").with_arch(self.arch)
        else:
            internal = self._tc2simtype(tc.basetype)
        return RustSimTypeReference(internal).with_arch(self.arch)

    def _translate_Pointer32(self, tc):
        return self._translate_Pointer64(tc)

    def _translate_Int8(self, tc):  # pylint:disable=unused-argument
        return RustSimTypeInt(size=8, signed=False).with_arch(self.arch)

    def _translate_Int16(self, tc):  # pylint:disable=unused-argument
        return RustSimTypeInt(size=16, signed=False).with_arch(self.arch)

    def _translate_Int32(self, tc):  # pylint:disable=unused-argument
        return RustSimTypeInt(size=32, signed=False).with_arch(self.arch)

    def _translate_Int64(self, tc):  # pylint:disable=unused-argument
        return RustSimTypeInt(size=64, signed=False).with_arch(self.arch)

    def _translate_Int128(self, tc):  # pylint:disable=unused-argument
        return RustSimTypeInt(size=128, signed=False).with_arch(self.arch)

    def _translate_Array(self, tc: typeconsts.Array):
        elem_type = self._tc2simtype(tc.element)
        return RustSimTypeArray(elem_type, length=tc.count).with_arch(self.arch)

    def _translate_Struct(self, tc):
        if tc in self.structs:
            return self.structs[tc]

        if tc.name:
            name = tc.name
        else:
            name = self.struct_name()

        # Check if it's pre-defined Rust structs
        if name in PreDefinedStructs:
            s = PreDefinedStructs[name]().with_arch(self.arch)
            self.structs[tc] = s
            return s

        s = RustSimStruct({}, name=name).with_arch(self.arch)
        self.structs[tc] = s

        next_offset = 0
        for offset, typ in sorted(tc.fields.items(), key=lambda item: item[0]):
            if offset > next_offset:
                # we need padding!
                padding_size = offset - next_offset
                s.fields["padding_%x" % next_offset] = RustSimTypeArray(
                    RustSimTypeInt(size=8, signed=False).with_arch(self.arch), padding_size
                ).with_arch(self.arch)

            translated_type = self._tc2simtype(typ)

            # TODO: Handle SimTypeBottom
            assert not isinstance(translated_type, sim_type.SimTypeBottom)

            s.fields["field_%x" % offset] = translated_type

            if isinstance(translated_type, RustSimTypeTempRef):
                next_offset = self.arch.bytes + offset
            else:
                next_offset = translated_type.size // self.arch.byte_width + offset

        return s

    def _tc2simtype(self, tc):
        if tc is None:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        try:
            handler = TypeConstHandlers[tc.__class__]
        except KeyError:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        translated = handler(self, tc)
        return translated

    def ctype2rust(self, simtype: Union[sim_type.SimType, RustSimType]):
        if isinstance(simtype, RustSimType):
            return simtype
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

PreDefinedStructs = {"String": RustSimTypeString, "str": RustSimTypeStr}
