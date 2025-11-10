from typing import Dict, Union
from itertools import count

from angr.analyses.typehoon.translator import TypeTranslator, SimTypeTempRef
from angr.analyses.typehoon import typeconsts
from angr.analyses.typehoon.typeconsts import TypeConstant, IntVar
from angr import sim_type
from angr.rust.sim_type import (
    SimType,
    RustSimTypeInt,
    RustSimTypeReference,
    RustSimType,
    RustSimTypeArray,
    RustSimStruct,
    RustSimTypeResult,
    RustSimTypeOption,
    RustSimEnum,
    EnumVariant,
)


class RustSimTypeTempRef(RustSimType, SimTypeTempRef):
    def __init__(self, typevar):
        super().__init__(typevar)

    def repr(self, name=None, full=0, memo=None, indent=0):
        return "<RustSimTypeTempRef>"


class RustTypeTranslator(TypeTranslator):
    """
    Translate type variables to RustSimType equivalence.
    """

    def __init__(self, project=None, arch=None):
        self.project = project
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

    def _translate_IntVar(self, tc: IntVar):  # pylint:disable=unused-argument
        return RustSimTypeInt(size=tc.size, signed=False).with_arch(self.arch)

    def _translate_Array(self, tc: typeconsts.Array):
        # TODO: Maybe array should be translated to struct?
        elem_type = self._tc2simtype(tc.element)
        # return RustSimTypeArray(elem_type, length=tc.count).with_arch(self.arch)
        return RustSimTypeInt(size=64, signed=False).with_arch(self.arch)

    def _translate_Struct(self, tc):
        if tc in self.structs:
            return self.structs[tc]

        if tc.name:
            name = tc.name
        else:
            name = self.struct_name()

        # Check if it's pre-defined Rust structs
        # if self.project and name in self.project.kb.known_structs:
        #     s = self.project.kb.known_structs[name]
        #     self.structs[tc] = s
        #     return s

        s = RustSimStruct({}, name=name).with_arch(self.arch)
        self.structs[tc] = s

        next_offset = 0
        for offset, typ in sorted(tc.fields.items(), key=lambda item: item[0]):
            if offset > next_offset and tc.name is None:
                # we need padding!
                # If struct's name is known, do not pad
                padding_size = offset - next_offset
                s.fields["padding_%x" % next_offset] = RustSimTypeArray(
                    RustSimTypeInt(size=8, signed=False).with_arch(self.arch), padding_size
                ).with_arch(self.arch)

            translated_type = self._tc2simtype(typ)

            if isinstance(translated_type, sim_type.SimTypeBottom):
                translated_type = RustSimTypeInt(self.arch.bytes * self.arch.byte_width).with_arch(self.arch)

            field_name = "field_%x" % offset
            if tc.field_names and offset in tc.field_names:
                field_name = tc.field_names[offset]
            s.fields[field_name] = translated_type

            if isinstance(translated_type, RustSimTypeTempRef):
                next_offset = self.arch.bytes + offset
            else:
                next_offset = translated_type.size // self.arch.byte_width + offset

        return s

    def _translate_Result(self, tc: typeconsts.Enum):
        ok_variant = tc.get_variant("Ok")
        err_variant = tc.get_variant("Err")
        ok_type = self._tc2simtype(ok_variant.fields[0][0])
        err_type = self._tc2simtype(err_variant.fields[0][0])
        return RustSimTypeResult(
            ok_type,
            ok_variant.discriminant,
            ok_variant.discriminant_size,
            err_type,
            err_variant.discriminant,
            err_variant.discriminant_size,
            name=tc.name,
        ).with_arch(self.arch)

    def _translate_Option(self, tc: typeconsts.Enum):
        none_variant = tc.get_variant("None")
        some_variant = tc.get_variant("Some")
        some_type = self._tc2simtype(some_variant.fields[0][0])
        return RustSimTypeOption(
            none_variant.discriminant,
            none_variant.discriminant_size,
            some_type,
            some_variant.discriminant,
            some_variant.discriminant_size,
            name=tc.name,
        ).with_arch(self.arch)

    def _translate_Enum(self, tc: typeconsts.Enum):
        if tc.name.startswith("core::result::Result<") or tc.name.startswith("Result<"):
            return self._translate_Result(tc)
        elif tc.name.startswith("core::option::Option<") or tc.name.startswith("Option<"):
            return self._translate_Option(tc)
        else:
            return RustSimEnum(
                tc.name,
                [
                    EnumVariant(
                        variant.name,
                        [(self._tc2simtype(field_ty), field_name) for field_ty, field_name in variant.fields],
                        variant.discriminant,
                        variant.discriminant_size,
                    )
                    for variant in tc.variants
                ],
            ).with_arch(self.arch)

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
    typeconsts.IntVar: RustTypeTranslator._translate_IntVar,
    typeconsts.TypeVariableReference: RustTypeTranslator._translate_TypeVariableReference,
    typeconsts.Enum: RustTypeTranslator._translate_Enum,
}
