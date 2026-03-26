from __future__ import annotations
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
    RustSimTypeSize,
    RustSimStruct,
    RustSimTypeResult,
    RustSimTypeOption,
    RustSimEnum,
    EnumVariant,
)
from angr.sim_type import SimTypeNum


class RustSimTypeTempRef(RustSimType, SimTypeTempRef):
    def __init__(self, typevar):
        super().__init__(typevar)

    def repr(self, name=None, full=0, memo=None, indent=0):
        return "<RustSimTypeTempRef>"


class RustTypeTranslator(TypeTranslator):
    """
    Bidirectional translator between Rust SimTypes and type constants.

    - tc2simtype / concretize: TypeConstant -> RustSimType
    - simtype2tc / lift: RustSimType -> TypeConstant
    """

    def __init__(self, project=None, arch=None):
        self.project = project
        self.arch = arch

        self.translated: dict[TypeConstant, SimType] = {}
        self.translated_simtypes: dict[SimType, TypeConstant] = {}
        self.structs = {}
        self._struct_ctr = count()
        self.memo = {}
        self.named_struct_id_counter = count(133337)
        self.struct_name_to_idx = {}

        # will be updated every time .tc2simtype() is called
        self._has_nonexistent_ref = False

    # ----------------------------------------------------------------
    # TypeConstant -> RustSimType (tc2simtype direction)
    # ----------------------------------------------------------------

    def _translate_Pointer64(self, tc):
        if isinstance(tc.basetype, typeconsts.BottomType):
            internal = sim_type.SimTypeBottom(label="void").with_arch(self.arch)
        else:
            internal = self._tc2simtype(tc.basetype)
        return RustSimTypeReference(internal).with_arch(self.arch)

    def _translate_Pointer32(self, tc):
        return self._translate_Pointer64(tc)

    def _translate_Int8(self, tc):
        return RustSimTypeInt(size=8, signed=False).with_arch(self.arch)

    def _translate_Int16(self, tc):
        return RustSimTypeInt(size=16, signed=False).with_arch(self.arch)

    def _translate_Int32(self, tc):
        return RustSimTypeInt(size=32, signed=False).with_arch(self.arch)

    def _translate_Int64(self, tc):
        return RustSimTypeInt(size=64, signed=False).with_arch(self.arch)

    def _translate_Int128(self, tc):
        return RustSimTypeInt(size=128, signed=False).with_arch(self.arch)

    def _translate_IntVar(self, tc: IntVar):
        return RustSimTypeInt(size=tc.size, signed=False).with_arch(self.arch)

    def _translate_Array(self, tc: typeconsts.Array):
        elem_type = self._tc2simtype(tc.element)
        # TODO: Maybe array should be translated to struct?
        return RustSimTypeInt(size=64, signed=False).with_arch(self.arch)

    def _translate_Struct(self, tc):
        if tc in self.structs:
            return self.structs[tc]

        if tc.name:
            name = tc.name
        else:
            name = self.struct_name()

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

    def _translate_Result(self, tc: typeconsts.RustEnum):
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

    def _translate_Option(self, tc: typeconsts.RustEnum):
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

    def _translate_RustEnum(self, tc: typeconsts.RustEnum):
        if tc.name.startswith("core::result::Result<") or tc.name.startswith("Result<"):
            return self._translate_Result(tc)
        if tc.name.startswith("core::option::Option<") or tc.name.startswith("Option<"):
            return self._translate_Option(tc)
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
            handler = RustTypeConstHandlers[tc.__class__]
        except KeyError:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        translated = handler(self, tc)
        return translated

    # ----------------------------------------------------------------
    # RustSimType -> TypeConstant (simtype2tc / lift direction)
    # ----------------------------------------------------------------

    def _simtype2tc(self, simtype):
        if simtype in self.translated_simtypes:
            return self.translated_simtypes[simtype]
        try:
            handler = RustSimTypeHandlers[simtype.__class__]
            return handler(self, simtype)
        except KeyError:
            # fall back to parent for non-Rust types
            return super()._simtype2tc(simtype)

    def _translate_RustSimTypeInt(self, ty: RustSimTypeInt):
        if ty.size == 8:
            return typeconsts.Int8()
        if ty.size == 16:
            return typeconsts.Int16()
        if ty.size == 32:
            return typeconsts.Int32()
        if ty.size == 64:
            return typeconsts.Int64()
        if ty.size == 128:
            return typeconsts.Int128()
        return IntVar(size=ty.size)

    def _translate_RustSimStruct(self, ty: RustSimStruct) -> TypeConstant | typeconsts.BottomType:
        if ty in self.memo:
            return self.memo[ty]

        obj = typeconsts.Struct(fields={}, name=ty.name)
        self.memo[ty] = obj
        converted_fields = {}
        field_names = {}
        ty_offsets = ty.offsets
        for field_name, simtype in ty.fields.items():
            if field_name not in ty_offsets:
                return typeconsts.BottomType()
            converted_fields[ty_offsets[field_name]] = self.simtype2tc(simtype)
            field_names[ty_offsets[field_name]] = field_name
        obj.fields = converted_fields
        obj.field_names = field_names
        return obj

    def _translate_RustSimEnum(self, ty: RustSimEnum):
        obj = typeconsts.RustEnum(ty.name, [self._translate_RustEnumVariant(variant) for variant in ty.variants])
        self.memo[ty] = obj
        return obj

    def _translate_RustEnumVariant(self, variant):
        return typeconsts.EnumVariant(
            variant.name,
            [(self.simtype2tc(field_ty), field_name) for field_ty, field_name in variant.fields],
            variant.discriminant,
            variant.discriminant_size,
            variant.size,
        )

    def _translate_RustSimTypeReference(self, ty: RustSimTypeReference):
        base = self._simtype2tc(ty.pts_to)
        if self.arch.bits == 32:
            return typeconsts.Pointer32(base)
        return typeconsts.Pointer64(base)

    def _translate_RustSimTypeArray(self, ty: RustSimTypeArray):
        elem_type = self._simtype2tc(ty.elem_type)
        return typeconsts.Array(elem_type, count=ty.length)

    # ----------------------------------------------------------------
    # Utility
    # ----------------------------------------------------------------

    def ctype2rust(self, simtype: sim_type.SimType | RustSimType):
        if isinstance(simtype, RustSimType):
            return simtype
        if isinstance(simtype, SimTypeNum):
            simtype = RustSimTypeInt(size=simtype.size, signed=simtype.signed).with_arch(self.arch)
        tc = self.simtype2tc(simtype)
        return self.tc2simtype(tc)[0]


RustTypeConstHandlers = {
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
    typeconsts.RustEnum: RustTypeTranslator._translate_RustEnum,
}


RustSimTypeHandlers = {
    RustSimTypeInt: RustTypeTranslator._translate_RustSimTypeInt,
    RustSimTypeSize: RustTypeTranslator._translate_RustSimTypeInt,
    RustSimTypeReference: RustTypeTranslator._translate_RustSimTypeReference,
    RustSimStruct: RustTypeTranslator._translate_RustSimStruct,
    RustSimTypeArray: RustTypeTranslator._translate_RustSimTypeArray,
    RustSimEnum: RustTypeTranslator._translate_RustSimEnum,
    RustSimTypeResult: RustTypeTranslator._translate_RustSimEnum,
    RustSimTypeOption: RustTypeTranslator._translate_RustSimEnum,
}
