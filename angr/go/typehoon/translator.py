from __future__ import annotations

from collections import OrderedDict

from angr import sim_type
from angr.analyses.typehoon import typeconsts
from angr.analyses.typehoon.translator import SimTypeTempRef, TypeTranslator
from angr.analyses.typehoon.typeconsts import IntVar, TypeConstant
from angr.go.sim_type import (
    GoSimStruct,
    GoSimType,
    GoSimTypeArray,
    GoSimTypeBool,
    GoSimTypeChan,
    GoSimTypeFloat,
    GoSimTypeFunc,
    GoSimTypeFunction,
    GoSimTypeInt,
    GoSimTypeInterface,
    GoSimTypeMap,
    GoSimTypePointer,
    GoSimTypeSlice,
    GoSimTypeString,
    GoSimTypeTuple,
    GoSimTypeUnsafePointer,
    go_int,
)


class GoTypeTranslator(TypeTranslator):
    """
    Bidirectional translator between Go SimTypes and type constants.
    """

    #
    # TypeConstant -> GoSimType
    #

    def _translate_Pointer64(self, tc):
        if isinstance(tc.basetype, typeconsts.BottomType):
            return GoSimTypeUnsafePointer().with_arch(self.arch)
        return GoSimTypePointer(self._tc2simtype(tc.basetype)).with_arch(self.arch)

    def _translate_Pointer32(self, tc):
        return self._translate_Pointer64(tc)

    def _translate_Int8(self, tc):
        return go_int(self.arch, 8, False)

    def _translate_Int16(self, tc):
        return go_int(self.arch, 16, True)

    def _translate_Int32(self, tc):
        return go_int(self.arch, 32, True)

    def _translate_Int64(self, tc):
        # word-sized integers are far more often ``int`` than ``int64`` in Go source
        return go_int(self.arch, 64, True, "int" if self.arch.bits == 64 else None)

    def _translate_Int128(self, tc):
        return GoSimTypeInt(128, False).with_arch(self.arch)

    def _translate_IntVar(self, tc: IntVar):
        return GoSimTypeInt(tc.size, False).with_arch(self.arch)

    def _translate_SInt8(self, tc):
        return go_int(self.arch, 8, True)

    def _translate_UInt8(self, tc):
        return go_int(self.arch, 8, False)

    def _translate_SInt16(self, tc):
        return go_int(self.arch, 16, True)

    def _translate_UInt16(self, tc):
        return go_int(self.arch, 16, False)

    def _translate_SInt32(self, tc):
        return go_int(self.arch, 32, True)

    def _translate_UInt32(self, tc):
        return go_int(self.arch, 32, False)

    def _translate_SInt64(self, tc):
        return go_int(self.arch, 64, True, "int" if self.arch.bits == 64 else None)

    def _translate_UInt64(self, tc):
        return go_int(self.arch, 64, False, "uint" if self.arch.bits == 64 else None)

    def _translate_Float32(self, tc):
        return GoSimTypeFloat(32).with_arch(self.arch)

    def _translate_Float64(self, tc):
        return GoSimTypeFloat(64).with_arch(self.arch)

    def _translate_Array(self, tc: typeconsts.Array):
        elem = self._tc2simtype(tc.element)
        return GoSimTypeArray(elem, tc.count).with_arch(self.arch)

    def _translate_Struct(self, tc: typeconsts.Struct):
        if tc in self.structs:
            return self.structs[tc]
        if tc.name is not None:
            known = self.known_structs.get(tc.name)
            if known is not None:
                self.structs[tc] = known
                return known

        name = tc.name or self.struct_name()
        s = GoSimStruct(OrderedDict(), go_name=name).with_arch(self.arch)
        s._def_order = next(self._struct_def_ctr)
        self.structs[tc] = s

        next_offset = 0
        for offset, typ in sorted(tc.fields.items(), key=lambda item: item[0]):
            if offset > next_offset:
                s.fields[f"padding_{next_offset:x}"] = GoSimTypeArray(
                    go_int(self.arch, 8, False), offset - next_offset
                ).with_arch(self.arch)
            translated = self._tc2simtype(typ)
            if isinstance(translated, sim_type.SimTypeBottom):
                translated = go_int(self.arch, 8, False)
            field_name = tc.field_names[offset] if tc.field_names and offset in tc.field_names else f"field_{offset:x}"
            s.fields[field_name] = translated
            if isinstance(translated, SimTypeTempRef):
                next_offset = self.arch.bytes + offset
            else:
                next_offset = (translated.size or 0) // self.arch.byte_width + offset
        return s

    def _tc2simtype(self, tc):
        if tc is None:
            return sim_type.SimTypeBottom().with_arch(self.arch)
        handler = GoTypeConstHandlers.get(tc.__class__)
        if handler is None:
            return super()._tc2simtype(tc)
        return handler(self, tc)

    #
    # GoSimType -> TypeConstant
    #

    def _simtype2tc(self, simtype):
        if simtype in self.translated_simtypes:
            return self.translated_simtypes[simtype]
        handler = GoSimTypeHandlers.get(simtype.__class__)
        if handler is None:
            return super()._simtype2tc(simtype)
        return handler(self, simtype)

    def _translate_GoSimTypeInt(self, ty: GoSimTypeInt):
        return {8: typeconsts.Int8, 16: typeconsts.Int16, 32: typeconsts.Int32, 64: typeconsts.Int64}.get(
            ty.size, lambda: IntVar(size=ty.size)
        )()

    def _translate_GoSimTypeFloat(self, ty: GoSimTypeFloat):
        return typeconsts.Float64() if ty.size == 64 else typeconsts.Float32()

    def _translate_GoSimTypePointer(self, ty: GoSimTypePointer):
        pts_to = ty.pts_to
        base = typeconsts.BottomType() if pts_to is None or isinstance(pts_to, sim_type.SimTypeBottom) else None
        if base is None:
            base = self._simtype2tc(pts_to)
        return typeconsts.Pointer32(base) if self.arch.bits == 32 else typeconsts.Pointer64(base)

    def _translate_GoSimTypeArray(self, ty: GoSimTypeArray):
        return typeconsts.Array(self._simtype2tc(ty.elem_type), count=ty.length)

    def _translate_GoSimStruct(self, ty: GoSimStruct) -> TypeConstant:
        # builtins (string, slices, interfaces, tuples) and named structs must come back unchanged
        name = ty.go_repr() if (ty.go_name is not None or _is_builtin_struct(ty)) else None
        key = f"go_struct_{name}" if name is not None else f"go_struct_anon_{id(ty)}"
        if key in self.memo:
            return self.memo[key]
        if name is not None:
            self.known_structs.setdefault(name, ty)
        obj = typeconsts.Struct(fields={}, name=name)
        self.memo[key] = obj
        offsets = ty.offsets
        fields = {}
        field_names = {}
        for field_name, fty in ty.fields.items():
            if field_name not in offsets:
                continue
            fields[offsets[field_name]] = self._simtype2tc(fty)
            field_names[offsets[field_name]] = field_name
        obj.fields = fields
        obj.field_names = field_names
        return obj

    def _translate_GoSimTypeFunction(self, ty: GoSimTypeFunction):  # pylint:disable=unused-argument
        return typeconsts.BottomType()

    #
    # Utility
    #

    def ctype2go(self, simtype: sim_type.SimType) -> sim_type.SimType:
        """Re-express a C-flavored SimType with Go SimTypes."""
        if isinstance(simtype, GoSimType):
            return simtype
        if isinstance(simtype, sim_type.SimTypeBottom):
            return simtype
        return self.tc2simtype(self.simtype2tc(simtype))[0]


def _is_builtin_struct(ty) -> bool:
    return isinstance(ty, (GoSimTypeString, GoSimTypeSlice, GoSimTypeInterface, GoSimTypeTuple))


GoTypeConstHandlers = {
    typeconsts.Pointer64: GoTypeTranslator._translate_Pointer64,
    typeconsts.Pointer32: GoTypeTranslator._translate_Pointer32,
    typeconsts.Array: GoTypeTranslator._translate_Array,
    typeconsts.Struct: GoTypeTranslator._translate_Struct,
    typeconsts.Int8: GoTypeTranslator._translate_Int8,
    typeconsts.Int16: GoTypeTranslator._translate_Int16,
    typeconsts.Int32: GoTypeTranslator._translate_Int32,
    typeconsts.Int64: GoTypeTranslator._translate_Int64,
    typeconsts.Int128: GoTypeTranslator._translate_Int128,
    typeconsts.IntVar: GoTypeTranslator._translate_IntVar,
    typeconsts.SInt8: GoTypeTranslator._translate_SInt8,
    typeconsts.UInt8: GoTypeTranslator._translate_UInt8,
    typeconsts.SInt16: GoTypeTranslator._translate_SInt16,
    typeconsts.UInt16: GoTypeTranslator._translate_UInt16,
    typeconsts.SInt32: GoTypeTranslator._translate_SInt32,
    typeconsts.UInt32: GoTypeTranslator._translate_UInt32,
    typeconsts.SInt64: GoTypeTranslator._translate_SInt64,
    typeconsts.UInt64: GoTypeTranslator._translate_UInt64,
    typeconsts.Float32: GoTypeTranslator._translate_Float32,
    typeconsts.Float64: GoTypeTranslator._translate_Float64,
}

GoSimTypeHandlers = {
    GoSimTypeInt: GoTypeTranslator._translate_GoSimTypeInt,
    GoSimTypeBool: GoTypeTranslator._translate_GoSimTypeInt,
    GoSimTypeFloat: GoTypeTranslator._translate_GoSimTypeFloat,
    GoSimTypePointer: GoTypeTranslator._translate_GoSimTypePointer,
    GoSimTypeUnsafePointer: GoTypeTranslator._translate_GoSimTypePointer,
    GoSimTypeMap: GoTypeTranslator._translate_GoSimTypePointer,
    GoSimTypeChan: GoTypeTranslator._translate_GoSimTypePointer,
    GoSimTypeFunc: GoTypeTranslator._translate_GoSimTypePointer,
    GoSimTypeArray: GoTypeTranslator._translate_GoSimTypeArray,
    GoSimStruct: GoTypeTranslator._translate_GoSimStruct,
    GoSimTypeString: GoTypeTranslator._translate_GoSimStruct,
    GoSimTypeSlice: GoTypeTranslator._translate_GoSimStruct,
    GoSimTypeInterface: GoTypeTranslator._translate_GoSimStruct,
    GoSimTypeTuple: GoTypeTranslator._translate_GoSimStruct,
    GoSimTypeFunction: GoTypeTranslator._translate_GoSimTypeFunction,
}
