from typing import Dict, Union
from itertools import count

from ... import sim_type
from ...sim_type import SimType
from . import typeconsts
from .typeconsts import TypeConstant


class SimTypeTempRef(sim_type.SimType):
    def __init__(self, typevar):
        super().__init__()
        self.typevar = typevar

    def c_repr(self):
        return "<SimTypeTempRef>"


class TypeTranslator:
    """
    Translate type variables to SimType equivalence.
    """

    def __init__(self, arch=None):
        self.arch = arch

        self.translated: Dict[TypeConstant, SimType] = {}
        self.translated_simtypes: Dict[SimType, TypeConstant] = {}
        self.structs = {}
        self._struct_ctr = count()

        # will be updated every time .translate() is called
        self._has_nonexistent_ref = False

    #
    # Naming
    #

    def struct_name(self):
        return "struct_%d" % next(self._struct_ctr)

    #
    # Type translation
    #

    def tc2simtype(self, tc):
        self._has_nonexistent_ref = False
        return self._tc2simtype(tc), self._has_nonexistent_ref

    def _tc2simtype(self, tc):
        if tc is None:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        try:
            handler = TypeConstHandlers[tc.__class__]
        except KeyError:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        translated = handler(self, tc)
        return translated

    def simtype2tc(self, simtype: sim_type.SimType) -> typeconsts.TypeConstant:
        return self._simtype2tc(simtype)

    def _simtype2tc(self, simtype: sim_type.SimType) -> typeconsts.TypeConstant:
        if simtype in self.translated_simtypes:
            return self.translated_simtypes[simtype]
        try:
            handler = SimTypeHandlers[simtype.__class__]
            return handler(self, simtype)
        except KeyError:
            return typeconsts.BottomType()

    #
    # Typehoon type handlers
    #

    def _translate_Pointer64(self, tc):
        if isinstance(tc.basetype, typeconsts.BottomType):
            # void *
            internal = sim_type.SimTypeBottom(label="void").with_arch(self.arch)
        else:
            internal = self._tc2simtype(tc.basetype)
        return sim_type.SimTypePointer(internal).with_arch(self.arch)

    def _translate_Pointer32(self, tc):
        if isinstance(tc.basetype, typeconsts.BottomType):
            # void *
            internal = sim_type.SimTypeBottom(label="void").with_arch(self.arch)
        else:
            internal = self._tc2simtype(tc.basetype)
        return sim_type.SimTypePointer(internal).with_arch(self.arch)

    def _translate_Array(self, tc: typeconsts.Array):
        elem_type = self._tc2simtype(tc.element)
        return sim_type.SimTypeArray(elem_type, length=tc.count).with_arch(self.arch)

    def _translate_Struct(self, tc):
        if tc in self.structs:
            return self.structs[tc]

        s = sim_type.SimStruct({}, name=self.struct_name()).with_arch(self.arch)
        self.structs[tc] = s

        next_offset = 0
        for offset, typ in sorted(tc.fields.items(), key=lambda item: item[0]):
            if offset > next_offset:
                # we need padding!
                padding_size = offset - next_offset
                s.fields["padding_%x" % next_offset] = sim_type.SimTypeFixedSizeArray(
                    sim_type.SimTypeChar(signed=False).with_arch(self.arch), padding_size
                ).with_arch(self.arch)

            translated_type = self._tc2simtype(typ)
            if isinstance(translated_type, sim_type.SimTypeBottom):
                # we cannot have bottom types in a struct since that would mess with offsets of all future types
                # for now, we replace it with an unsigned char
                translated_type = sim_type.SimTypeChar(signed=False).with_arch(self.arch)

            s.fields["field_%x" % offset] = translated_type

            if isinstance(translated_type, SimTypeTempRef):
                next_offset = self.arch.bytes + offset
            else:
                next_offset = translated_type.size // self.arch.byte_width + offset

        return s

    def _translate_Int8(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeChar(signed=False).with_arch(self.arch)

    def _translate_Int16(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeShort(signed=False).with_arch(self.arch)

    def _translate_Int32(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeInt(signed=False).with_arch(self.arch)

    def _translate_Int64(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeLongLong(signed=False).with_arch(self.arch)

    def _translate_Int128(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeNum(128, signed=False).with_arch(self.arch)

    def _translate_TypeVariableReference(self, tc):
        if tc.typevar in self.translated:
            return self.translated[tc.typevar]

        self._has_nonexistent_ref = True
        return SimTypeTempRef(tc.typevar)

    #
    # Backpatching
    #

    def backpatch(self, st, translated):
        """

        :param sim_type.SimType st:
        :param dict translated:
        :return:
        """

        if isinstance(st, sim_type.SimTypePointer):
            self.backpatch(st.pts_to, translated)

        elif isinstance(st, sim_type.SimStruct):
            fields_patch = {}
            for offset, fld in st.fields.items():
                if isinstance(fld, SimTypeTempRef) and fld.typevar in translated:
                    fields_patch[offset] = translated[fld.typevar]
                st.fields.update(fields_patch)

    #
    # SimType handlers
    #

    def _translate_SimTypeInt(self, st: sim_type.SimTypeInt) -> typeconsts.Int32:
        return typeconsts.Int32()

    def _translate_SimTypeLong(self, st: sim_type.SimTypeLong) -> typeconsts.Int32:
        return typeconsts.Int32()

    def _translate_SimTypeLongLong(self, st: sim_type.SimTypeLongLong) -> typeconsts.Int64:
        return typeconsts.Int64()

    def _translate_SimTypeChar(self, st: sim_type.SimTypeChar) -> typeconsts.Int8:
        return typeconsts.Int8()

    def _translate_SimStruct(self, st: sim_type.SimStruct) -> typeconsts.Struct:
        fields = {}
        offsets = st.offsets
        for name, ty in st.fields.items():
            offset = offsets[name]
            fields[offset] = self._simtype2tc(ty)

        return typeconsts.Struct(fields=fields)

    def _translate_SimTypeArray(self, st: sim_type.SimTypeArray) -> typeconsts.Array:
        elem_type = self._simtype2tc(st.elem_type)
        array_tc = typeconsts.Array(elem_type, count=st.length)
        return array_tc

    def _translate_SimTypePointer(
        self, st: sim_type.SimTypePointer
    ) -> Union[typeconsts.Pointer32, typeconsts.Pointer64]:
        base = self._simtype2tc(st.pts_to)
        if self.arch.bits == 32:
            return typeconsts.Pointer32(base)
        elif self.arch.bits == 64:
            return typeconsts.Pointer64(base)
        raise TypeError("Unsupported pointer size %d" % self.arch.bits)


TypeConstHandlers = {
    typeconsts.Pointer64: TypeTranslator._translate_Pointer64,
    typeconsts.Pointer32: TypeTranslator._translate_Pointer32,
    typeconsts.Array: TypeTranslator._translate_Array,
    typeconsts.Struct: TypeTranslator._translate_Struct,
    typeconsts.Int8: TypeTranslator._translate_Int8,
    typeconsts.Int16: TypeTranslator._translate_Int16,
    typeconsts.Int32: TypeTranslator._translate_Int32,
    typeconsts.Int64: TypeTranslator._translate_Int64,
    typeconsts.Int128: TypeTranslator._translate_Int128,
    typeconsts.TypeVariableReference: TypeTranslator._translate_TypeVariableReference,
}


SimTypeHandlers = {
    sim_type.SimTypePointer: TypeTranslator._translate_SimTypePointer,
    sim_type.SimTypeInt: TypeTranslator._translate_SimTypeInt,
    sim_type.SimTypeLong: TypeTranslator._translate_SimTypeLong,
    sim_type.SimTypeLongLong: TypeTranslator._translate_SimTypeLongLong,
    sim_type.SimTypeChar: TypeTranslator._translate_SimTypeChar,
    sim_type.SimStruct: TypeTranslator._translate_SimStruct,
    sim_type.SimTypeArray: TypeTranslator._translate_SimTypeArray,
}
