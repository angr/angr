
from itertools import count

from ... import sim_type
from . import typeconsts


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

        self.translated = { }
        self.structs = { }
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

    def translate(self, tc):

        self._has_nonexistent_ref = False
        return self._translate(tc), self._has_nonexistent_ref

    def _translate(self, tc):

        if tc is None:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        try:
            handler = TypeConstHandlers[tc.__class__]
        except KeyError:
            return sim_type.SimTypeBottom().with_arch(self.arch)

        translated = handler(self, tc)
        return translated

    def _translate_Pointer64(self, tc):

        if isinstance(tc.basetype, typeconsts.BottomType):
            # void *
            internal = sim_type.SimTypeBottom(label="void").with_arch(self.arch)
        else:
            internal = self._translate(tc.basetype)
        return sim_type.SimTypePointer(internal).with_arch(self.arch)

    def _translate_Array(self, tc: typeconsts.Array):
        elem_type = self._translate(tc.element)
        return sim_type.SimTypeArray(elem_type, length=tc.count).with_arch(self.arch)

    def _translate_Struct(self, tc):

        if tc in self.structs:
            return self.structs[tc]

        s = sim_type.SimStruct({}, name=self.struct_name()).with_arch(self.arch)
        self.structs[tc] = s

        for offset, typ in tc.fields.items():
            s.fields["field_%x" % offset] = self._translate(typ)

        return s

    def _translate_Int8(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeChar(signed=False).with_arch(self.arch)

    def _translate_Int16(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeShort(signed=False).with_arch(self.arch)

    def _translate_Int32(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeInt(signed=False).with_arch(self.arch)

    def _translate_Int64(self, tc):  # pylint:disable=unused-argument
        return sim_type.SimTypeLongLong(signed=False).with_arch(self.arch)

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
            fields_patch = { }
            for offset, fld in st.fields.items():
                if isinstance(fld, SimTypeTempRef) and fld.typevar in translated:
                    fields_patch[offset] = translated[fld.typevar]
                st.fields.update(fields_patch)


TypeConstHandlers = {
    typeconsts.Pointer64: TypeTranslator._translate_Pointer64,
    typeconsts.Array: TypeTranslator._translate_Array,
    typeconsts.Struct: TypeTranslator._translate_Struct,
    typeconsts.Int8: TypeTranslator._translate_Int8,
    typeconsts.Int16: TypeTranslator._translate_Int16,
    typeconsts.Int32: TypeTranslator._translate_Int32,
    typeconsts.Int64: TypeTranslator._translate_Int64,
    typeconsts.TypeVariableReference: TypeTranslator._translate_TypeVariableReference,
}
