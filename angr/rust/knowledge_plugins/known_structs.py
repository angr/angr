from typing import Optional
from collections import OrderedDict

from angr.ailment import Const

from ..optimization_passes.utils import extract_str_from_addr
from angr.rust.sim_type import (
    RustSimTypeReference,
    RustSimStruct,
    RustSimType,
    RustSimTypeArrayRef,
    RustSimTypeArray,
    RustSimTypeOption,
    RustSimTypeResult,
    RustSimEnum,
    EnumVariant,
)
from ...knowledge_plugins.plugin import KnowledgeBasePlugin


class StructMatcher:

    def __init__(self, project):
        self.project = project
        self._matchers = (self._match_Arguments,)

    def _match_Arguments(self, fields):
        arguments_ty = self.project.kb.known_structs["core::fmt::Arguments"].with_arch(self.project.arch)
        offsets = arguments_ty.offsets
        pieces_ptr_offset = offsets["pieces"]
        pieces_len_offset = pieces_ptr_offset + self.project.arch.bytes
        args_ptr_offset = offsets["args"]
        args_len_offset = args_ptr_offset + self.project.arch.bytes
        fmt_offset = offsets["fmt"]
        if (
            max(fields) < arguments_ty.size // 8
            and pieces_ptr_offset in fields
            and pieces_len_offset in fields
            and args_ptr_offset in fields
            and args_len_offset in fields
            and isinstance(fields[pieces_ptr_offset], Const)
            and isinstance(fields[pieces_len_offset], Const)
            and isinstance(fields[args_len_offset], Const)
            and 1 >= fields[pieces_len_offset].value - fields[args_len_offset].value >= 0
            and extract_str_from_addr(self.project, fields[pieces_ptr_offset].value) is not None
        ):
            if fmt_offset in fields:
                return arguments_ty
            elif (
                args_len_offset == fmt_offset - self.project.arch.bytes
                and isinstance(fields[args_len_offset], Const)
                and fields[args_len_offset].value == 0
                and fields[args_len_offset].size == 2 * self.project.arch.bytes
            ):
                return arguments_ty
        return None

    def match(self, fields):
        for matcher in self._matchers:
            result = matcher(fields)
            if result:
                return result
        return None


class TypeWalker:

    def __init__(self, handlers=None):
        self.updated = False
        self._handlers = {
            RustSimStruct: self._handle_Struct,
            RustSimTypeReference: self._handle_Reference,
            RustSimTypeArrayRef: self._handle_ArrayRef,
            RustSimTypeArray: self._handle_Array,
            RustSimTypeOption: self._handle_Option,
            RustSimTypeResult: self._handle_Result,
            RustSimEnum: self._handle_Enum,
        }
        if handlers:
            self._handlers.update(handlers)

    def _handle(self, ty: RustSimType):
        handler = self._handlers.get(type(ty), None)
        new_ty = ty
        if handler:
            new_ty = handler(ty)
            if new_ty != ty:
                self.updated = True
        return new_ty

    def _handle_Struct(self, ty: RustSimStruct):
        return RustSimStruct(
            OrderedDict([(field_name, self._handle(field_ty)) for field_name, field_ty in ty.fields.items()]),
            ty.name,
            ty._pack,
            ty._align,
        ).with_arch(ty._arch)

    def _handle_Reference(self, ty: RustSimTypeReference):
        return RustSimTypeReference(self._handle(ty.pts_to)).with_arch(ty._arch)

    def _handle_ArrayRef(self, ty: RustSimTypeArrayRef):
        return RustSimTypeArrayRef(self._handle(ty.ele_ty)).with_arch(ty._arch)

    def _handle_Array(self, ty: RustSimTypeArray):
        return RustSimTypeArray(self._handle(ty.elem_type), ty.length, ty.label).with_arch(ty._arch)

    def _handle_Option(self, ty: RustSimTypeOption):
        return RustSimTypeOption(
            ty.none_discriminant,
            ty.none_discriminant_size,
            self._handle(ty.some_type),
            ty.some_discriminant,
            ty.some_discriminant_size,
            ty.name,
        ).with_arch(ty._arch)

    def _handle_Result(self, ty: RustSimTypeResult):
        return RustSimTypeResult(
            self._handle(ty.ok_type),
            ty.ok_discriminant,
            ty.ok_discriminant_size,
            self._handle(ty.err_type),
            ty.err_discriminant,
            ty.err_discriminant_size,
            ty.name,
        ).with_arch(ty._arch)

    def _handle_Enum(self, ty: RustSimEnum):
        return RustSimEnum(
            ty.name,
            [
                EnumVariant(
                    variant.name,
                    [(self._handle(field_ty), field_name) for field_ty, field_name in variant.fields],
                    variant.discriminant,
                    variant.discriminant_size,
                )
                for variant in ty.variants
            ],
        ).with_arch(ty._arch)

    def walk(self, ty: RustSimType | None):
        return self._handle(ty)

    def walk_fields(self, ty: RustSimStruct | RustSimEnum):
        if isinstance(ty, RustSimStruct):
            return TypeWalker._handle_Struct(self, ty)
        elif isinstance(ty, RustSimTypeOption):
            return TypeWalker._handle_Option(self, ty)
        elif isinstance(ty, RustSimTypeResult):
            return TypeWalker._handle_Result(self, ty)
        elif isinstance(ty, RustSimEnum):
            return TypeWalker._handle_Enum(self, ty)
        return ty


class KnownStructs(KnowledgeBasePlugin):

    def __init__(self, kb):
        super().__init__(kb)
        self.known_struct_types = OrderedDict()

    def __iter__(self):
        return iter(self.known_struct_types)

    def __setitem__(self, key, value):
        self.known_struct_types[key] = value

    def __getitem__(self, item):
        return self.known_struct_types.get(item, None)

    def __contains__(self, item):
        return item in self.known_struct_types

    def match_with_known_structs(self, fields) -> Optional[RustSimStruct]:
        return StructMatcher(self._kb._project).match(fields)


KnowledgeBasePlugin.register_default("known_structs", KnownStructs)
