from typing import Optional

from angr.ailment import Const

from angr.rust.definitions.structs import default_structs
from ..optimization_passes.utils import extract_str_from_addr
from ..sim_type import RustSimStruct
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
            and fmt_offset in fields
            and isinstance(fields[pieces_ptr_offset], Const)
            and isinstance(fields[pieces_len_offset], Const)
            and isinstance(fields[args_len_offset], Const)
            and 1 >= fields[pieces_len_offset].value - fields[args_len_offset].value >= 0
            and extract_str_from_addr(self.project, fields[pieces_ptr_offset].value) is not None
        ):
            return arguments_ty
        return None

    def match(self, fields):
        for matcher in self._matchers:
            result = matcher(fields)
            if result:
                return result
        return None


class KnownStructs(KnowledgeBasePlugin):

    def __init__(self, kb):
        super().__init__(kb)
        self.known_struct_types = dict(default_structs)
        self._calibrated_structs = set()

    def __iter__(self):
        return iter(self.known_struct_types)

    def __setitem__(self, key, value):
        self.known_struct_types[key] = value

    def __getitem__(self, item):
        return self.known_struct_types.get(item, None)

    def __contains__(self, item):
        return item in self.known_struct_types

    def is_calibrated(self, struct_name):
        return struct_name in self._calibrated_structs

    def update(self, struct_name, struct_ty):
        self._calibrated_structs.add(struct_name)
        self.known_struct_types[struct_name] = struct_ty

    def match_with_known_structs(self, fields) -> Optional[RustSimStruct]:
        return StructMatcher(self._kb._project).match(fields)


KnowledgeBasePlugin.register_default("known_structs", KnownStructs)
