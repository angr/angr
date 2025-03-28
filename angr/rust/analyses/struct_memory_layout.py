from collections import OrderedDict

from ..definitions.structs import SimpleMessage
from ..knowledge_plugins.known_structs import KnownStructs
from ..optimization_passes.utils import extract_str_from_addr
from ...analyses import Analysis, AnalysesHub


class LayoutInference:

    def __init__(self, project):
        self.project = project

    def get_integer(self, addr):
        memory = self.project.loader.memory
        try:
            value = memory.unpack(addr, self.project.arch.struct_fmt())[0]
        except KeyError:
            return None
        return value

    def cache_layout(self, name, struct_ty):
        self.project.kb.known_structs[name] = struct_ty.with_arch(self.project.arch)


class SimpleMessageLayoutInference(LayoutInference):
    ERROR_MESSAGES = (
        "stream did not contain valid UTF-8",
        "failed to fill whole buffer",
        "The number of hardware threads is not known for the target platform",
        "operation not supported on this platform",
        "failed to write whole buffer",
        "cannot set a 0 duration timeout",
    )

    def __init__(self, project):
        super().__init__(project)

    def infer_layout(self, addr):
        if KnownStructs.SIMPLE_MESSAGE in self.project.kb.known_structs:
            return True
        kind = self.get_integer(addr)
        if kind is not None and 0 <= kind < 42:
            message = extract_str_from_addr(self.project, addr + self.project.arch.bytes)
            if message in SimpleMessageLayoutInference.ERROR_MESSAGES:
                self.cache_layout(KnownStructs.SIMPLE_MESSAGE, SimpleMessage())
                return True
        kind = self.get_integer(addr + 2 * self.project.arch.bytes)
        if kind is not None and 0 <= kind < 42:
            message = extract_str_from_addr(self.project, addr)
            if message in SimpleMessageLayoutInference.ERROR_MESSAGES:
                struct_ty = SimpleMessage()
                struct_ty.fields = OrderedDict(reversed(struct_ty.fields.items()))
                self.cache_layout(KnownStructs.SIMPLE_MESSAGE, struct_ty)
                return True
        return False

    def is_const_simple_message(self, addr):
        struct_ty = self.project.kb.known_structs[KnownStructs.SIMPLE_MESSAGE]
        if struct_ty:
            reordered = struct_ty.offsets["kind"] != 0
            if reordered:
                kind = self.get_integer(addr + 2 * self.project.arch.bytes)
                message = extract_str_from_addr(self.project, addr)
            else:
                kind = self.get_integer(addr)
                message = extract_str_from_addr(self.project, addr + self.project.arch.bytes)
            if kind is not None and 0 <= kind < 42 and message in SimpleMessageLayoutInference.ERROR_MESSAGES:
                return True
        return False


class StructMemoryLayoutAnalysis(Analysis):
    def __init__(self, scan_data_section=False):
        self.scan_data_section = scan_data_section
        self._analyze()

    def _analyze(self):
        if self.scan_data_section:
            for section in self.project.loader.main_object.sections:
                if section.is_readable and not section.is_executable:
                    for addr in range(section.vaddr, section.vaddr + section.memsize, self.project.arch.bytes):
                        if self.kb.xrefs.get_xrefs_by_dst(addr):
                            SimpleMessageLayoutInference(self.project).infer_layout(addr)


AnalysesHub.register_default("StructMemoryLayout", StructMemoryLayoutAnalysis)
