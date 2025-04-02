from collections import OrderedDict

from ailment import Const

from ..definitions.structs import SimpleMessage, StrSlice, ArrayReference
from ..knowledge_plugins.known_structs import KnownStructs
from ..optimization_passes.utils import extract_str_from_addr
from ..utils.library import demangle
from ..utils.ail_util import unwrap_stack_vvar_reference
from ...analyses import Analysis, AnalysesHub
from ..mixins import CFAMixin, DFAMixin
from ..sim_type import RustSimTypeOption, RustSimStruct, RustSimTypeReference, RustSimTypeBottom


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


class ArgumentsLayoutInference(LayoutInference, CFAMixin, DFAMixin):
    def __init__(self, project):
        super().__init__(project)
        CFAMixin.__init__(self, None, project)
        DFAMixin.__init__(self)

    def _recover_layout_from_panic_fmt_callsite(self, block, call):
        arg_vvar = unwrap_stack_vvar_reference(call.args[0])
        stack_writes = {}
        for stmt in block.statements:
            dst_vvar, src_data = self.extract_write_to_stack_vvar(stmt)
            if dst_vvar and src_data:
                stack_writes[dst_vvar.stack_offset] = src_data
        fields = OrderedDict()
        for i in range(3):
            cur_offset = arg_vvar.stack_offset + 2 * i * self.project.arch.bytes
            data = stack_writes[cur_offset]
            if isinstance(data, Const) and data.value == 0:
                fields["fmt"] = RustSimTypeOption(ArrayReference(RustSimTypeBottom()), none_discriminant=None)
            elif cur_offset + self.project.arch.bytes in stack_writes:
                ptr_data = data
                len_data = stack_writes[cur_offset + self.project.arch.bytes]
                if isinstance(ptr_data, Const) and isinstance(len_data, Const) and len_data.value == 2:
                    if extract_str_from_addr(self.project, ptr_data.value) == "failed printing to ":
                        fields["pieces"] = ArrayReference(StrSlice())
                elif (
                    (ptr_vvar := unwrap_stack_vvar_reference(ptr_data))
                    and isinstance(len_data, Const)
                    and len_data.value == 2
                ):
                    ptr_vvar_offset = ptr_vvar.stack_offset
                    argument_ty = None
                    if ptr_vvar_offset in stack_writes and ptr_vvar_offset + self.project.arch.bytes in stack_writes:
                        if isinstance(stack_writes[ptr_vvar_offset], Const):
                            argument_ty = RustSimStruct(
                                name="Argument",
                                fields={
                                    "formatter": RustSimTypeReference(RustSimTypeBottom()),
                                    "value": RustSimTypeReference(RustSimTypeBottom()),
                                },
                            )
                        elif isinstance(stack_writes[ptr_vvar_offset + self.project.arch.bytes], Const):
                            argument_ty = RustSimStruct(
                                name="Argument",
                                fields={
                                    "value": RustSimTypeReference(RustSimTypeBottom()),
                                    "formatter": RustSimTypeReference(RustSimTypeBottom()),
                                },
                            )
                    if argument_ty:
                        self.cache_layout(KnownStructs.ARGUMENT, argument_ty)
                        fields["args"] = ArrayReference(argument_ty)
        if len(fields) == 3:
            arguments_ty = RustSimStruct(name="Arguments", fields=fields)
            self.cache_layout(KnownStructs.ARGUMENTS, arguments_ty)

    def infer_layout(self):
        print_func = None
        for addr in self.project.kb.functions:
            func = self.project.kb.functions[addr]
            if demangle(func.name) == "std::io::stdio::_print":
                print_func = func
                break
        if print_func:
            cfg = self.project.kb.cfgs.get_most_accurate()
            clinic = self.project.analyses.Clinic(print_func, cfg=cfg)
            for block in clinic.graph.nodes:
                call = self.terminal_call(block)
                if self.match_call(call, ["core::panicking::panic_fmt"]) and call.args and len(call.args) > 0:
                    self._recover_layout_from_panic_fmt_callsite(block, call)
                    break


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
        ArgumentsLayoutInference(self.project).infer_layout()


AnalysesHub.register_default("StructMemoryLayout", StructMemoryLayoutAnalysis)
