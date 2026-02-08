import logging
from collections import defaultdict, deque
from typing import Tuple

from angr.analyses import Analysis, AnalysesHub
from angr.knowledge_plugins import KnowledgeBasePlugin
from angr.ailment import Block
from angr.ailment.expression import Const, VirtualVariable, StringLiteral, Struct, Array
from angr.ailment.statement import Call, FunctionLikeMacro, Store
from angr.rust.optimization_passes.utils import extract_str_from_addr
from angr.rust.utils.ail import unwrap_stack_vvar_reference, extract_vvar_and_offset
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.mixins import CFAMixin, DFAMixin, SRDAMixin, SSAVariableMixin
from angr.rust.optimization_passes.utils import CallRewriter
from angr.rust.sim_type import RustSimType, RustSimTypeSize
from angr.rust.utils.demangler import demangle, normalize

FORMAT_FUNCTIONS = (
    "std::io::stdio::_print",
    "std::io::stdio::_eprint",
    "alloc::fmt::format::format_inner",
    "alloc::fmt::format",
    "core::option::Option<T>::map_or_else",
    "core::panicking::panic_fmt",
    "std::io::Write::write_fmt",
    "core::fmt::write",
    "core::fmt::Write::write_fmt",
    "core::fmt::Formatter::write_fmt",
)

NEW_ARGUMENTS_FUNCTION = (
    "core::fmt::rt::<impl core::fmt::Arguments>::new_v1",
    "core::fmt::rt::<impl core::fmt::Arguments>::new_const",
)

NEW_ARGUMENT_FUNCTION = ("core::fmt::rt::Argument::new_display",)

l = logging.getLogger(__name__)


class FormatWrapperIdentification(Analysis):

    def __init__(self):
        self._format_wrappers = {}

        self._analyze()

    @property
    def format_wrappers(self):
        return self._format_wrappers

    def _analyze(self):
        format_functions_set = set(FORMAT_FUNCTIONS)
        for addr, func in self.project.kb.functions.items():
            normalized = normalize(func.name, monopolize=False, use_trait_name=False)
            if normalized in format_functions_set:
                self._format_wrappers[addr] = normalized
        queue = deque(self._format_wrappers.keys())
        while queue:
            func_addr = queue.popleft()
            callers = self.project.kb.callgraph.predecessors(func_addr)
            for caller_addr in callers:
                if caller_addr not in self._format_wrappers:
                    self._format_wrappers[caller_addr] = self._format_wrappers[func_addr]
                    queue.append(caller_addr)


AnalysesHub.register_default("FormatWrapperIdentification", FormatWrapperIdentification)


class FormatWrappers(KnowledgeBasePlugin):

    def __init__(self, kb):
        super().__init__(kb)
        self._analyzed = False
        self._format_wrappers = {}

    def resolve(self, addr):
        if not self._analyzed:
            self._format_wrappers = self._kb._project.analyses.FormatWrapperIdentification().format_wrappers
            self._analyzed = True
        return self._format_wrappers.get(addr, None)


KnowledgeBasePlugin.register_default("format_wrappers", FormatWrappers)


class FormatMacroSimplifier(OptimizationPass, CFAMixin, DFAMixin, SRDAMixin, SSAVariableMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Recover print-like macros"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        DFAMixin.__init__(self, self._graph)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        SSAVariableMixin.__init__(self, self)

        self._stmts_to_remove = defaultdict(list)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _select_macro(self, func_name, fmt_str) -> Tuple[str, str, RustSimType | None] | Tuple[None, None, None]:
        match func_name.split("::")[-1]:
            case "_print":
                if fmt_str.endswith("\n"):
                    return "println", fmt_str[:-1], None
                return "print", fmt_str, None
            case "_eprint":
                if fmt_str.endswith("\n"):
                    return "eprintln", fmt_str[:-1], None
                return "eprint", fmt_str, None
            case "format_inner" | "format" | "map_or_else":
                return "format", fmt_str, self.project.kb.known_structs["alloc::string::String"]
            case "panic_fmt":
                return "panic", fmt_str, None
            case "write_fmt" | "write":
                if fmt_str.endswith("\n"):
                    return "writeln", fmt_str[:-1], RustSimTypeSize(signed=False)
                return "write", fmt_str, RustSimTypeSize(signed=False)
        l.error(f"Can't find a macro for {func_name}")
        assert False

    def _is_debug_formatter(self, arg: Struct):
        formatter = arg.get_field("formatter")
        if isinstance(formatter, Const) and formatter.value in self.project.kb.functions:
            name = demangle(self.project.kb.functions[formatter.value].name)
            if "core::fmt::Display" in name:
                return False
            return True
        return False

    def _try_find_arguments_struct(self, call: Call):
        if call.args and (arg_vvar := unwrap_stack_vvar_reference(call.args[-1])):
            arg_value = self.get_terminal_vvar_value(arg_vvar)
            def_block, def_stmt = self.get_def_block_and_stmt(arg_value)
            if isinstance(arg_value, Struct) and arg_value.name == "core::fmt::Arguments":
                return arg_value, def_block, def_stmt
            elif (
                isinstance(arg_value, Call)
                and isinstance(arg_value.target, Const)
                and arg_value.target.value in self.project.kb.functions
            ):
                arguments_ty = self.project.kb.known_structs["core::fmt::Arguments"]
                func = self.project.kb.functions[arg_value.target.value]
                clinic = self.project.kb.clinic_factory.get(func)
                srda_mixin = SRDAMixin(func, clinic.graph, self.project)
                fields = {}
                for block in clinic.graph.nodes:
                    for stmt in block.statements:
                        if isinstance(stmt, Store):
                            vvar, offset = extract_vvar_and_offset(stmt.addr)
                            if vvar:
                                data = stmt.data
                                if isinstance(data, VirtualVariable):
                                    data = srda_mixin.get_terminal_vvar_value(data) or data
                                fields[offset] = data
                for offset, data in fields.copy().items():
                    if (
                        isinstance(data, VirtualVariable)
                        and data.was_parameter
                        and data.varid - 1 < len(arg_value.args)
                    ):
                        fields[offset] = arg_value.args[data.varid - 1]
                struct = self.project.analyses.StructBuilder(context=self, strict=True).build(fields, arguments_ty)
                return struct, def_block, def_stmt
        return None, None, None

    def _try_find_argument_structs(self, arguments_struct: Struct, arguments_def_block: Block, arguments_def_stmt):
        args = arguments_struct.get_field("args")
        if args.length == 0:
            return [], {}
        argument_ty = (
            self.project.kb.known_structs["core::fmt::rt::Argument"]
            or self.project.kb.known_structs["core::fmt::ArgumentV1"]
        )
        argument_structs = []
        stmts_to_remove = defaultdict(list)
        arg_vvars = []
        for arg in args.elements:
            arg_vvar = self.get_stack_vvar_by_insn(
                arg.stack_offset,
                arguments_def_stmt.tags["ins_addr"],
                arguments_def_block.idx,
            )
            arg_vvars.append(arg_vvar)
        arg_values = [self.get_terminal_vvar_value(arg_vvar) if arg_vvar else None for arg_vvar in arg_vvars]
        # In case args structs are packed into one struct
        if (
            arg_values
            and arg_values[0] is not None
            and isinstance(arg_values[0], Struct)
            and arg_values[0].size == len(arg_values) * argument_ty.size // self.project.arch.bytes
            and all(
                isinstance(field, VirtualVariable) and field.size == argument_ty.size // self.project.arch.bytes
                for field in arg_values[0].fields.values()
            )
        ):
            def_block, def_stmt = self.get_def_block_and_stmt(arg_values[0])
            stmts_to_remove[def_block].append(def_stmt)
            arg_values = [self.get_terminal_vvar_value(field) for field in arg_values[0].fields.values()]
        # Pattern-1: Argument(s) are constructed via calls
        if all(isinstance(arg_value, Call) for arg_value in arg_values):
            for arg_value in arg_values:
                arg_def_block, arg_def_stmt = self.get_def_block_and_stmt(arg_value)
                fields = {}
                func = self.project.kb.functions.get(arg_value.target.value, None)
                clinic = self.project.kb.clinic_factory.get(func)
                for block in clinic.graph.nodes:
                    for stmt in block.statements:
                        if isinstance(stmt, Store):
                            vvar, offset = extract_vvar_and_offset(stmt.addr)
                            if vvar:
                                fields[offset] = stmt.data
                for offset, data in fields.copy().items():
                    if (
                        isinstance(data, VirtualVariable)
                        and data.was_parameter
                        and data.varid - 1 < len(arg_value.args)
                    ):
                        fields[offset] = arg_value.args[data.varid - 1]
                struct = self.project.analyses.StructBuilder(context=self, strict=True).build(fields, argument_ty)
                if isinstance(struct, Struct):
                    argument_structs.append(struct)
                    stmts_to_remove[arg_def_block].append(arg_def_stmt)
                else:
                    return None, None
            return argument_structs, stmts_to_remove
        # Pattern-2: Argument(s) are directly Structs
        elif all(isinstance(arg_value, Struct) for arg_value in arg_values):
            for arg_value in arg_values:
                argument_structs.append(arg_value)
                def_block, def_stmt = self.get_def_block_and_stmt(arg_value)
                stmts_to_remove[def_block].append(def_stmt)
            return argument_structs, stmts_to_remove
        # Pattern-3: Argument(s) are stack-allocated and are not recovered yet
        stack_defs = self.collect_callsite_stack_defs(arguments_def_block)
        for arg in args.elements:
            argument_ty_value_offset = argument_ty.get_field_offset("value", 0) if argument_ty else 0
            argument_ty_formatter_offset = (
                argument_ty.get_field_offset("formatter", self.project.arch.bytes)
                if argument_ty
                else self.project.arch.bytes
            )
            value_def = stack_defs.get(arg.stack_offset + argument_ty_value_offset, None)
            formatter_def = stack_defs.get(arg.stack_offset + argument_ty_formatter_offset, None)
            if value_def and formatter_def:
                fields = {
                    argument_ty_value_offset: value_def.data,
                    argument_ty_formatter_offset: formatter_def.data,
                }
                struct = self.project.analyses.StructBuilder(context=self, strict=True).build(fields, argument_ty)
                if isinstance(struct, Struct):
                    argument_structs.append(struct)
                    stmts_to_remove[value_def.block].append(value_def.stmt)
                    stmts_to_remove[formatter_def.block].append(formatter_def.stmt)
                else:
                    return None, None
            else:
                return None, None
        return argument_structs, stmts_to_remove

    def replace_call(self, call: Call, block: Block, stmt, is_expr):
        name = self.match_call(call, FORMAT_FUNCTIONS, monopolize=False, use_trait_name=False)
        if name is None and isinstance(call.target, Const):
            name = self.project.kb.format_wrappers.resolve(call.target.value)
        if name:
            arguments_struct, arguments_def_block, arguments_def_stmt = self._try_find_arguments_struct(call)
            # Sanity check
            if arguments_struct:
                pieces = arguments_struct.get_field("pieces")
                args = arguments_struct.get_field("args")
                if (
                    isinstance(pieces, Array)
                    and isinstance(args, Array)
                    and 0 <= pieces.length - args.length <= 1
                    and all(isinstance(arg, VirtualVariable) and arg.was_stack for arg in args.elements)
                ):
                    macro_args, stmts_to_remove = self._try_find_argument_structs(
                        arguments_struct, arguments_def_block, arguments_def_stmt
                    )
                    if macro_args is not None:
                        pieces = [extract_str_from_addr(self.project, ele.value) for ele in pieces.elements]
                        if len(pieces) == args.length:
                            pieces.append("")
                        placeholders = [
                            "{:?}" if self._is_debug_formatter(macro_arg) else "{}" for macro_arg in macro_args
                        ]
                        placeholders.append("")
                        macro_args = [
                            macro_arg.get_field("value.pointer") or macro_arg.get_field("value")
                            for macro_arg in macro_args
                        ]
                        for block, stmts in stmts_to_remove.items():
                            for stmt in stmts:
                                self._stmts_to_remove[block].append(stmt)
                        self._stmts_to_remove[arguments_def_block].append(arguments_def_stmt)
                        fmt_str = ""
                        for piece, placeholder in zip(pieces, placeholders):
                            fmt_str += piece + placeholder
                        macro_name, fmt_str, returnty = self._select_macro(name, fmt_str)
                        if returnty is not None:
                            returnty = returnty.with_arch(self.project.arch)
                        macro_args.insert(0, StringLiteral(None, fmt_str, self.project.arch.bits * 2))
                        macro = FunctionLikeMacro(
                            None,
                            macro_name,
                            macro_args,
                            bits=call.bits if is_expr else None,
                            returnty=returnty,
                            **call.tags,
                        )
                        return macro
        return call

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            CallRewriter(self.replace_call).walk(block)
        for block, stmts in self._stmts_to_remove.items():
            for stmt in stmts:
                if stmt in block.statements:
                    block.statements.remove(stmt)
