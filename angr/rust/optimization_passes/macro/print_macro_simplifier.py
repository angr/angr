from typing import Tuple

from ailment import Block
from ailment.expression import Const, VirtualVariable
from ailment.statement import Call

from angr.rust.optimization_passes.utils import extract_str_from_addr
from angr.rust.utils.ail_util import unwrap_stack_vvar_reference
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.ailment.expression import Struct, Array, StringLiteral
from angr.rust.ailment.statement import FunctionLikeMacro
from angr.rust.mixins import CFAMixin, DFAMixin
from angr.rust.optimization_passes.utils import CallReplacer
from angr.rust.sim_type import RustSimType, RustSimTypeString
from angr.rust.utils.library import demangle

PRINT_FUNCTIONS = (
    "std::io::stdio::_print",
    "std::io::stdio::_eprint",
    "alloc::fmt::format::format_inner",
    "core::option::Option<T>::map_or_else",
    "core::panicking::panic_fmt",
)


class PrintMacroSimplifier(OptimizationPass, CFAMixin, DFAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.RUST_SPECIFIC_SIMPLIFICATION
    NAME = "Recover print-like macros"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)

        self._stmts_to_remove = {}
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    @staticmethod
    def _select_macro(func_name, fmt_str) -> Tuple[str, str, RustSimType | None] | Tuple[None, None, None]:
        if func_name.endswith("::_print"):
            if fmt_str.endswith("\n"):
                return "println", fmt_str[:-1], None
            return "print", fmt_str, None
        elif func_name.endswith("::_eprint"):
            if fmt_str.endswith("\n"):
                return "eprintln", fmt_str[:-1], None
            return "eprint", fmt_str, None
        elif func_name.endswith("::format_inner") or func_name.endswith("::map_or_else"):
            return "format", fmt_str, RustSimTypeString()
        elif func_name.endswith("::panic_fmt"):
            return "panic", fmt_str, None
        return None, None, None

    def _is_debug_formatter(self, arg: Struct):
        formatter = arg.get_field("formatter")
        if isinstance(formatter, Const) and formatter.value in self.project.kb.functions:
            name = demangle(self.project.kb.functions[formatter.value].name)
            if "core::fmt::Display" in name:
                return False
            return True
        return False

    def replace_call(self, call: Call, block: Block, is_expr):
        if (
            (name := self.match_call(call, PRINT_FUNCTIONS, monopolize=False, use_trait_name=False))
            and call.args
            and (arg_vvar := unwrap_stack_vvar_reference(call.args[-1]))
        ):
            stack_writes, offset_to_stmt = self.collect_stack_writes(block)
            arg = stack_writes.get(arg_vvar.stack_offset, None)
            if isinstance(arg, Struct) and arg.name == "Arguments":
                pieces = arg.get_field("pieces")
                args = arg.get_field("args")
                if (
                    isinstance(pieces, Array)
                    and isinstance(args, Array)
                    and 0 <= pieces.length - args.length <= 1
                    and all(
                        isinstance(arg, VirtualVariable)
                        and arg.was_stack
                        and arg.stack_offset in stack_writes
                        and isinstance(stack_writes[arg.stack_offset], Struct)
                        and stack_writes[arg.stack_offset].name == "Argument"
                        for arg in args.elements
                    )
                    and all(isinstance(piece, Const) for piece in pieces.elements)
                ):
                    stmts_to_remove = [offset_to_stmt[arg.stack_offset] for arg in args.elements]
                    stmts_to_remove.append(offset_to_stmt[arg_vvar.stack_offset])

                    pieces = [extract_str_from_addr(self.project, piece.value) for piece in pieces.elements]
                    args = [stack_writes[arg.stack_offset] for arg in args.elements]

                    if len(pieces) == len(args):
                        pieces.append("")

                    placeholders = ["{:?}" if self._is_debug_formatter(arg) else "{}" for arg in args]
                    placeholders.append("")
                    fmt_str = ""
                    for piece, placeholder in zip(pieces, placeholders):
                        fmt_str += piece + placeholder
                    macro_name, fmt_str, returnty = self._select_macro(name, fmt_str)
                    if returnty is not None:
                        returnty = returnty.with_arch(self.project.arch)
                    if macro_name and fmt_str:
                        args = [arg.get_field("value") for arg in args]
                        args.insert(0, StringLiteral(None, fmt_str, self.project.arch.bits * 2))
                        macro = FunctionLikeMacro(
                            None, macro_name, args, bits=call.bits if is_expr else None, returnty=returnty, **call.tags
                        )
                        self._stmts_to_remove[block] = stmts_to_remove
                        return macro
        return None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            replacer = CallReplacer(self.replace_call)
            replacer.walk(block)
        for block, stmts in self._stmts_to_remove.items():
            for stmt in stmts:
                try:
                    block.statements.remove(stmt)
                except:
                    pass
