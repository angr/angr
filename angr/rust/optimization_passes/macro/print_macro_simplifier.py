from typing import Tuple

from ailment import Block
from ailment.expression import StackBaseOffset, Const
from ailment.statement import Store, Call

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.ailment.expression import Struct, Array, String
from angr.rust.ailment.statement import FunctionLikeMacro
from angr.rust.mixins.cfa_mixin import CFAMixin
from angr.rust.optimization_passes.utils import CallReplacer

PRINT_FUNCTIONS = (
    "std::io::stdio::_print",
    "std::io::stdio::_eprint",
    "alloc::fmt::format::format_inner",
    "core::option::Option<T>::map_or_else",
    "core::panicking::panic_fmt",
)


class PrintMacroSimplifier(OptimizationPass, CFAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Recover print-family macros"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)

        self._stmts_to_remove = {}
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _extract_string_from_const(self, expr: Const):
        decoded_str = ""
        if (section := self.project.loader.find_section_containing(expr.value)) and section.is_readable:
            memory = self.project.loader.memory
            str_addr = memory.unpack(expr.value, self.project.arch.struct_fmt())[0]
            if (
                (section := self.project.loader.find_section_containing(str_addr))
                and section.is_readable
                and not section.is_writable
            ):
                str_len = memory.unpack(expr.value + self.project.arch.bytes, self.project.arch.struct_fmt())[0]
                try:
                    decoded_str = memory.load(str_addr, str_len).decode("utf-8")
                except UnicodeDecodeError:
                    pass
        return decoded_str

    @staticmethod
    def _select_macro(func_name, fmt_str) -> Tuple[str, str] | Tuple[None, None]:
        if func_name.endswith("::_print"):
            if fmt_str.endswith("\n"):
                return "println", fmt_str[:-1]
            return "print", fmt_str
        elif func_name.endswith("::_eprint"):
            if fmt_str.endswith("\n"):
                return "eprintln", fmt_str[:-1]
            return "eprint", fmt_str
        elif func_name.endswith("::format_inner"):
            return "format", fmt_str
        elif func_name.endswith("::map_or_else"):
            return "format", fmt_str
        elif func_name.endswith("::panic_fmt"):
            return "panic", fmt_str
        return None, None

    def replace_call(self, call: Call, block: Block):
        if (
            (name := self.match_call(call, PRINT_FUNCTIONS, monopolize=False, use_trait_name=False))
            and call.args
            and isinstance(call.args[0], StackBaseOffset)
        ):
            stack = {}
            offset_to_stmt = {}
            for stmt in block.statements:
                if isinstance(stmt, Store) and isinstance(stmt.addr, StackBaseOffset):
                    stack[stmt.addr.offset] = stmt.data
                    offset_to_stmt[stmt.addr.offset] = stmt
            arg = stack.get(call.args[0].offset, None)
            if isinstance(arg, Struct) and arg.type.name == "Arguments":
                pieces = arg.get_field("pieces")
                args = arg.get_field("args")
                if (
                    isinstance(pieces, Array)
                    and isinstance(args, Array)
                    and 0 <= pieces.length - args.length <= 1
                    and all(
                        isinstance(arg, StackBaseOffset)
                        and arg.offset in stack
                        and isinstance(stack[arg.offset], Struct)
                        and stack[arg.offset].type.name == "Argument"
                        for arg in args.elements
                    )
                    and all(isinstance(piece, Const) for piece in pieces.elements)
                ):
                    stmts_to_remove = [offset_to_stmt[arg.offset] for arg in args.elements]
                    stmts_to_remove.append(offset_to_stmt[call.args[0].offset])

                    pieces = [self._extract_string_from_const(piece) for piece in pieces.elements]
                    args = [stack[arg.offset] for arg in args.elements]

                    if len(pieces) == len(args):
                        pieces.append("")

                    placeholders = ["{:?}" if arg.get_field("formatter") else "{}" for arg in args]
                    placeholders.append("")
                    fmt_str = ""
                    for piece, placeholder in zip(pieces, placeholders):
                        fmt_str += piece + placeholder
                    macro_name, fmt_str = self._select_macro(name, fmt_str)
                    if macro_name and fmt_str:
                        args = [arg.get_field("value") for arg in args]
                        args.insert(0, String(None, None, 0, self.project.arch.bits, fmt_str))
                        macro = FunctionLikeMacro(None, macro_name, args, bits=call.bits, **call.tags)
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
