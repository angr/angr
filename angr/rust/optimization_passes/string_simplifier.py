import ailment

from ...analyses.decompiler.optimization_passes.engine_base import SimplifierAILState
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ..sim_type import RustSimTypeStr, RustSimTypePointer
from ..ailment.expression import Str


class StringSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Simplify Rust str"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def try_simplify_string(self, stmt):
        if isinstance(stmt, ailment.statement.Store) and isinstance(stmt.data, ailment.Const):
            data = stmt.data
            section = self.project.loader.find_section_containing(data.value)
            if section and section.is_readable:
                memory = self.project.loader.memory
                str_addr = memory.unpack(stmt.data.value, self.project.arch.struct_fmt())[0]
                section = self.project.loader.find_section_containing(str_addr)
                if section and section.is_readable and not section.is_writable:
                    str_len = memory.unpack(stmt.data.value + self.project.arch.bytes, self.project.arch.struct_fmt())[
                        0
                    ]
                    try:
                        decoded_str = memory.load(str_addr, str_len).decode("utf-8")
                    except UnicodeDecodeError:
                        return False
                    new_expr = Str(data.idx, data.variable, data.value, data.bits, decoded_str)
                    stmt.data = new_expr
                    # Set variable type to &str
                    self._variable_kb.variables.get_function_manager(self._func.addr).set_variable_type(
                        stmt.variable, RustSimTypePointer(RustSimTypeStr()), mark_manual=True
                    )
                    return True
        return False

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            block: ailment.Block
            for stmt in block.statements:
                self.try_simplify_string(stmt)
