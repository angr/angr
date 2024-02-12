import ailment

from ...analyses.decompiler.optimization_passes.engine_base import SimplifierAILState
from ...knowledge_plugins.cfg import MemoryDataSort
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ...analyses.typehoon.rust.sim_type import RustSimTypeStr, RustSimTypePointer
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
        return True, None

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            block: ailment.Block
            for stmt in block.statements:
                if isinstance(stmt, ailment.statement.Store) and isinstance(stmt.data, ailment.Const):
                    data = stmt.data
                    section = self.project.loader.find_section_containing(data.value)
                    if section and section.is_readable:
                        str_addr = self.project.loader.memory.unpack(stmt.data.value, self.project.arch.struct_fmt())[0]
                        section = self.project.loader.find_section_containing(str_addr)
                        if section and section.is_readable and not section.is_writable:
                            str_len = self.project.loader.memory.unpack(
                                stmt.data.value + self.project.arch.bytes, self.project.arch.struct_fmt()
                            )[0]
                            cfg = self.project.kb.cfgs.get_most_accurate()
                            if cfg is not None and str_addr in cfg.memory_data:
                                memory_data = cfg.memory_data[str_addr]
                                if memory_data.sort == MemoryDataSort.String:
                                    new_memory_data = memory_data.copy()
                                    new_memory_data.content = memory_data.content[:str_len]
                                    new_memory_data.size = str_len
                                    new_expr = Str(data.idx, data.variable, data.value, data.bits, new_memory_data)
                                    stmt.data = new_expr
                                    # Set variable type to &str
                                    self._variable_kb.variables.get_function_manager(self._func.addr).set_variable_type(
                                        stmt.variable, RustSimTypePointer(RustSimTypeStr())
                                    )
