import networkx as nx
from angr.ailment import Assignment
from angr.ailment.expression import VirtualVariable

from angr.analyses.s_reaching_definitions import SRDAView, SReachingDefinitionsAnalysis
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE


class SRDAUtil:
    def __init__(self, srda: SReachingDefinitionsAnalysis):
        self.srda = srda
        self.srda_view = SRDAView(srda.model)

    @staticmethod
    def from_function(project, func, func_graph):
        srda = project.analyses.SReachingDefinitions(subject=func, func_graph=func_graph)
        return SRDAUtil(srda)

    @staticmethod
    def from_block(project, block):
        func_graph = nx.DiGraph()
        func_graph.add_node(block)
        srda = project.analyses.SReachingDefinitions(subject=block, func_graph=func_graph)
        return SRDAUtil(srda)

    def get_stack_vvar_by_insn(
        self, stack_offset: int, addr: int, block_idx: int | None = None, op_type=OP_BEFORE
    ) -> VirtualVariable | None:
        vvars = set()

        def _predicate(stmt) -> bool:
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and stmt.dst.stack_offset == stack_offset
            ):
                vvars.add(stmt.dst)
                return True
            return False

        self.srda_view._get_vvar_by_insn(addr, op_type, _predicate, block_idx=block_idx)

        # assert len(vvars) <= 1
        return next(iter(vvars), None)

    def get_def_by_vvar(self, vvar):
        for def_ in self.srda.model.all_definitions:
            if hasattr(def_.atom, "varid") and def_.atom.varid == vvar.varid:
                return def_
        return None
