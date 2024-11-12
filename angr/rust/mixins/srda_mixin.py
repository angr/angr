from ailment import Expression, Assignment
from ailment.expression import VirtualVariable, Phi

from angr.analyses.s_reaching_definitions import SRDAView
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE


class SRDAMixin:
    def __init__(self, subject, graph, project):
        self.srda = project.analyses.SReachingDefinitions(subject=subject, func_graph=graph)
        self.srda_view = SRDAView(self.srda.model)

    def get_vvar_value(self, vvar: VirtualVariable) -> Expression | None:
        # Fix the vvar value not found issue caused by unmatched expr idx
        for key in self.srda.model.all_vvar_definitions:
            if key.likes(vvar):
                vvar = key
                break
        return self.srda_view.get_vvar_value(vvar)

    def get_terminal_vvar_value(self, vvar):
        visited = set()
        value = vvar
        while (value := self.get_vvar_value(value)) and value not in visited:
            visited.add(value)
            if isinstance(value, VirtualVariable):
                continue
            elif isinstance(value, Phi):
                result = set()
                for _, phi_vvar in value.src_and_vvars:
                    result.add(self.get_terminal_vvar_value(phi_vvar))
                if len(result) == 1:
                    return next(iter(result))
                else:
                    return value
            else:
                return value
        return None

    def get_terminal_vvar(self, vvar):
        visited = set()
        value = vvar
        while (value := self.get_vvar_value(value)) and value not in visited:
            visited.add(value)
            if isinstance(value, VirtualVariable):
                vvar = value
                continue
            elif isinstance(value, Phi):
                result = set()
                for _, phi_vvar in value.src_and_vvars:
                    result.add(self.get_terminal_vvar(phi_vvar))
                if len(result) == 1:
                    return next(iter(result))
                else:
                    return vvar
            else:
                return vvar
        return vvar

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
