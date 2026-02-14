from angr.ailment import Expression, Assignment
from angr.ailment.expression import VirtualVariable, Phi
from angr.ailment.statement import Call, FunctionLikeMacro
from angr.rust.sim_type import RustSimTypeFunction, RustSimType
from angr.analyses.s_reaching_definitions import SRDAView
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE


class SRDAMixin:
    def __init__(self, subject, graph, project):
        self._graph = graph
        self.srda = project.analyses.SReachingDefinitions(subject=subject, func_graph=graph)
        self.srda_view = SRDAView(self.srda.model)
        self._gtv_cache = {}  # varid -> terminal VirtualVariable

    def get_vvar_value(self, vvar: VirtualVariable) -> Expression | None:
        if not vvar:
            return None
        # Fix the vvar value not found issue caused by unmatched expr idx
        for key in self.srda.model.all_vvar_definitions:
            key = self.srda.model.varid_to_vvar[key]
            if key.likes(vvar):
                vvar = key
                break
        return self.srda_view.get_vvar_value(vvar)

    def get_terminal_vvar_values(self, vvar, visited=None):
        visited = visited if visited else set()
        value = vvar
        visited.add(value)
        while (value := self.get_vvar_value(value)) and value not in visited:
            visited.add(value)
            if isinstance(value, VirtualVariable):
                continue
            elif isinstance(value, Phi):
                result = set()
                for _, phi_vvar in value.src_and_vvars:
                    result |= self.get_terminal_vvar_values(phi_vvar, visited)
                return result
            else:
                return {value}
        return set()

    def get_terminal_vvar_value(self, vvar, visited=None):
        return self.get_vvar_value(self.get_terminal_vvar(vvar, visited))

    def get_terminal_vvar(self, vvar, visited=None):
        visited = visited or set()  # set of varid ints
        if isinstance(vvar, VirtualVariable) and vvar.varid in self._gtv_cache:
            return self._gtv_cache[vvar.varid]
        cur_vvar = vvar
        while isinstance(cur_vvar, VirtualVariable) and cur_vvar.varid not in visited:
            if cur_vvar.varid in self._gtv_cache:
                cur_vvar = self._gtv_cache[cur_vvar.varid]
                break
            visited.add(cur_vvar.varid)
            value = self.get_vvar_value(cur_vvar)
            if isinstance(value, VirtualVariable):
                cur_vvar = value
                continue
            elif isinstance(value, Phi):
                result = {}  # varid -> VirtualVariable
                for _, phi_vvar in value.src_and_vvars:
                    terminal = self.get_terminal_vvar(phi_vvar, set(visited))
                    if isinstance(terminal, VirtualVariable) and terminal.varid not in visited:
                        result[terminal.varid] = terminal
                if len(result) == 1:
                    cur_vvar = next(iter(result.values()))
                else:
                    break
            else:
                break
        else:
            # Loop ended due to cycle (varid in visited) or non-VV — don't cache
            return cur_vvar
        # Reached here via break — successful resolution, cache it
        if isinstance(vvar, VirtualVariable):
            self._gtv_cache[vvar.varid] = cur_vvar
        return cur_vvar

    def get_stack_vvar_by_insn(
        self, stack_offset: int, addr: int, block_idx: int | None = None, size=None, op_type=OP_BEFORE
    ) -> VirtualVariable | None:
        vvars = set()

        def _predicate(stmt) -> bool:
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and stmt.dst.stack_offset == stack_offset
                and (size is None or stmt.dst.size == size)
            ):
                vvars.add(stmt.dst)
                return True
            return False

        self.srda_view._get_vvar_by_insn(addr, op_type, _predicate, block_idx=block_idx)

        # assert len(vvars) <= 1
        return next(iter(vvars), None)

    def get_stack_vvar_and_offset_by_insn(
        self, stack_offset: int, addr: int, block_idx: int | None = None, op_type=OP_BEFORE
    ) -> tuple[VirtualVariable, int] | tuple[None, None]:
        vvars = set()

        def _predicate(stmt) -> bool:
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and stmt.dst.stack_offset <= stack_offset < stmt.dst.stack_offset + stmt.dst.size
            ):
                offset = stack_offset - stmt.dst.stack_offset
                vvars.add((stmt.dst, offset))
                return True
            return False

        self.srda_view._get_vvar_by_insn(addr, op_type, _predicate, block_idx=block_idx)

        # assert len(vvars) <= 1
        return next(iter(vvars), (None, None))

    def get_vvar_type(self, vvar) -> RustSimType | None:
        value = self.get_terminal_vvar_value(vvar)
        if isinstance(value, Call) and isinstance(value.prototype, RustSimTypeFunction):
            return value.prototype.returnty
        if isinstance(value, FunctionLikeMacro):
            return value.returnty
        return None

    def get_def_by_vvar(self, vvar):
        for def_ in self.srda.model.all_definitions:
            if hasattr(def_.atom, "varid") and def_.atom.varid == vvar.varid:
                return def_
        return None
