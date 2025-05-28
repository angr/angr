from __future__ import annotations

from collections import defaultdict
from collections.abc import Generator
from typing import Any, Literal, overload

from angr.ailment.expression import VirtualVariable, Tmp

from angr.knowledge_plugins.key_definitions import atoms, Definition
from angr.code_location import CodeLocation


class SRDAModel:
    """
    The model for SRDA.
    """

    def __init__(self, func_graph, func_args, arch):
        self.func_graph = func_graph
        self.func_args = func_args
        self.arch = arch
        self.varid_to_vvar: dict[int, VirtualVariable] = {}
        self.all_vvar_definitions: dict[int, CodeLocation] = {}
        self.all_vvar_uses: dict[int, list[tuple[VirtualVariable | None, CodeLocation]]] = defaultdict(list)
        self.all_tmp_definitions: dict[CodeLocation, dict[atoms.Tmp, int]] = defaultdict(dict)
        self.all_tmp_uses: dict[CodeLocation, dict[atoms.Tmp, set[tuple[Tmp, int]]]] = defaultdict(dict)
        self.phi_vvar_ids: set[int] = set()
        self.phivarid_to_varids: dict[int, set[int]] = {}
        self.vvar_uses_by_loc: dict[CodeLocation, list[int]] = {}

    def add_vvar_use(self, vvar_id: int, expr: VirtualVariable | None, loc: CodeLocation) -> None:
        self.all_vvar_uses[vvar_id].append((expr, loc))
        if loc not in self.vvar_uses_by_loc:
            self.vvar_uses_by_loc[loc] = []
        self.vvar_uses_by_loc[loc].append(vvar_id)

    @property
    def all_definitions(self) -> Generator[Definition]:
        for vvar_id, defloc in self.all_vvar_definitions.items():
            vvar = self.varid_to_vvar[vvar_id]
            yield Definition(atoms.VirtualVariable(vvar_id, vvar.size, vvar.category, vvar.oident), defloc)

    def is_phi_vvar_id(self, idx: int) -> bool:
        return idx in self.phi_vvar_ids

    def get_all_definitions(self, block_loc: CodeLocation) -> set[Definition]:
        s = set()
        for vvar_id, codeloc in self.all_vvar_definitions.items():
            vvar = self.varid_to_vvar[vvar_id]
            if codeloc.block_addr == block_loc.block_addr and codeloc.block_idx == block_loc.block_idx:
                s.add(Definition(atoms.VirtualVariable(vvar_id, vvar.size, vvar.category, vvar.oident), codeloc))
        return s | self.get_all_tmp_definitions(block_loc)

    def get_all_tmp_definitions(self, block_loc: CodeLocation) -> set[Definition]:
        s = set()
        for tmp_atom, stmt_idx in self.all_tmp_definitions[block_loc].items():
            s.add(Definition(tmp_atom, CodeLocation(block_loc.block_addr, stmt_idx, block_idx=block_loc.block_idx)))
        return s

    @overload
    def get_uses_by_location(self, loc: CodeLocation, exprs: Literal[True]) -> set[tuple[Definition, Any | None]]: ...

    @overload
    def get_uses_by_location(self, loc: CodeLocation, exprs: Literal[False] = ...) -> set[Definition]: ...

    def get_uses_by_location(
        self, loc: CodeLocation, exprs: bool = False
    ) -> set[Definition] | set[tuple[Definition, Any | None]]:
        """
        Retrieve all definitions that are used at a given location.

        :param loc:     The code location.
        :return:        A set of definitions that are used at the given location.
        """
        if exprs:
            def_with_exprs: set[tuple[Definition, Any]] = set()
            if loc not in self.vvar_uses_by_loc:
                return def_with_exprs
            for vvar_id in self.vvar_uses_by_loc[loc]:
                vvar = self.varid_to_vvar[vvar_id]
                def_with_exprs.add(
                    (
                        Definition(
                            atoms.VirtualVariable(vvar_id, vvar.size, vvar.category, vvar.oident),
                            self.all_vvar_definitions[vvar_id],
                        ),
                        vvar,
                    )
                )
            return def_with_exprs

        defs: set[Definition] = set()
        if loc not in self.vvar_uses_by_loc:
            return defs
        for vvar_id in self.vvar_uses_by_loc[loc]:
            vvar = self.varid_to_vvar[vvar_id]
            defs.add(
                Definition(
                    atoms.VirtualVariable(vvar_id, vvar.size, vvar.category, vvar.oident),
                    self.all_vvar_definitions[vvar_id],
                )
            )
        return defs

    def get_vvar_uses(self, obj: VirtualVariable | atoms.VirtualVariable) -> set[CodeLocation]:
        if obj.varid in self.all_vvar_uses:
            return {loc for _, loc in self.all_vvar_uses[obj.varid]}
        return set()

    def get_vvar_uses_with_expr(
        self, obj: VirtualVariable | atoms.VirtualVariable
    ) -> set[tuple[VirtualVariable | None, CodeLocation]]:
        if obj.varid in self.all_vvar_uses:
            return set(self.all_vvar_uses[obj.varid])
        return set()

    def get_tmp_uses(self, obj: atoms.Tmp, block_loc: CodeLocation) -> set[CodeLocation]:
        if block_loc not in self.all_tmp_uses:
            return set()
        if obj not in self.all_tmp_uses[block_loc]:
            return set()
        s = set()
        for _, stmt_idx in self.all_tmp_uses[block_loc][obj]:
            s.add(CodeLocation(block_loc.block_addr, stmt_idx, block_idx=block_loc.block_idx))
        return s

    def get_uses_by_def(self, def_: Definition) -> set[CodeLocation]:
        if isinstance(def_.atom, atoms.Tmp):
            return self.get_tmp_uses(
                def_.atom,
                CodeLocation(def_.codeloc.block_addr, def_.codeloc.stmt_idx, block_idx=def_.codeloc.block_idx),
            )
        if isinstance(def_.atom, atoms.VirtualVariable):
            return self.get_vvar_uses(def_.atom)
        return set()
