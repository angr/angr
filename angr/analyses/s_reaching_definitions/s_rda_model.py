from __future__ import annotations

from collections import defaultdict
from collections.abc import Generator
from typing import Any

from ailment.expression import VirtualVariable, Tmp

from angr.knowledge_plugins.key_definitions import atoms, Definition
from angr.code_location import CodeLocation


class SRDAModel:
    """
    The model for SRDA.
    """

    def __init__(self, func_graph, arch):
        self.func_graph = func_graph
        self.arch = arch
        self.varid_to_vvar: dict[int, VirtualVariable] = {}
        self.all_vvar_definitions: dict[VirtualVariable, CodeLocation] = {}
        self.all_vvar_uses: dict[VirtualVariable, set[tuple[VirtualVariable | None, CodeLocation]]] = defaultdict(set)
        self.all_tmp_definitions: dict[CodeLocation, dict[atoms.Tmp, int]] = defaultdict(dict)
        self.all_tmp_uses: dict[CodeLocation, dict[atoms.Tmp, set[tuple[Tmp, int]]]] = defaultdict(dict)
        self.phi_vvar_ids: set[int] = set()
        self.phivarid_to_varids: dict[int, set[int]] = {}

    @property
    def all_definitions(self) -> Generator[Definition]:
        for vvar, defloc in self.all_vvar_definitions.items():
            yield Definition(atoms.VirtualVariable(vvar.varid, vvar.size, vvar.category, vvar.oident), defloc)

    def is_phi_vvar_id(self, idx: int) -> bool:
        return idx in self.phi_vvar_ids

    def get_all_definitions(self, block_loc: CodeLocation) -> set[Definition]:
        s = set()
        for vvar, codeloc in self.all_vvar_definitions.items():
            if codeloc.block_addr == block_loc.block_addr and codeloc.block_idx == block_loc.block_idx:
                s.add(Definition(atoms.VirtualVariable(vvar.varid, vvar.size, vvar.category, vvar.oident), codeloc))
        return s | self.get_all_tmp_definitions(block_loc)

    def get_all_tmp_definitions(self, block_loc: CodeLocation) -> set[Definition]:
        s = set()
        for tmp_atom, stmt_idx in self.all_tmp_definitions[block_loc].items():
            s.add(Definition(tmp_atom, CodeLocation(block_loc.block_addr, stmt_idx, block_idx=block_loc.block_idx)))
        return s

    def get_uses_by_location(
        self, loc: CodeLocation, exprs: bool = False
    ) -> set[Definition] | set[tuple[Definition, Any | None]]:
        """
        Retrieve all definitions that are used at a given location.

        :param loc:     The code location.
        :return:        A set of definitions that are used at the given location.
        """
        if exprs:
            defs: set[tuple[Definition, Any]] = set()
            for vvar, uses in self.all_vvar_uses.items():
                for expr, loc_ in uses:
                    if loc_ == loc:
                        defs.add(
                            (
                                Definition(
                                    atoms.VirtualVariable(vvar.varid, vvar.size, vvar.category, vvar.oident),
                                    self.all_vvar_definitions[vvar],
                                ),
                                expr,
                            )
                        )
            return defs

        defs: set[Definition] = set()
        for vvar, uses in self.all_vvar_uses.items():
            for _, loc_ in uses:
                if loc_ == loc:
                    defs.add(
                        Definition(
                            atoms.VirtualVariable(vvar.varid, vvar.size, vvar.category, vvar.oident),
                            self.all_vvar_definitions[vvar],
                        )
                    )
        return defs

    def get_vvar_uses(self, obj: atoms.VirtualVariable) -> set[CodeLocation]:
        the_vvar = self.varid_to_vvar.get(obj.varid, None)
        if the_vvar is not None:
            return {loc for _, loc in self.all_vvar_uses[the_vvar]}
        return set()

    def get_vvar_uses_with_expr(self, obj: atoms.VirtualVariable) -> set[tuple[CodeLocation, VirtualVariable]]:
        the_vvar = self.varid_to_vvar.get(obj.varid, None)
        if the_vvar is not None:
            return {(loc, expr) for expr, loc in self.all_vvar_uses[the_vvar]}
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
