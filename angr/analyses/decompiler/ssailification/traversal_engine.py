from __future__ import annotations
from collections import OrderedDict
from claripy.utils.orderedset import OrderedSet

from ailment.statement import Assignment
from ailment.expression import Register

from angr.engines.light import SimEngineLight, SimEngineLightAILMixin


class SimEngineSSATraversal(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    """
    This engine collects all register and stack variable locations and links them to the block of their creation.
    """

    def __init__(self, arch, sp_tracker=None, bp_as_gpr: bool = False, def_to_loc=None, loc_to_defs=None):
        super().__init__()

        self.arch = arch
        self.sp_tracker = sp_tracker
        self.bp_as_gpr = bp_as_gpr

        self.def_to_loc = def_to_loc if def_to_loc is not None else OrderedDict()
        self.loc_to_defs = loc_to_defs if loc_to_defs is not None else OrderedDict()

    def _handle_Assignment(self, stmt: Assignment):
        if isinstance(stmt.dst, Register):
            codeloc = self._codeloc()
            self.def_to_loc[stmt.dst] = codeloc
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(stmt.dst)
