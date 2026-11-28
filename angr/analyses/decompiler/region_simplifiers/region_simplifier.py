from __future__ import annotations

from typing import TYPE_CHECKING

from angr.ailment import Manager
from angr.analyses.analysis import AnalysesHub, Analysis
from angr.analyses.decompiler.goto_manager import GotoManager

from .passes import REGION_SIMPLIFICATION_PASSES

if TYPE_CHECKING:
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal


class RegionSimplifier(Analysis):
    """
    Simplifies a given region by running the passes in REGION_SIMPLIFICATION_PASSES in order.

    :ivar structure_only:   Only run the passes that may change the structure of the region. Structurability probes use
                            this mode.
    """

    def __init__(
        self,
        func,
        region,
        ail_manager: Manager,
        arg_vvars: set[int] | None = None,
        simplify_switches: bool = True,
        simplify_ifelse: bool = True,
        variable_manager: VariableManagerInternal | None = None,
        loopctr_naming: bool = True,
        structure_only: bool = False,
    ):
        self.func = func
        self.region = region
        self.arg_vvars = arg_vvars
        self.ail_manager = ail_manager
        self.simplify_switches = simplify_switches
        self.simplify_ifelse = simplify_ifelse
        self.variable_manager = variable_manager
        self.loopctr_naming = loopctr_naming
        self.structure_only = structure_only

        self.goto_manager: GotoManager | None = None
        self.result = self.region

        self._simplify()

    def _simplify(self):
        r = self.region
        for simplification_pass in REGION_SIMPLIFICATION_PASSES:
            if self.structure_only and not simplification_pass.changes_structure:
                continue
            if not simplification_pass.enabled(self):
                continue
            r = simplification_pass.run(self, r)
        self.result = r


AnalysesHub.register_default("RegionSimplifier", RegionSimplifier)
