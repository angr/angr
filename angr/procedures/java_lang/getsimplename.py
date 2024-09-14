from __future__ import annotations
import logging

from ..java import JavaSimProcedure
from angr.engines.soot.values.strref import SimSootValue_StringRef

l = logging.getLogger(name=__name__)


class GetSimpleName(JavaSimProcedure):
    __provides__ = (("java.lang.Class", "getSimpleName()"),)

    def run(self, this):  # pylint: disable=arguments-differ
        class_simple_name = this.type.split(".")[-1]
        return SimSootValue_StringRef.new_string(self.state, self.state.solver.StringV(class_simple_name))
