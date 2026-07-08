from __future__ import annotations

import logging

from angr import claripy
from angr.engines.soot.values.strref import SimSootValue_StringRef
from angr.procedures.java import JavaSimProcedure

l = logging.getLogger(name=__name__)


class GetSimpleName(JavaSimProcedure):
    __provides__ = (("java.lang.Class", "getSimpleName()"),)

    def run(self, this):  # pylint: disable=arguments-differ
        class_simple_name = this.type.split(".")[-1]
        return SimSootValue_StringRef.new_string(self.state, claripy.StringV(class_simple_name))
