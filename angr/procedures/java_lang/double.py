from __future__ import annotations
import logging

import claripy

from ..java import JavaSimProcedure

log = logging.getLogger(name=__name__)


class ParseDouble(JavaSimProcedure):
    __provides__ = (("java.lang.Double", "parseDouble(java.lang.String)"),)

    def run(self, str_ref):
        log.debug(f"Called SimProcedure java.lang.Double.parseDouble with args: {str_ref}")
        str_ = self.state.memory.load(str_ref)

        if str_.concrete:
            str_value = self.state.solver.eval(str_)
            # this can raise a ValueError if str_value is not convertible to float
            double_val = float(str_value)
            return claripy.FPV(double_val, claripy.FSORT_DOUBLE)

        return claripy.StrToInt(str_, self.arch.bits)
