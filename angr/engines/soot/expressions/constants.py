from __future__ import annotations
import claripy
from archinfo.arch_soot import SootClassDescriptor, SootNullConstant
from claripy import FSORT_DOUBLE, FSORT_FLOAT

from ..values import SimSootValue_StringRef
from .base import SimSootExpr


class SimSootExpr_IntConstant(SimSootExpr):
    def _execute(self):
        self.expr = claripy.BVV(self.expr.value, 32)


class SimSootExpr_LongConstant(SimSootExpr):
    def _execute(self):
        self.expr = claripy.BVV(self.expr.value, 64)


class SimSootExpr_FloatConstant(SimSootExpr):
    def _execute(self):
        self.expr = claripy.FPV(self.expr.value, FSORT_FLOAT)


class SimSootExpr_DoubleConstant(SimSootExpr):
    def _execute(self):
        self.expr = claripy.FPV(self.expr.value, FSORT_DOUBLE)


class SimSootExpr_StringConstant(SimSootExpr):
    def _execute(self):
        # strip away quotes introduced by soot
        str_val = claripy.StringV(self.expr.value.strip('"'))
        str_ref = SimSootValue_StringRef(self.state.memory.get_new_uuid())
        self.state.memory.store(str_ref, str_val)
        self.expr = str_ref


class SimSootExpr_ClassConstant(SimSootExpr):
    def _execute(self):
        class_name = self.expr.value[8:-2].replace("/", ".")
        self.expr = SootClassDescriptor(class_name)


class SimSootExpr_NullConstant(SimSootExpr):
    def _execute(self):
        self.expr = SootNullConstant()
