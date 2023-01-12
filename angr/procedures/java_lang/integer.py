import claripy
import logging

from ..java import JavaSimProcedure
from ...engines.soot.values import SimSootValue_StringRef, SimSootValue_ThisRef

log = logging.getLogger(name=__name__)


class IntToInteger(JavaSimProcedure):
    __provides__ = (("java.lang.Integer", "<init>(int)"),)

    def run(self, this_ref, int_val):
        log.debug(f"Called SimProcedure java.lang.Integer.<init> with args: {this_ref} {int_val}")
        this_ref.store_field(self.state, "value", "int", int_val)
        return this_ref


class IntegerToInt(JavaSimProcedure):
    __provides__ = (("java.lang.Integer", "intValue()"),)

    def run(self, this_ref):
        log.debug(f"Called SimProcedure java.lang.Integer.intValue with args: {this_ref}")
        return this_ref.get_field(self.state, "value", "int")


class IntegerToString(JavaSimProcedure):
    __provides__ = (("java.lang.Integer", "toString(int)"),)

    def run(self, int_val):
        log.debug(f"Called SimProcedure java.lang.Integer.toString with args: {int_val}")
        return SimSootValue_StringRef.new_string(self.state, claripy.IntToStr(int_val))


class IntegerValueOf(JavaSimProcedure):
    __provides__ = (("java.lang.Integer", "valueOf(int)"),)

    def run(self, int_val):
        log.debug(f"Called SimProcedure java.lang.Integer.valueOf with args: {int_val}")
        obj_ref = SimSootValue_ThisRef.new_object(self.state, "java.lang.Integer")
        obj_ref.store_field(self.state, "value", "int", int_val)
        return obj_ref
