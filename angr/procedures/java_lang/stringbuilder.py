import claripy
import logging

from ..java import JavaSimProcedure
from ...engines.soot.values import SimSootValue_StringRef

log = logging.getLogger(name=__name__)


class StringBuilderInit(JavaSimProcedure):
    __provides__ = (("java.lang.StringBuilder", "<init>()"),)

    def run(self, this_ref):
        log.debug(f"Called SimProcedure java.lang.StringBuilder.<init> with args: {this_ref}")

        str_ref = SimSootValue_StringRef.new_string(self.state, claripy.StringV(""))
        this_ref.store_field(self.state, "str", "java.lang.String", str_ref)
        return


class StringBuilderAppend(JavaSimProcedure):
    __provides__ = (("java.lang.StringBuilder", "append(java.lang.String)"), ("java.lang.StringBuilder", "append(int)"))

    def run(self, this_ref, thing):
        log.debug(f"Called SimProcedure java.lang.StringBuilder.append with args: {this_ref} {thing}")
        field = this_ref.get_field(self.state, "str", "java.lang.String")
        field_str = self.state.memory.load(field)

        if isinstance(thing, SimSootValue_StringRef):
            thing_str = self.state.memory.load(thing)

        elif isinstance(thing, claripy.ast.BV):
            thing_str = claripy.IntToStr(thing)

        else:
            log.error("NotImplemented, unsupported type for StringBuilder.append")
            return this_ref

        result = claripy.StrConcat(field_str, thing_str)
        new_str_ref = SimSootValue_StringRef.new_string(self.state, result)
        this_ref.store_field(self.state, "str", "java.lang.String", new_str_ref)

        return this_ref
