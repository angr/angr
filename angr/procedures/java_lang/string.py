import logging

import claripy

from ..java import JavaSimProcedure
from ...engines.soot.expressions import SimSootExpr_NewArray
from ...engines.soot.values import SimSootValue_ArrayRef, SimSootValue_StringRef

log = logging.getLogger(name=__name__)


class StringConcat(JavaSimProcedure):

    __provides__ = (
        ("java.lang.String", "concat(java.lang.String)"),
    )

    def run(self, str_1_ref, str_2_ref): # pylint: disable=arguments-differ
        log.debug("Called SimProcedure java.string.concat with args: {} {}".format(str_1_ref, str_2_ref))
        str_1 = self.state.javavm_memory.load(str_1_ref)
        str_2 = self.state.javavm_memory.load(str_2_ref)
        result = claripy.StrConcat(str_1, str_2)
        return SimSootValue_StringRef.new_object(self.state, result)


class StringEquals(JavaSimProcedure):

    __provides__ = (
        ("java.lang.String", "equals(java.lang.Object)"),
    )

    def run(self, str_ref_1, str_ref_2): # pylint: disable=unused-argument
        str_1 = self.state.javavm_memory.load(str_ref_1)
        str_2 = self.state.javavm_memory.load(str_ref_2)
        return self.state.solver.If(str_1 == str_2,
                                    self.state.solver.BVV(1, 32),
                                    self.state.solver.BVV(0, 32))


class StringSplit(JavaSimProcedure):

    __provides__ = (
        ('java.lang.String', 'split(java.lang.String)'),
    )

    def generate_symbolic_array(self, state, max_length=1000):
        return self.this_ref

    def run(self, this_ref,  separator_ref):
        log.debug('Called SimProcedure java.lang.String.split with args: {}, {}'.format(this_ref, separator_ref))
        self.this_ref = this_ref
        this = self.state.javavm_memory.load(this_ref)
        separator = self.state.javavm_memory.load(separator_ref)

        if this.concrete and separator.concrete:
            # FIXME: escaping should be fixed in claripy
            separator_value = self.state.solver.eval(separator).replace('\\n', '\n')
            values = self.state.solver.eval(this).split(separator_value)
            str_array = SimSootExpr_NewArray.new_array(self.state, 'java.lang.String', claripy.BVV(len(values), 32))

            for idx, value in enumerate(values):
                value_ref = SimSootValue_StringRef.new_object(self.state, claripy.StringV(value))
                elem_ref = SimSootValue_ArrayRef(str_array, idx)
                self.state.javavm_memory.store(elem_ref, value_ref)

        else:
            str_array = SimSootExpr_NewArray.new_array(self.state, 'java.lang.String', claripy.BVS('array_size', 32))
            str_array.add_default_value_generator(self.generate_symbolic_array)

        return str_array


class StringLength(JavaSimProcedure):

    __provides__ = (
        ('java.lang.String', 'length()'),
    )

    def run(self, this_str):
        log.debug('Called SimProcedure java.lang.String.length with args: {}'.format(this_str))

        return this_str.get_field(self.state, 'length', 'int')


class StringCharAt(JavaSimProcedure):

    __provides__ = (
        ('java.lang.String', 'charAt(int)'),
    )

    def run(self, this_str, index):
        log.debug('Called SimProcedure java.lang.String.charAt with args: {} {}'.format(this_str, index))

        char_str = claripy.StrSubstr(index, claripy.BVV(1, 32), self.state.javavm_memory.load(this_str))
        return SimSootValue_StringRef.new_object(self.state, char_str)
