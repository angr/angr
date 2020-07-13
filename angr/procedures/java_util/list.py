import claripy
import logging

from ..java import JavaSimProcedure
from ...engines.soot.expressions import SimSootExpr_NewArray
from ...engines.soot.values import SimSootValue_ThisRef
from .collection import ELEMS, SIZE

log = logging.getLogger(name=__name__)


class ListInit(JavaSimProcedure):

    __provides__ = (
        ('java.util.List', '<init>()'),
        ('java.util.LinkedList', '<init>()'),
        ('java.util.ArrayList', '<init>()')
    )

    def run(self, this_ref):
        log.debug('Called SimProcedure java.util.List.<init> with args: {}'.format(this_ref))

        array_ref = SimSootExpr_NewArray.new_array(self.state, 'java.lang.Object', claripy.BVV(1000, 32))
        this_ref.store_field(self.state, ELEMS, 'java.lang.Object[]', array_ref)
        this_ref.store_field(self.state, SIZE, 'int', claripy.BVV(0, 32))

        return


class ListAdd(JavaSimProcedure):

    __provides__ = (
        ('java.util.List', 'add(java.lang.Object)'),
        ('java.util.LinkedList', 'add(java.lang.Object)'),
        ('java.util.ArrayList', 'add(java.lang.Object)')
    )

    def run(self, this_ref, obj_ref):
        log.debug('Called SimProcedure java.util.List.add with args: {} {}'.format(this_ref, obj_ref))

        if this_ref.symbolic:
            return claripy.BoolS('list.append')

        try:
            array_ref = this_ref.load_field(self.state, ELEMS, 'java.lang.Object[]')
            array_len = this_ref.load_field(self.state, SIZE, 'int')
            self.state.javavm_memory.store_array_element(array_ref, array_len, obj_ref)
            # Update size
            new_array_len = claripy.BVV(self.state.solver.eval(array_len) + 1, 32)
            this_ref.store_field(self.state, SIZE, 'int', new_array_len)
        except KeyError:
            log.warning('Could not add element to list {}'.format(this_ref))

        return claripy.BoolV(1)

class ListAddAtIndex(JavaSimProcedure):

    __provides__ = (
        ('java.util.List', 'add(int,java.lang.Object)'),
        ('java.util.LinkedList', 'add(int,java.lang.Object)'),
        ('java.util.ArrayList', 'add(int,java.lang.Object)')
    )

    def run(self, this_ref, idx, obj_ref):
        log.debug('Called SimProcedure java.util.List.add with args: {} {}'.format(this_ref, obj_ref))

        if this_ref.symbolic:
            return claripy.BoolS('list.append')

        try:
            array_ref = this_ref.load_field(self.state, ELEMS, 'java.lang.Object[]')
            array_len = this_ref.load_field(self.state, SIZE, 'int')

            array_len_concrete = self.state.solver.eval(array_len)
            # We don't support symbolic indexing for now
            idx_concrete = self.state.solver.eval(idx)

            if idx_concrete <= array_len_concrete - 1:
                i = array_len_concrete - 1
                # Shift all the element after the idx to the left
                while i >= idx_concrete:
                    elem = self.state.javavm_memory.load_array_element(array_ref, i)
                    self.state.javavm_memory.store_array_element(array_ref, i+1, elem)
                    i -= 1
            # Insert the element
            self.state.javavm_memory.store_array_element(array_ref, idx, obj_ref)
            # Update size
            new_array_len = claripy.BVV(self.state.solver.eval(array_len) + 1, 32)
            this_ref.store_field(self.state, SIZE, 'int', new_array_len)
        except KeyError:
            log.warning('Could not add element to list {}'.format(this_ref))

        return claripy.BoolV(1)


class ListGet(JavaSimProcedure):

    __provides__ = (
        ('java.util.List', 'get(int)'),
        ('java.util.LinkedList', 'get(int)'),
        ('java.util.ArrayList', 'get(int)')
    )

    def run(self, this_ref, index):
        log.debug('Called SimProcedure java.util.List.get with args: {} {}'.format(this_ref, index))

        if this_ref.symbolic:
            return SimSootValue_ThisRef.new_object(self.state, 'java.lang.Object', symbolic=True)

        try:
            array_ref = this_ref.load_field(self.state, ELEMS, 'java.lang.Object[]')
            array_len = this_ref.load_field(self.state, SIZE, 'int')
            # TODO should check boundaries?

            return self.state.javavm_memory.load_array_element(array_ref, index)
        except KeyError:
            return SimSootValue_ThisRef.new_object(self.state, 'java.lang.Object', symbolic=True)


class ListGetFirst(JavaSimProcedure):

    __provides__ = (
        ('java.util.List', 'getFirst()'),
        ('java.util.LinkedList', 'getFirst()'),
        ('java.util.ArrayList', 'getFirst()')
    )

    def run(self, this_ref):
        log.debug('Called SimProcedure java.util.List.getFirst with args: {}'.format(this_ref))

        if this_ref.symbolic:
            return SimSootValue_ThisRef.new_object(self.state, 'java.lang.Object', symbolic=True)

        try:
            array_ref = this_ref.load_field(self.state, ELEMS, 'java.lang.Object[]')
            array_len = this_ref.load_field(self.state, SIZE, 'int')

            # TODO should check boundaries?

            return self.state.javavm_memory.load_array_element(array_ref, claripy.BVV(0, 32))
        except KeyError:
            return SimSootValue_ThisRef.new_object(self.state, 'java.lang.Object', symbolic=True)


class ListSize(JavaSimProcedure):

    __provides__ = (
        ('java.util.List', 'size()'),
        ('java.util.LinkedList', 'size()'),
        ('java.util.ArrayList', 'size()')
    )

    def run(self, this_ref):
        log.debug('Called SimProcedure java.util.List.size with args: {}'.format(this_ref))

        if this_ref.symbolic:
            return claripy.BVS('list_size', 32)

        try:
            return this_ref.load_field(self.state, SIZE, 'int')
        except KeyError:
            return claripy.BVS('list_size', 32)

