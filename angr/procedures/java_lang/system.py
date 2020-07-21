import logging
import claripy

from ..java import JavaSimProcedure

log = logging.getLogger(name=__name__)


class SystemCurrentTimeMillis(JavaSimProcedure):

    __provides__ = (
        ('java.lang.System', 'currentTimeMillis()'),
    )

    def run(self):
        log.debug('Called SimProcedure java.lang.System.currentTimeMillis with args')

        from time import time
        return claripy.BVV(int(time() * 1000), 64)

class SystemArrayCopy(JavaSimProcedure):

    __provides__ = (
        ('java.lang.System', 'arraycopy(java.lang.Object,int,java.lang.Object,int,int)'),
    )

    def run(self, array_ref_src, src_idx, array_ref_dst, dst_idx, length):
        log.debug('Called SimProcedure java.lang.System.arraycopy with args {} {} {} {} {}'.format(
            array_ref_src, src_idx, array_ref_dst, dst_idx, length))

        # We don't support symbolic indexing
        src_idx_concrete = self.state.solver.eval(src_idx)
        dst_idx_concrete = self.state.solver.eval(dst_idx)
        length_concrete = self.state.solver.eval(length)

        # TODO: Implement checks for OOB exceptions
        for cur_src_idx, cur_dst_idx in zip(
                range(src_idx_concrete, src_idx_concrete+length_concrete),
                range(dst_idx_concrete, dst_idx_concrete+length_concrete)):
            src_elem = self.state.javavm_memory.load_array_element(array_ref_src, cur_src_idx)
            self.state.javavm_memory.store_array_element(array_ref_dst, cur_dst_idx, src_elem)

