from ailment.expression import Load, Const
from cle.backends import Blob

from .base import PeepholeOptimizationExprBase


class ConstantDereferences(PeepholeOptimizationExprBase):
    """
    Dereferences constant memory loads from read-only memory regions.
    """

    __slots__ = ()

    NAME = "Dereference constant references"
    expr_classes = (Load,)

    def optimize(self, expr: Load, **kwargs):
        if isinstance(expr.addr, Const):
            # is it loading from a read-only section?
            sec = self.project.loader.find_section_containing(expr.addr.value)
            if sec is not None and sec.is_readable and (not sec.is_writable or "got" in sec.name):
                # do we know the value that it's reading?
                try:
                    val = self.project.loader.memory.unpack_word(expr.addr.value, size=expr.size)
                except KeyError:
                    return None

                return Const(None, None, val, expr.bits, **expr.tags, deref_src_addr=expr.addr.value)

            # is it loading from a blob?
            obj = self.project.loader.find_object_containing(expr.addr.value)
            if obj is not None and isinstance(obj, Blob):
                # do we know the value that it's reading?
                try:
                    val = self.project.loader.memory.unpack_word(expr.addr.value, size=self.project.arch.bytes)
                except KeyError:
                    return None

                return Const(None, None, val, expr.bits, **expr.tags, deref_src_addr=expr.addr.value)

        return None
