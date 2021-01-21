from ailment.statement import Assignment
from ailment.expression import Load, Const

from .base import PeepholeOptimizationStmtBase


class ConstantDereferences(PeepholeOptimizationStmtBase):
    __slots__ = ()

    name = "Dereference constant references"
    stmt_classes = (Assignment, )  # all expressions are allowed

    def optimize(self, stmt: Assignment):

        if isinstance(stmt.src, Load) and isinstance(stmt.src.addr, Const):
            # is it loading from a read-only section?
            sec = self.project.loader.find_section_containing(stmt.src.addr.value)
            if sec is not None and sec.is_readable and not sec.is_writable:
                # do we know the value that it's reading?
                try:
                    val = self.project.loader.memory.unpack_word(stmt.src.addr.value, size=self.project.arch.bytes)
                except KeyError:
                    return stmt

                return Assignment(stmt.idx, stmt.dst,
                                  Const(None, None, val, stmt.src.size * self.project.arch.byte_width),
                                  **stmt.tags,
                                  )

        return None
