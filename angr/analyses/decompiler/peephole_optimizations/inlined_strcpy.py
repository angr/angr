# pylint:disable=arguments-differ
from typing import Tuple, Optional
import string

from archinfo import Endness

from ailment.expression import Const
from ailment.statement import Call, Store

from .base import PeepholeOptimizationStmtBase


ASCII_PRINTABLES = set(string.printable)
ASCII_DIGITS = set(string.digits)


class InlinedStrcpy(PeepholeOptimizationStmtBase):
    """
    Simplifies inlined string copying logic into calls to strcpy.
    """

    __slots__ = ()

    NAME = "Simplifying inlined strcpy"
    stmt_classes = (Store,)

    def optimize(self, stmt: Store, **kwargs):
        if isinstance(stmt.data, Const):
            r, s = self.is_integer_likely_a_string(stmt.data.value, stmt.data.size, stmt.endness)
            if r:
                # replace it with a call to strncpy
                str_id = self.kb.custom_strings.allocate(s.encode("ascii"))
                return Call(
                    stmt.idx,
                    "strncpy",
                    args=[
                        stmt.addr,
                        Const(None, None, str_id, stmt.addr.bits, custom_string=True),
                        Const(None, None, len(s), self.project.arch.bits),
                    ],
                    **stmt.tags,
                )

        return None

    @staticmethod
    def is_integer_likely_a_string(
        v: int, size: int, endness: Endness, min_length: int = 4
    ) -> Tuple[bool, Optional[str]]:
        # we need at least four bytes of printable characters

        chars = []
        if endness == Endness.LE:
            while v != 0:
                byt = v & 0xFF
                if chr(byt) not in ASCII_PRINTABLES:
                    return False, None
                chars.append(chr(byt))
                v >>= 8

        elif endness == Endness.BE:
            first_non_zero = False
            for _ in range(size):
                byt = v & 0xFF
                v >>= 8
                if byt == 0:
                    if first_non_zero:
                        return False, None
                    continue
                first_non_zero = True  # this is the first non-zero byte
                if chr(byt) not in ASCII_PRINTABLES:
                    return False, None
                chars.append(chr(byt))
            chars = chars[::-1]
        else:
            # unsupported endness
            return False, None

        if len(chars) >= min_length:
            if len(chars) <= 4 and all(ch in ASCII_DIGITS for ch in chars):
                return False, None
            return True, "".join(chars)
        return False, None
