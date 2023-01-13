from typing import Tuple

from ...code_location import CodeLocation


class ExternalCodeLocation(CodeLocation):
    """
    Stands for a program point that originates from outside an analysis' scope.
    i.e. a value loaded from rdi in a callee where the caller has not been analyzed.
    """

    __slots__ = ("call_string",)

    def __init__(self, call_string: Tuple[int, ...] = None):
        super().__init__(0, None)
        self.call_string = call_string if call_string is not None else ()

    def __repr__(self):
        return f"[External {[hex(x) if isinstance(x, int) else x for x in self.call_string]}]"

    def __hash__(self):
        """
        returns the hash value of self.
        """
        if self._hash is None:
            self._hash = hash(
                (
                    self.block_addr,
                    self.stmt_idx,
                    self.sim_procedure,
                    self.ins_addr,
                    self.context,
                    self.block_idx,
                    self.call_string,
                )
            )
        return self._hash
