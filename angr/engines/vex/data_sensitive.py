from __future__ import annotations

import pyvex


class DataSensitiveRdTmp(pyvex.expr.RdTmp):
    """
    An RdTmp tagged with the block it was read in, so that data-sensitive analyses can tell apart temporaries with the
    same index in different blocks. It has its own tag, so engines dispatch it separately from RdTmp.
    """

    __slots__ = ("block_id",)

    tag = "Iex_DataSensitiveRdTmp"
    tag_int = pyvex.expr.tag_count

    def __init__(self, tmp, block_id):
        super().__init__(tmp)
        self.block_id = block_id


# lets IRExpr._to_c find the class; libVEX has no such tag, so lifting never produces one
pyvex.expr.tag_to_expr_mapping[DataSensitiveRdTmp.tag] = DataSensitiveRdTmp


class DataSensitiveU64(pyvex.const.U64):
    def __init__(self, value, block_id):
        super().__init__(value)
        self.block_id = block_id


class DataSensitiveU32(pyvex.const.U32):
    def __init__(self, value, block_id):
        super().__init__(value)
        self.block_id = block_id


def is_same_ip_branch(irsb) -> bool:
    """
    Does the block branch to one address under two different block ids? That is a VM branch whose two
    successors resume at the same handler and differ only in VM state (see the same-ip split guard).
    """
    exit_stmt = next(
        (s for s in reversed(irsb.statements) if isinstance(s, pyvex.stmt.Exit) and s.jumpkind != "Ijk_EmWarn"), None
    )
    if exit_stmt is None:
        return False
    exit_bid = getattr(exit_stmt.dst, "block_id", None)
    next_con = getattr(irsb.next, "con", None)
    next_bid = getattr(next_con, "block_id", None)
    return (
        exit_bid is not None and next_bid is not None and exit_bid != next_bid and exit_stmt.dst.value == next_con.value
    )
