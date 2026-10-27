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
