from __future__ import annotations

from pyvex import IRSB
from pyvex.stmt import WrTmp


def get_tmp_def_stmt(vex_block: IRSB, tmp_idx: int) -> int | None:
    for i, stmt in enumerate(vex_block.statements):
        if isinstance(stmt, WrTmp) and stmt.tmp == tmp_idx:
            return i
    return None
