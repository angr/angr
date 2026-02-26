from __future__ import annotations

from typing import Literal

from archinfo.arch_soot import SootAddressDescriptor

from .block_id import BlockID


CFGNODE_K = tuple[int, int]  # tuple[addr, size]
CFGENODE_K = tuple[BlockID, int, int]  # tuple[BlockID, size, looping times]
SOOTNODE_K = SootAddressDescriptor
K = CFGNODE_K | CFGENODE_K | SOOTNODE_K

CFG_ADDR_TYPES = Literal["int", "block_id", "soot"]

__all__ = ["CFGENODE_K", "CFGNODE_K", "CFG_ADDR_TYPES", "SOOTNODE_K", "K"]
