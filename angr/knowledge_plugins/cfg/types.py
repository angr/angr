from __future__ import annotations

from archinfo.arch_soot import SootAddressDescriptor

from .block_id import BlockID


CFGNODE_K = tuple[int, int]  # tuple[addr, size]
CFGENODE_K = tuple[BlockID, int, int]  # tuple[BlockID, size, looping times]
SOOTNODE_K = SootAddressDescriptor
K = CFGNODE_K | CFGENODE_K | SOOTNODE_K

__all__ = ["CFGENODE_K", "CFGNODE_K", "SOOTNODE_K", "K"]
