from __future__ import annotations

from typing import TYPE_CHECKING

from archinfo.arch_soot import SootAddressDescriptor

if TYPE_CHECKING:
    from typing import TypeAlias


AddressType: TypeAlias = int | SootAddressDescriptor
