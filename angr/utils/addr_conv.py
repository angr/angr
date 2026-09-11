from __future__ import annotations

from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor

from angr.protos.primitives_pb2 import SootAddress

# An address as the angrDb messages carry it: a native address, or a Soot method or statement address.
type Address = int | SootAddressDescriptor | SootMethodDescriptor


def soot_addr_to_pb(addr: SootAddressDescriptor | SootMethodDescriptor, pb: SootAddress) -> None:
    """
    Fill a SootAddress message from a Soot method or statement address.
    """
    method = addr.method if isinstance(addr, SootAddressDescriptor) else addr
    pb.class_name = method.class_name
    pb.method_name = method.name
    pb.params.extend(method.params)
    if isinstance(addr, SootAddressDescriptor):
        pb.block_idx = addr.block_idx
        if addr.stmt_idx is not None:
            pb.stmt_idx = addr.stmt_idx


def soot_addr_from_pb(pb: SootAddress) -> SootAddressDescriptor | SootMethodDescriptor:
    """
    Build a Soot method or statement address from a SootAddress message.
    """
    method = SootMethodDescriptor(pb.class_name, pb.method_name, tuple(pb.params))
    if not pb.HasField("block_idx"):
        return method
    return SootAddressDescriptor(method, pb.block_idx, pb.stmt_idx if pb.HasField("stmt_idx") else None)


def addr_to_pb(cmsg, field: str, addr) -> None:
    """
    Store an address in ``cmsg``, using the uint64 field ``field`` for an integer address and the SootAddress
    field ``soot_<field>`` for a Soot one.
    """
    if isinstance(addr, int):
        setattr(cmsg, field, addr)
    else:
        soot_addr_to_pb(addr, getattr(cmsg, "soot_" + field))


def addr_from_pb(cmsg, field: str) -> Address:
    """
    Read back an address stored by :func:`addr_to_pb`.
    """
    soot_field = "soot_" + field
    if cmsg.HasField(soot_field):
        return soot_addr_from_pb(getattr(cmsg, soot_field))
    return getattr(cmsg, field)


def optional_addr_from_pb(cmsg, field: str) -> Address | None:
    """
    Read back an address stored by :func:`addr_to_pb` in an optional field, or None when it was never stored.
    """
    soot_field = "soot_" + field
    if cmsg.HasField(soot_field):
        return soot_addr_from_pb(getattr(cmsg, soot_field))
    return getattr(cmsg, field) if cmsg.HasField(field) else None
