import binascii
from typing import Optional


class BaseEdit:
    def __repr__(self):
        raise NotImplementedError()


class BytesEdit(BaseEdit):
    """
    Change the bytes starting at address from orig to new. Orig is optional.
    """
    def __init__(self, addr: int, new: bytes, orig: Optional[bytes]=None):
        self.addr = addr
        self.new = new
        self.orig = orig

    def __repr__(self):
        new = binascii.hexlify(self.new)
        if self.orig is not None:
            orig = binascii.hexlify(self.orig)
            return "BytesEdit @ %#x: %s -> %s" % (self.addr, orig, new)
        return "BytesEdit @ %#x: ?? -> %s" % (self.addr, new)

    def __eq__(self, other):
        return isinstance(other, BytesEdit) \
               and other.addr == self.addr \
               and other.new == self.new \
               and other.orig == self.orig


class MaskedBytesEdit(BaseEdit):
    """
    Change the bytes starting at address from orig to (new & mask) | (orig & ~mask)
    """
    def __init__(self, addr: int, new: bytes, mask: bytes, orig: Optional[bytes]=None):
        self.addr = addr
        self.new = new
        self.mask = mask
        self.orig = orig

    def __repr__(self):
        new = binascii.hexlify(self.new)
        mask = binascii.hexlify(self.mask)
        if self.orig is not None:
            orig = binascii.hexlify(self.orig)
            return "MaskedBytesEdit @ %#x: %s -> %s(%s)" % (self.addr, orig, new, mask)
        return "MaskedBytesEdit @ %#x: ?? -> %s(%s)" % (self.addr, new, mask)

    def __eq__(self, other):
        return isinstance(other, MaskedBytesEdit) \
               and other.addr == self.addr \
               and other.new == self.new \
               and other.mask == self.mask \
               and other.orig == self.orig


class BitsEdit(BaseEdit):
    """
    Change the bits starting at address:offset from orig to new. Orig is optional.
    """
    def __init__(self, addr: int, offset: int, new: int, orig: Optional[int]=None):
        self.addr = addr
        self.offset = offset
        self.orig = orig
        self.new = new

    def __repr__(self):
        new = bin(self.new)
        if self.orig is not None:
            orig = bin(self.orig)
            return "BitsEdit @ %#x:%d: %s -> %s" % (self.addr, self.offset, orig, new)
        return "BitsEdit @ %#x:%d: ?? -> %s" % (self.addr, self.offset, new)

    def __eq__(self, other):
        return isinstance(other, BitsEdit) \
                and other.addr == self.addr \
                and other.new == self.new \
                and other.orig == self.orig
