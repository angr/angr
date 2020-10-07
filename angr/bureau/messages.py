import struct
from typing import List, Optional


class MessageBase:
    def serialize(self) -> bytes:
        raise NotImplementedError()

    b = serialize

    @classmethod
    def unserialize(cls, stream: bytes) -> 'MessageBase':
        msg_num = struct.unpack("<H", stream[:2])[0]
        msg_cls = MSGS.get(msg_num, None)
        if msg_cls is None:
            raise NotImplementedError("Unsupported message type number %d" % msg_num)
        return msg_cls.unserialize(stream[2:])

    unb = unserialize


class InvokeSyscall(MessageBase):

    MSG_NUM = 1

    def __init__(self, num: int, args: List[int]):
        self.num = num
        self.args = args

    def serialize(self) -> bytes:
        stream = struct.pack("<H", self.MSG_NUM) + \
                 struct.pack("<I", self.num) + \
                 struct.pack("<I", len(self.args))

        for arg in self.args:
            stream += struct.pack("<Q", arg)

        return stream

    def __repr__(self):
        return "<InvokeSyscall: num=%d, args=%s>" % (self.num, self.args)


class SyscallReturn(MessageBase):

    MSG_NUM = 2

    def __init__(self, retval: int):
        self.retval = retval

    @classmethod
    def unserialize(cls, stream) -> 'SyscallReturn':
        retval = struct.unpack("<Q", stream[0:8])[0]
        return SyscallReturn(retval)

    def __repr__(self):
        return "<SyscallReturn: retval=%d>" % self.retval


class RetrieveMemory(MessageBase):

    MSG_NUM = 6

    def __init__(self, addr: int, size: int, writing: bool):
        self.addr = addr
        self.size = size
        self.writing = writing

    @classmethod
    def unserialize(cls, stream) -> 'RetrieveMemory':
        addr = struct.unpack("<Q", stream[0:8])[0]
        size = struct.unpack("<Q", stream[8:16])[0]
        writing = stream[16] != 0
        o = RetrieveMemory(addr, size, writing)
        return o

    def __repr__(self):
        return "<RetrieveMemory: addr=%#x, size=%d, writing=%s>" % (self.addr, self.size, self.writing)


class RetrieveMemoryReturnResult:
    OK = 0
    ABORT = 1
    FAULT = 2


class RetrieveMemoryReturn(MessageBase):

    MSG_NUM = 7

    def __init__(self, result: int, data: Optional[bytes]):
        self.ret = result
        self.data = data

    def serialize(self) -> bytes:
        stream = struct.pack("<H", self.MSG_NUM) + \
                 bytes([self.ret])

        if self.data:
            stream += self.data

        return stream


class SyncMemory(MessageBase):

    MSG_NUM = 8

    def __init__(self, addr: int, size: int, data: bytes):
        self.addr = addr
        self.size = size
        self.data = data

    def unserialize(cls, stream: bytes) -> 'SyncMemory':
        addr = struct.unpack("<Q", stream[0:8])[0]
        size = struct.unpack("<Q", stream[8:16])[0]
        data = stream[16:]
        o = SyncMemory(addr, size, data)
        return o


MSGS = {
    InvokeSyscall.MSG_NUM: InvokeSyscall,
    SyscallReturn.MSG_NUM: SyscallReturn,
    RetrieveMemory.MSG_NUM: RetrieveMemory,
    RetrieveMemoryReturn.MSG_NUM: RetrieveMemoryReturn,
    SyncMemory.MSG_NUM: SyncMemory,
}
