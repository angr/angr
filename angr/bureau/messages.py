import struct
from typing import List, Optional


class MessageBase:
    def serialize(self) -> bytes:
        raise NotImplementedError()

    b = serialize

    @classmethod
    def unserialize(cls, stream: bytes) -> 'MessageBase':
        msg_num = struct.unpack("<H", stream[:2])[0]
        if msg_num == 2:
            return SyscallReturn.unserialize(stream[2:])
        elif msg_num == 6:
            return RetrieveMemory.unserialize(stream[2:])
        raise NotImplementedError()

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


class SyscallReturn(MessageBase):

    MSG_NUM = 2

    def __init__(self, retval: int):
        self.retval = retval

    @classmethod
    def unserialize(cls, stream) -> 'SyscallReturn':
        retval = struct.unpack("<Q", stream[0:8])[0]
        return SyscallReturn(retval)


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
