import struct
from typing import List


class MessageBase:
    def serialize(self) -> bytes:
        raise NotImplementedError()

    b = serialize

    @classmethod
    def unserialize(cls, stream: bytes) -> 'MessageBase':
        msg_num = stream[0]
        if msg_num == 2:
            return SyscallReturn.unb(stream[1:])
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

    def unserialize(cls, stream) -> 'SyscallReturn':
        retval = struct.unpack("<Q", stream[0:8])[0]
        return SyscallReturn(retval)


class RetrieveMemory(MessageBase):

    MSG_NUM = 3

    def __init__(self, addr: int, size: int, writing: bool):
        self.addr = addr
        self.size = size
        self.writing = writing

    def unserialize(cls, stream) -> 'RetrieveMemory':
        addr = struct.unpack("<Q", stream[0:8])[0]
        size = struct.unpack("<Q", stream[8:16])[0]
        writing = struct.unpack("b", stream[16])[0] == 0
        o = RetrieveMemory(addr, size, writing)
        return o
