
class BaseAction:

    __slots__ = ()

    pass


class SyscallReturnAction(BaseAction):

    __slots__ = ('retval', )

    def __init__(self, retval):
        self.retval = retval


class WriteMemoryAction(BaseAction):

    __slots__ = ('addr', 'data', )

    def __init__(self, addr, data):
        self.addr = addr
        self.data = data
