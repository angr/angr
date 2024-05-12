class CallSite:
    """
    Describes a call site on a CFG.
    """

    __slots__ = (
        "caller_func_addr",
        "block_addr",
        "callee_func_addr",
    )

    def __init__(self, caller_func_addr: int, block_addr: int | None, callee_func_addr: int):
        self.caller_func_addr = caller_func_addr
        self.callee_func_addr = callee_func_addr
        self.block_addr = block_addr

    def __repr__(self):
        result = f"<CallSite in function {self.caller_func_addr:#x}, calling {self.callee_func_addr:#x}"
        if self.block_addr is not None:
            result += "at block %#x" % self.block_addr
        result += ">"
        return result

    def __eq__(self, other):
        return (
            self.caller_func_addr == other.caller_func_addr
            and self.callee_func_addr == other.callee_func_addr
            and self.block_addr == other.block_addr
        )


class CallTrace:
    """
    Describes a series of functions calls to get from one function (current_function_address()) to another function or
    a basic block (self.target).
    """

    __slots__ = (
        "callsites",
        "target",
    )

    def __init__(self, target: int):
        self.target = target
        self.callsites: list[CallSite] = []

    def __repr__(self):
        return "<Trace with %d callsites>" % len(self.callsites)

    def current_function_address(self) -> int:
        if not self.callsites:
            return self.target
        return self.callsites[-1].caller_func_addr

    def step_back(self, caller_func_addr: int, block_addr: int | None, callee_func_addr) -> "CallTrace":
        # create a new CallSite object
        site = CallSite(caller_func_addr, block_addr, callee_func_addr)
        t = self.copy()
        t.callsites.append(site)
        return t

    def includes_function(self, func_addr: int) -> bool:
        if self.target == func_addr:
            return True
        if any(cs.caller_func_addr == func_addr for cs in self.callsites):
            return True
        return False

    def copy(self) -> "CallTrace":
        t = CallTrace(self.target)
        t.callsites = self.callsites[::]
        return t
