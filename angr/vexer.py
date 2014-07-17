import pyvex
import logging
l = logging.getLogger("angr.vexer")

class VEXer:
    def __init__(self, mem, arch, max_size=None, num_inst=None, traceflags=None, use_cache=None):
        self.mem = mem
        self.arch = arch
        self.max_size = 400 if max_size is None else max_size
        self.num_inst = 99 if num_inst is None else num_inst
        self.traceflags = 0 if traceflags is None else traceflags
        self.use_cache = True if use_cache is None else use_cache
        self.irsb_cache = { }


    def block(self, addr, max_size=None, num_inst=None, traceflags=0, thumb=False):
        """
        Returns a pyvex block starting at address addr

        Optional params:

        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param traceflags: traceflags to be passed to VEX. Default: 0
        """
        max_size = 400 if max_size is None else max_size
        num_inst = 99 if num_inst is None else num_inst

        # TODO: FIXME: figure out what to do if we're about to exhaust the memory
        # (we can probably figure out how many instructions we have left by talking to IDA)

        # Try to find the actual size of the block, stop at the first keyerror
        arr = []
        for i in range(addr, addr+max_size):
            try:
                arr.append(self.mem[i])
            except KeyError:
                break

        buff = "".join(arr)

        # deal with thumb mode in ARM, sending an odd address and an offset
        # into the string
        byte_offset = 0

        if self.arch.name == "ARM" and thumb:
            addr += 1
            byte_offset = 1

        if not buff:
            raise AngrMemoryError("No bytes in memory for block starting at 0x%x." % addr)

        l.debug("Creating pyvex.IRSB of arch %s at 0x%x", self.arch.name, addr)

        if self.use_cache:
            cache_key = (buff, addr, num_inst, self.arch.vex_arch, byte_offset, thumb)
            if cache_key in self.irsb_cache:
                return self.irsb_cache[cache_key]

        if num_inst:
            block = pyvex.IRSB(bytes=buff, mem_addr=addr, num_inst=num_inst, arch=self.arch.vex_arch, bytes_offset=byte_offset, traceflags=traceflags)
        else:
            block = pyvex.IRSB(bytes=buff, mem_addr=addr,
                               arch=self.arch.vex_arch,
                               bytes_offset=byte_offset, traceflags=traceflags)

        if self.use_cache:
            self.irsb_cache[cache_key] = block

        return block

    def __getitem__(self, addr):
        return self.block(addr)

from .errors import AngrMemoryError
