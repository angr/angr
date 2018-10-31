import logging

import claripy

from ..storage.memory import SimMemory
from ..errors import SimFastMemoryError

l = logging.getLogger(name=__name__)
#l.setLevel(logging.DEBUG)

class SimFastMemory(SimMemory):
    def __init__(self, memory_backer=None, memory_id=None, endness=None, contents=None, width=None, uninitialized_read_handler=None):
        SimMemory.__init__(self, endness=endness)
        self._contents = { } if contents is None else contents
        self.width = width
        self._uninitialized_read_handler = uninitialized_read_handler
        self.id = memory_id
        self._backer = memory_backer

        if self._backer is not None:
            raise SimFastMemoryError("TODO: support memory backers in SimFastMemory")

    # TODO: support backers
    #def _get_from_backer(self, missing_addr, size):
    #   for addr, backer in self._memory_backer.cbackers:
    #       start_backer = missing_addr - addr
    #       if start_backer < 0 and abs(start_backer) >= self._page_size: continue
    #       if start_backer >= len(backer): continue
    #       snip_start = max(0, start_backer)
    #       write_start = max(missing_addr, addr + snip_start)
    #       write_size = self._page_size - write_start%self._page_size
    #       snip = _ffi.buffer(backer)[snip_start:snip_start+write_size]
    #       mo = SimMemoryObject(claripy.BVV(snip), write_start)
    #       self._apply_object_to_page(n*self._page_size, mo, page=new_page)

    def set_state(self, state):
        super(SimFastMemory, self).set_state(state)

        if self.width is None:
            self.width = self.state.arch.bytes

    def _handle_uninitialized_read(self, addr, inspect=True, events=True):
        """
        The default uninitialized read handler. Returns symbolic bytes.
        """
        if self._uninitialized_read_handler is None:
            v = self.state.solver.Unconstrained("%s_%s" % (self.id, addr), self.width*self.state.arch.byte_width, key=self.variable_key_prefix + (addr,), inspect=inspect, events=events)
            return v.reversed if self.endness == "Iend_LE" else v
        else:
            return self._uninitialized_read_handler(self, addr, inspect=inspect, events=events)

    def _translate_addr(self, a): #pylint:disable=no-self-use
        """
        Resolves this address.
        """
        if isinstance(a, claripy.ast.Base) and not a.singlevalued:
            raise SimFastMemoryError("address not supported")
        return self.state.solver.eval(a)

    def _translate_data(self, d): #pylint:disable=no-self-use
        """
        Checks whether this data can be supported by FastMemory."
        """
        return d

    def _translate_size(self, s): #pylint:disable=no-self-use
        """
        Checks whether this size can be supported by FastMemory."
        """
        if isinstance(s, claripy.ast.Base) and not s.singlevalued:
            raise SimFastMemoryError("size not supported")
        if s is None:
            return s
        return self.state.solver.eval(s)

    def _translate_cond(self, c): #pylint:disable=no-self-use
        """
        Checks whether this condition can be supported by FastMemory."
        """
        if isinstance(c, claripy.ast.Base) and not c.singlevalued:
            raise SimFastMemoryError("size not supported")
        if c is None:
            return True
        else:
            return self.state.solver.eval_upto(c, 1)[0]

    def _resolve_access(self, addr, size):
        """
        Resolves a memory access of a certain size. Returns a sequence of the bases, offsets, and sizes of the accesses required
        to fulfil this.
        """

        # if we fit in one word
        first_offset = addr % self.width
        first_base = addr - first_offset
        if first_offset + size <= self.width:
            return [ (first_base, first_offset, size) ]

        last_size = (addr + size) % self.width
        last_base = addr + size - last_size

        accesses = [ ]
        accesses.append((first_base, first_offset, self.width - first_offset))
        accesses.extend((a, 0, self.width) for a in range(first_base+self.width, last_base, self.width))
        if last_size != 0:
            accesses.append((last_base, 0, last_size))

        return accesses

    def _single_load(self, addr, offset, size, inspect=True, events=True):
        """
        Performs a single load.
        """
        try:
            d = self._contents[addr]
        except KeyError:
            d = self._handle_uninitialized_read(addr, inspect=inspect, events=events)
            self._contents[addr] = d

        if offset == 0 and size == self.width:
            return d
        else:
            return d.get_bytes(offset, size)

    def _single_store(self, addr, offset, size, data):
        """
        Performs a single store.
        """

        if offset == 0 and size == self.width:
            self._contents[addr] = data
        elif offset == 0:
            cur = self._single_load(addr, size, self.width - size)
            self._contents[addr] = data.concat(cur)
        elif offset + size == self.width:
            cur = self._single_load(addr, 0, offset)
            self._contents[addr] = cur.concat(data)
        else:
            cur = self._single_load(addr, 0, self.width)
            start = cur.get_bytes(0, offset)
            end = cur.get_bytes(offset+size, self.width-offset-size)
            self._contents[addr] = start.concat(data, end)

    def _store(self, req):
        data = self._translate_data(req.data) if self._translate_cond(req.condition) else self._translate_data(req.fallback)
        if data is None:
            l.debug("Received false condition. Returning.")
            req.completed = False
            req.actual_addresses = [ req.addr ]
            return None
        if req.endness == "Iend_LE" or (req.endness is None and self.endness == "Iend_LE"):
            data = data.reversed
        addr = self._translate_addr(req.addr)
        size = self._translate_addr(req.size) if req.size is not None else data.length//self.state.arch.byte_width

        #
        # simplify
        #

        if (self.category == 'mem' and options.SIMPLIFY_MEMORY_WRITES in self.state.options) or \
           (self.category == 'reg' and options.SIMPLIFY_REGISTER_WRITES in self.state.options):
            data = self.state.solver.simplify(data)

        accesses = self._resolve_access(addr, size)
        if len(accesses) == 1:
            # simple case
            a,o,s = accesses[0]
            self._single_store(a, o, s, data)
        else:
            cur_offset = 0
            for a,o,s in accesses:
                portion = data.get_bytes(cur_offset, s)
                cur_offset += s
                self._single_store(a, o, s, portion)

        # fill out the request
        req.completed = True
        req.actual_addresses = [ req.addr ]
        req.stored_values = [ data ]
        return req

    def _load(self, addr, size, condition=None, fallback=None,
            inspect=True, events=True, ret_on_segv=False):
        if not self._translate_cond(condition):
            l.debug("Received false condition. Returning fallback.")
            return fallback
        addr = self._translate_addr(addr)
        size = self._translate_addr(size)

        accesses = self._resolve_access(addr, size)
        if len(accesses) == 1:
            a,o,s = accesses[0]
            return [addr], self._single_load(a, o, s, inspect=inspect, events=events), []
        else:
            return [addr], claripy.Concat(*[self._single_load(a, o, s) for a,o,s in accesses]), []

    def _find(self, addr, what, max_search=None, max_symbolic_bytes=None, default=None, step=1, chunk_size=None): # pylint: disable=unused-argument
        raise SimFastMemoryError("find unsupported")

    def _copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None): # pylint: disable=unused-argument
        raise SimFastMemoryError("copy unsupported")

    @SimMemory.memo
    def copy(self, memo): # pylint: disable=unused-argument
        return SimFastMemory(
            endness=self.endness,
            contents=dict(self._contents),
            width=self.width,
            uninitialized_read_handler=self._uninitialized_read_handler,
            memory_id=self.id
        )

    def changed_bytes(self, other):
        """
        Gets the set of changed bytes between self and other.
        """

        changes = set()

        l.warning("FastMemory.changed_bytes(): This implementation is very slow and only for debug purposes.")
        for addr,v in self._contents.items():
            for i in range(self.width):
                other_byte = other.load(addr+i, 1)
                our_byte = v.get_byte(i)
                if other_byte is our_byte:
                    changes.add(addr+i)

        return changes

from angr.sim_state import SimState
SimState.register_default('fast_memory', SimFastMemory)

from .. import sim_options as options
