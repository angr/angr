import logging
import claripy
import struct

l = logging.getLogger(name=__name__)

def _mem_write_cb(s): s.symbolizer._mem_write_callback()
def _mem_read_cb(s): s.symbolizer._mem_read_callback()
def _reg_write_cb(s): s.symbolizer._reg_write_callback()
def _reg_read_cb(s): s.symbolizer._reg_read_callback()
def _page_map_cb(s): s.symbolizer._page_map_callback()

from .plugin import SimStatePlugin
class SimSymbolizer(SimStatePlugin): #pylint:disable=abstract-method
    def __init__(self):
        SimStatePlugin.__init__(self)

        self._symbolize_all = False
        self.symbolization_target_pages = set()
        self.ignore_target_pages = set()
        self.symbolized_count = 0

        self._LE_FMT = None
        self._BE_FMT = None

    def _page_map_callback(self):
        if self._symbolize_all:
            self.symbolization_target_pages.add(self.state.inspect.mapped_address//0x1000)

    def _mem_write_callback(self):
        if not isinstance(self.state.inspect.mem_write_expr, int) and self.state.inspect.mem_write_expr.symbolic:
            return
        if not isinstance(self.state.inspect.mem_write_length, int) and self.state.inspect.mem_write_length.symbolic:
            return

        #length = self.state.solver.eval_one(self.state.inspect.mem_write_length)
        #if length != self.state.arch.bytes:
        #   return

        write_expr = self.state.inspect.mem_write_expr
        byte_expr = self.state.solver.eval_one(self.state.inspect.mem_write_expr, cast_to=bytes).rjust(write_expr.length//8)
        replacement_expr = self._resymbolize_data(byte_expr)
        if replacement_expr is not None:
            assert replacement_expr.length == write_expr.length
            self.state.inspect.mem_write_expr = replacement_expr

    def _reg_write_callback(self):
        if not isinstance(self.state.inspect.reg_write_expr, int) and self.state.inspect.reg_write_expr.symbolic:
            return
        if not isinstance(self.state.inspect.reg_write_length, int) and self.state.inspect.reg_write_length.symbolic:
            return
        if self.state.inspect.reg_write_offset == self.state.arch.ip_offset:
            return

        length = self.state.solver.eval_one(self.state.inspect.reg_write_length)
        if length != self.state.arch.bytes:
            return

        expr = self.state.solver.eval_one(self.state.inspect.reg_write_expr)
        if self._should_symbolize(expr):
            self.state.inspect.reg_write_expr = self._preconstrain('symbolic_ptr_reg', expr)

    def init_state(self):
        super().init_state()
        self._LE_FMT = self.state.arch.struct_fmt(endness='Iend_LE')
        self._BE_FMT = self.state.arch.struct_fmt(endness='Iend_BE')

        # ignore CLE pages
        for i in range(0, self.state.project.loader.kernel_object.map_size, 0x1000):
            self.ignore_target_pages.add((self.state.project.loader.kernel_object.mapped_base+i)//0x1000)
        for i in range(0, self.state.project.loader.extern_object.map_size, 0x1000):
            self.ignore_target_pages.add((self.state.project.loader.extern_object.mapped_base+i)//0x1000)

        self.state.inspect.make_breakpoint('memory_page_map', when=self.state.inspect.BP_BEFORE, action=_page_map_cb)
        self.state.inspect.make_breakpoint('mem_write', when=self.state.inspect.BP_BEFORE, action=_mem_write_cb)
        #self.state.inspect.make_breakpoint('mem_read', when=self.state.inspect.BP_BEFORE, action=_mem_read_cb)
        #self.state.inspect.make_breakpoint('reg_write', when=self.state.inspect.BP_BEFORE, action=_reg_write_cb)
        #self.state.inspect.make_breakpoint('reg_read', when=self.state.inspect.BP_BEFORE, action=_reg_read_cb)

    def set_symbolization_for_all_pages(self):
        self._symbolize_all = True
        self.symbolization_target_pages.update(set(self.state.memory.mem._pages.keys()))
        # handle bigger pages
        for pg in self.state.memory.mem._pages.values():
            if pg._page_size != 0x1000:
                self.symbolization_target_pages.update(pg._page_size + i for i in range(0, pg._page_size, 0x1000))

    def set_symbolized_target_range(self, base, length):
        base_page = base // 0x1000
        pages = (length + base % 0x1000 + 0x999) // 0x1000
        assert pages > 0
        self.symbolization_target_pages.update(range(base_page, base_page+pages))

    def set_symbolized_target(self, base):
        return self.set_symbolized_target_range(base, 1)

    def _preconstrain(self, name, value):
        symbol = claripy.BVS(name, self.state.arch.bits)
        self.state.solver.add(symbol == claripy.BVV(value, self.state.arch.bits))
        self.symbolized_count += 1
        return symbol

    def _should_symbolize(self, addr):
        return addr//0x1000 in self.symbolization_target_pages and not addr//0x1000 in self.ignore_target_pages

    def _resymbolize_data(self, data, prefix=b"", base=0, skip=()):
        replacement_parts = [ prefix ]

        replaced = False
        for offset in range(0, len(data), self.state.arch.bytes):
            if base + offset in skip:
                continue

            word = data[offset:offset+self.state.arch.bytes]
            if len(word) < self.state.arch.bytes:
                replacement_parts.append(claripy.BVV(word))
                break

            ptr_be = struct.unpack(self._BE_FMT, word)[0]
            if ptr_be == 0: # common case
                replacement_parts.append(claripy.BVV(0, self.state.arch.bits))
                continue
            ptr_le = struct.unpack(self._LE_FMT, word)[0]

            ptr_mapped = ptr_be if self._should_symbolize(ptr_be) else ptr_le if self._should_symbolize(ptr_le) else None
            ptr_endness = 'Iend_BE' if ptr_be is ptr_mapped else 'Iend_LE'
            if ptr_mapped:
                replaced = True
                symbol = self._preconstrain('symbolic_pointer', ptr_mapped)
                l.debug("Replacing %#x (at %#x, endness %s) with %s!", ptr_mapped, base+offset, ptr_endness, symbol)
                if ptr_endness == 'Iend_LE':
                    symbol = symbol.reversed
                replacement_parts.append(symbol)
            else:
                replacement_parts.append(claripy.BVV(word))

        if replaced:
            return claripy.Concat(*replacement_parts)
        else:
            return None

    def _resymbolize_region(self, storage, addr, length):
        assert type(addr) is int
        assert type(length) is int

        self.state.scratch.push_priv(True)
        memory_objects = storage.mem.load_objects(addr, length)
        self.state.scratch.pop_priv()

        for _,mo in memory_objects:
            if not mo.is_bytes and mo.object.symbolic:
                l.debug("Skipping symbolic memory object %s.", mo)
                continue

            aligned_base = mo.base - mo.base % (-self.state.arch.bytes)
            remaining_len = mo.last_addr + 1 - aligned_base
            if remaining_len < self.state.arch.bytes:
                continue

            data = mo.bytes_at(aligned_base, remaining_len, allow_concrete=True)
            if not mo.is_bytes:
                data = self.state.solver.eval_one(data, cast_to=bytes)
            #assert self.state.solver.eval_one(storage.load(aligned_base, remaining_len, endness='Iend_BE'), cast_to=bytes).rjust(self.state.arch.bytes) == data

            replacement_content = self._resymbolize_data(
                data,
                base=aligned_base,
                prefix=mo.bytes_at(mo.base, mo.length - remaining_len) if aligned_base != mo.base else b"",
                skip=() if storage is self.state.memory else (self.state.arch.ip_offset)
            )
            if replacement_content is not None:
                storage.mem.replace_memory_object(mo, replacement_content)

    def resymbolize(self):
        #for i, p_id in enumerate(self.state.registers.mem._pages):
        #   if i % 100 == 0:
        #       l.debug("%s/%s register pages symbolized", i, len(self.state.registers.mem._pages))
        #   addr_start = self.state.registers.mem._page_addr(p_id)
        #   length = self.state.registers.mem._page_size
        #   self._resymbolize_region(self.state.registers, addr_start, length)
        #self._resymbolize_region(self.state.registers, self.state.arch.sp_offset, 8)

        for i, p_id in enumerate(self.state.memory.mem._pages):
            if i % 100 == 0:
                l.debug("%s/%s memory pages symbolized", i, len(self.state.memory.mem._pages))
            addr_start = self.state.memory.mem._page_addr(p_id)
            length = self.state.memory.mem._page_size
            self._resymbolize_region(self.state.memory, addr_start, length)

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        sc = SimSymbolizer()
        sc._symbolize_all = self._symbolize_all
        sc.symbolization_target_pages = set(self.symbolization_target_pages)
        sc.ignore_target_pages = set(self.ignore_target_pages)
        sc.symbolized_count = self.symbolized_count
        sc._LE_FMT = self._LE_FMT
        sc._BE_FMT = self._BE_FMT
        return sc

from angr.sim_state import SimState
SimState.register_default('symbolizer', SimSymbolizer)
