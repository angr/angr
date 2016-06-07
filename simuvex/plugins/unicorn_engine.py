import os
import sys
import ctypes
import logging
import threading
import itertools
l = logging.getLogger('simuvex.plugins.unicorn')

try:
    import unicorn
except ImportError:
    l.warning("Unicorn is not installed. Support disabled.")

from .plugin import SimStatePlugin
from ..s_errors import SimValueError, SimUnicornUnsupport

class MEM_PATCH(ctypes.Structure): # mem_update_t
    pass

MEM_PATCH._fields_ = [
        ('address', ctypes.c_uint64),
        ('length', ctypes.c_uint64),
        ('next', ctypes.POINTER(MEM_PATCH))
    ]

class STOP(object): # stop_t
    STOP_NORMAL     = 0
    STOP_SYMBOLIC   = 1
    STOP_ERROR      = 2
    STOP_SYSCALL    = 3
    STOP_EXECNONE   = 4
    STOP_ZEROPAGE   = 5
    STOP_NOSTART    = 6

#
# Because Unicorn leaks like crazy, we use one Uc object per thread...
#

_unicounter = itertools.count()

class Uniwrapper(unicorn.Uc):
    def __init__(self, arch):
        self.arch = arch
        self.wrapped_mapped = set()
        self.wrapped_hooks = set()
        self.id = None
        unicorn.Uc.__init__(self, arch.uc_arch, arch.uc_mode)

    def hook_add(self, htype, callback, user_data=None, begin=1, end=0, arg1=0):
        h = unicorn.Uc.hook_add(self, htype, callback, user_data=user_data, begin=begin, end=end, arg1=arg1)
        l.debug("Hook: %s,%s -> %s", htype, callback.__name__, h)
        self.wrapped_hooks.add(h)
        return h

    def hook_del(self, h):
        l.debug("Clearing hook %s", h)
        h = unicorn.Uc.hook_del(self, h)
        self.wrapped_hooks.discard(h)
        return h

    def mem_map(self, addr, size, perms=7):
        l.debug("Mapping %d bytes at %#x", size, addr)
        m = unicorn.Uc.mem_map(self, addr, size, perms=perms)
        self.wrapped_mapped.add((addr, size))
        return m

    def mem_unmap(self, addr, size):
        l.debug("Unmapping %d bytes at %#x", size, addr)
        m = unicorn.Uc.mem_unmap(self, addr, size)
        self.wrapped_mapped.discard((addr, size))
        return m

    def mem_reset(self):
        l.debug("Resetting memory.")
        for addr,size in self.wrapped_mapped:
            l.debug("Unmapping %d bytes at %#x", size, addr)
            unicorn.Uc.mem_unmap(self, addr, size)
        self.wrapped_mapped.clear()

    def hook_reset(self):
        l.debug("Resetting hooks.")
        for h in self.wrapped_hooks:
            l.debug("Clearing hook %s", h)
            unicorn.Uc.hook_del(self, h)
        self.wrapped_hooks.clear()

    def reset(self):
        self.mem_reset()
        #self.hook_reset()
        l.debug("Reset complete.")

_unicorn_tls = threading.local()
_unicorn_tls.uc = None

def _load_native():
    if sys.platform == 'darwin':
        libfile = 'sim_unicorn.dylib'
    else:
        libfile = 'sim_unicorn.so'
    _simuvex_paths = [ os.path.join(os.path.dirname(__file__), '..', '..', 'simuvex_c', libfile), os.path.join(sys.prefix, 'lib', libfile) ]
    try:
        h = None

        for f in _simuvex_paths:
            l.debug('checking %r', f)
            if os.path.exists(f):
                h = ctypes.CDLL(f)
                break

        if h is None:
            l.warning('failed loading sim_unicorn, unicorn support disabled')
            raise ImportError("Could not find sim_unicorn shared object.")

        uc_err = ctypes.c_int
        state_t = ctypes.c_void_p
        stop_t = ctypes.c_int
        uc_engine_t = ctypes.c_void_p

        def _setup_prototype(handle, func, restype, *argtypes):
            getattr(handle, func).restype = restype
            getattr(handle, func).argtypes = argtypes

        _setup_prototype(h, 'alloc', state_t, uc_engine_t, ctypes.c_uint64)
        _setup_prototype(h, 'dealloc', None, state_t)
        _setup_prototype(h, 'hook', None, state_t)
        _setup_prototype(h, 'unhook', None, state_t)
        _setup_prototype(h, 'start', uc_err, state_t, ctypes.c_uint64, ctypes.c_uint64)
        _setup_prototype(h, 'stop', None, state_t, stop_t)
        _setup_prototype(h, 'sync', ctypes.POINTER(MEM_PATCH), state_t)
        _setup_prototype(h, 'bbl_addrs', ctypes.POINTER(ctypes.c_uint64), state_t)
        _setup_prototype(h, 'bbl_addr_count', ctypes.c_uint64, state_t)
        _setup_prototype(h, 'destroy', None, ctypes.POINTER(MEM_PATCH))
        _setup_prototype(h, 'step', ctypes.c_uint64, state_t)
        _setup_prototype(h, 'stop_reason', stop_t, state_t)
        _setup_prototype(h, 'activate', None, state_t, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p)
        _setup_prototype(h, 'set_stops', None, state_t, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64))
        _setup_prototype(h, 'logSetLogLevel', None, ctypes.c_uint64)
        _setup_prototype(h, 'cache_page', ctypes.c_bool, state_t, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p)

        l.info('native plugin is enabled')

        return h
    except (OSError, AttributeError):
        l.warning('failed loading "%s", unicorn support disabled', libfile)
        e_type, value, traceback = sys.exc_info()
        raise ImportError, ("Unable to import native SimUnicorn support.", e_type, value), traceback

try:
    _UC_NATIVE = _load_native()
    _UC_NATIVE.logSetLogLevel(2)
except ImportError:
    _UC_NATIVE = None


class Unicorn(SimStatePlugin):
    '''
    setup the unicorn engine for a state
    '''

    UC_CONFIG = {} # config cache for each arch

    def __init__(self, syscall_hooks=None, cache_key=None, runs_since_unicorn=0, runs_since_symbolic_data=0, register_check_count=0, unicount=None, cooldown_symbolic_registers=40, cooldown_symbolic_memory=40, cooldown_nonunicorn_blocks=20, max_steps=1000000):
        """
        Initializes the Unicorn plugin for SimuVEX. This plugin handles communication with
        UnicornEngine.
        """

        SimStatePlugin.__init__(self)

        self._syscall_pc = None
        self.jumpkind = 'Ijk_Boring'
        self.error = None
        self.errno = 0

        self.last_miss = 0
        self.cache_key = hash(self) if cache_key is None else cache_key

        # cooldowns to avoid thrashing in and out of unicorn
        self._current_nonunicorn_blocks = runs_since_unicorn
        self._current_symbolic_registers = register_check_count
        self._current_symbolic_memory = runs_since_symbolic_data
        self.cooldown_symbolic_registers = cooldown_symbolic_registers
        self.cooldown_symbolic_memory = cooldown_symbolic_memory
        self.cooldown_nonunicorn_blocks = cooldown_nonunicorn_blocks

        # the default step limit
        self.max_steps = max_steps

        self._dirty = {}
        self.steps = 0
        self._mapped = 0

        # following variables are used in python level hook
        # we cannot see native hooks from python
        self.syscall_hooks = { } if syscall_hooks is None else syscall_hooks

        # native state in libsimunicorn
        self._uc_state = None
        self._uc_const = None
        self._uc_prefix = None
        self._uc_regs = None
        self.stop_reason = None

        # this is the counter for the unicorn count
        self._unicount = next(_unicounter) if unicount is None else unicount

    @property
    def uc(self):
        new_id = next(_unicounter)

        if _unicorn_tls.uc is None or _unicorn_tls.uc.arch != self.state.arch:
            l.debug("Creating unicorn state!")
            _unicorn_tls.uc = Uniwrapper(self.state.arch)
        elif _unicorn_tls.uc.id != self._unicount:
            l.debug("Resetting unicorn state!")
            _unicorn_tls.uc.reset()
        else:
            #l.debug("Reusing unicorn state!")
            pass

        _unicorn_tls.uc.id = new_id
        self._unicount = new_id
        return _unicorn_tls.uc

    def _setup_unicorn(self):
        if self.state.arch.uc_mode is None:
            raise SimUnicornUnsupport("unsupported architecture %r" % self.state.arch)

        self._uc_regs = self.state.arch.uc_regs
        self._uc_prefix = self.state.arch.uc_prefix
        self._uc_const = self.state.arch.uc_const

    def set_stops(self, stop_points):
        _UC_NATIVE.set_stops(self._uc_state,
            ctypes.c_uint64(len(stop_points)),
            (ctypes.c_uint64 * len(stop_points))(*map(ctypes.c_uint64, stop_points))
        )

    def hook(self):
        l.debug('adding native hooks')
        _UC_NATIVE.hook(self._uc_state) # prefer to use native hooks

        self.uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, self._hook_mem_unmapped, None, 1, 0)

        arch = self.state.arch.qemu_name
        if arch == 'x86_64':
            self.uc.hook_add(unicorn.UC_HOOK_INTR, self._hook_intr_x86, None, 1, 0)
            self.uc.hook_add(unicorn.UC_HOOK_INSN, self._hook_syscall_x86_64, None, self._uc_const.UC_X86_INS_SYSCALL)
        elif arch == 'i386':
            self.uc.hook_add(unicorn.UC_HOOK_INTR, self._hook_intr_x86, None, 1, 0)
        elif arch == 'mips':
            self.uc.hook_add(unicorn.UC_HOOK_INTR, self._hook_intr_mips, None, 1, 0)
        else:
            raise SimUnicornUnsupport

    def _hook_intr_mips(self, uc, intno, user_data):
        if intno == 17: # EXCP_SYSCALL
            sysno = uc.reg_read(self._uc_regs['v0'])
            pc = uc.reg_read(self._uc_regs['pc'])
            l.debug('hit sys_%d at %#x', sysno, pc)
            self._syscall_pc = pc + 4
            self._handle_syscall(uc, user_data)
        else:
            l.warning('unhandled interrupt %d', intno)

    def _hook_intr_x86(self, uc, intno, user_data):
        if intno == 0x80:
            if self.state.arch.bits == 32:
                self._hook_syscall_i386(uc, user_data)
            else:
                self._hook_syscall_x86_64(uc, user_data)
        else:
            l.warning('unhandled interrupt %d', intno)

    def _hook_syscall_x86_64(self, uc, user_data):
        sysno = uc.reg_read(self._uc_regs['rax'])
        pc = uc.reg_read(self._uc_regs['rip'])
        l.debug('hit sys_%d at %#x', sysno, pc)
        self._syscall_pc = pc + 2 # skip syscall instruction
        self._handle_syscall(uc, user_data)

    def _hook_syscall_i386(self, uc, user_data):
        sysno = uc.reg_read(self._uc_regs['eax'])
        pc = uc.reg_read(self._uc_regs['eip'])
        l.debug('hit sys_%d at %#x', sysno, pc)
        self._syscall_pc = pc + 2
        if not self._quick_syscall(sysno):
            self._handle_syscall(uc, user_data)

    def _quick_syscall(self, sysno):
        if sysno in self.syscall_hooks:
            self.syscall_hooks[sysno](self.state)
            return True
        else:
            return False

    def _handle_syscall(self, uc, user_data): #pylint:disable=unused-argument
        # unicorn does not support syscall, we should giveup emulation
        # and send back to SimProcedure. (ignore is always False)
        l.info('stop emulation')
        self.jumpkind = 'Ijk_Sys_syscall'
        _UC_NATIVE.stop(self._uc_state, STOP.STOP_SYSCALL)

    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data): #pylint:disable=unused-argument
        ''' load memory from current state'''

        # FIXME check angr hooks at `address`

        start = address & (0xffffffffffffff000)
        length = ((address + size + 0xfff) & (0xffffffffffffff000)) - start

        if start == 0 or ((start + length) & ((1 << self.state.arch.bits) - 1)) == 0:
            # sometimes it happens because of %fs is not correctly set
            self.error = 'accessing zero page [%#x, %#x] (%#x)' % (address, address + size - 1, access)
            l.warning(self.error)

            # tell uc_state to rollback
            _UC_NATIVE.stop(self._uc_state, STOP.STOP_ZEROPAGE)
            return False

        the_bytes, _ = self.state.memory.mem.load_bytes(start, length)

        if access == unicorn.UC_MEM_FETCH_UNMAPPED and len(the_bytes) == 0:
            # we can not initalize an empty page then execute on it
            self.error = 'fetching empty page [%#x, %#x]' % (address, address + size - 1)
            l.warning(self.error)
            _UC_NATIVE.stop(self._uc_state, STOP.STOP_EXECNONE)
            return False

        data = bytearray(length)

        partial_symbolic = False

        offsets = sorted(the_bytes.keys())
        offsets.append(length)

        for i in xrange(len(offsets)-1):
            pos = offsets[i]
            chunk = the_bytes[pos]
            size = min((chunk.base + len(chunk) / 8) - (start + pos), offsets[i + 1] - pos)
            d = chunk.bytes_at(start + pos, size)
            # if not self.state.se.unique(d):
            if d.symbolic:
                l.debug('loading symbolic memory [%#x, %#x]', start + pos, start + pos + size - 1)

                if not partial_symbolic:
                    taint = ctypes.create_string_buffer(length)
                    partial_symbolic = True

                ctypes.memset(ctypes.byref(taint, pos), 0x2, size) # mark them as TAINT_SYMBOLIC
                s = '\x00' * (len(d)/8)
            else:
                s = self.state.se.any_str(d)
            data[pos:pos + size] = s

        if access == unicorn.UC_MEM_FETCH_UNMAPPED:
            l.debug('caching executable pages')
            return _UC_NATIVE.cache_page(self._uc_state, start, length, str(data))

        if access == unicorn.UC_MEM_WRITE_UNMAPPED:
            l.info('mmap [%#x, %#x] rwx', start, start + length - 1)
            uc.mem_map(start, length, unicorn.UC_PROT_ALL)
        else:
            # map all pages read-only
            l.info('mmap [%#x, %#x] r-x', start, start + length - 1)
            uc.mem_map(start, length,
                            unicorn.UC_PROT_EXEC | unicorn.UC_PROT_READ)

        self._mapped += 1

        uc.mem_write(start, str(data))

        l.info('mmap: activate new page [%#x, %#x]', start, start + length - 1)
        if partial_symbolic:
            # we have initalized tainted bits for this case
            _UC_NATIVE.activate(self._uc_state, start, length, taint)
        elif access == unicorn.UC_MEM_WRITE_UNMAPPED:
            # we didn't initalize the bitmap for this case, should provide
            # an empty bitmap
            _UC_NATIVE.activate(self._uc_state, start, length, None)

        return True

    def setup(self):
        self._setup_unicorn()
        self.set_regs()
        # tricky: using unicorn handle form unicorn.Uc object
        self._uc_state = _UC_NATIVE.alloc(self.uc._uch, self.cache_key)

    def start(self, step=None):
        addr = self.state.se.any_int(self.state.ip)

        self.jumpkind = 'Ijk_Boring'

        l.debug('emu_start at %#x (%d steps)', addr, self.max_steps if step is None else step)
        self._current_nonunicorn_blocks = 0
        self.errno = _UC_NATIVE.start(self._uc_state, addr, self.max_steps if step is None else step)

    def finish(self):
        self.get_regs()
        head = _UC_NATIVE.sync(self._uc_state)
        p_update = head
        while bool(p_update):
            update = p_update.contents
            l.debug('Got dirty [%#x, %#x]', update.address, update.length - 1)
            self._dirty[update.address] = update.length
            p_update = update.next

        _UC_NATIVE.destroy(head)
        self.steps = _UC_NATIVE.step(self._uc_state)

        self.sync()

        # get the addresses out of the state
        num_bbl_addrs = _UC_NATIVE.bbl_addr_count(self._uc_state)
        bbl_addrs = _UC_NATIVE.bbl_addrs(self._uc_state)
        self.state.scratch.bbl_addr_list = bbl_addrs[:num_bbl_addrs]

        addr = self.state.se.any_int(self.state.ip)
        l.debug('finished emulation at %#x after %d steps', addr, self.steps)

        self.stop_reason = _UC_NATIVE.stop_reason(self._uc_state)
        # STOP.STOP_SYSCALL/STOP_EXECNONE/STOP_ZEROPAGE is already handled

    def destroy(self):
        l.debug("Unhooking.")
        _UC_NATIVE.unhook(self._uc_state)
        self.uc.hook_reset()

        l.debug('deallocting native state %#x', self._uc_state)
        _UC_NATIVE.dealloc(self._uc_state)
        self._uc_state = None

        # there's something we're not properly resetting for syscalls, so
        # we'll clear the state when they happen
        if self.stop_reason == STOP.STOP_SYSCALL:
            _unicorn_tls.uc = None

        l.debug("Resetting the unicorn state.")
        self.uc.reset()

    def set_regs(self):
        ''' setting unicorn registers '''

        if self.state.arch.qemu_name == 'x86_64':
            fs = self.state.se.any_int(self.state.regs.fs)
            gs = self.state.se.any_int(self.state.regs.gs)
            self.write_msr(fs, 0xC0000100)
            self.write_msr(gs, 0xC0000101)
            flags = ccall._get_flags(self.state)[0]
            if flags.symbolic:
                raise SimValueError('symbolic eflags')
            self.uc.reg_write(self._uc_const.UC_X86_REG_EFLAGS, self.state.se.any_int(flags))
        elif self.state.arch.qemu_name == 'i386':
            flags = ccall._get_flags(self.state)[0]
            if flags.symbolic:
                raise SimValueError('symbolic eflags')
            self.uc.reg_write(self._uc_const.UC_X86_REG_EFLAGS, self.state.se.any_int(flags))
            fs = self.state.se.any_int(self.state.regs.fs) << 16
            gs = self.state.se.any_int(self.state.regs.gs) << 16
            self.setup_gdt(fs, gs)

        for r, c in self._uc_regs.iteritems():
            if r in ('cs', 'ds', 'es', 'fs', 'gs', 'ss'):
                continue        # :/
            v = getattr(self.state.regs, r)
            if not v.symbolic:
                # l.debug('setting $%s = %#x', r, self.state.se.any_int(v))
                self.uc.reg_write(c, self.state.se.any_int(v))
            else:
                raise SimValueError('setting a symbolic register')


    # this stuff is 100% copied from the unicorn regression tests
    def setup_gdt(self, fs, gs, fs_size=0xFFFFFFFF, gs_size=0xFFFFFFFF):
        GDT_ADDR = 0x1000
        GDT_LIMIT = 0x1000
        A_PRESENT = 0x80
        A_DATA = 0x10
        A_DATA_WRITABLE = 0x2
        A_PRIV_0 = 0x0
        A_DIR_CON_BIT = 0x4
        F_PROT_32 = 0x4
        S_GDT = 0x0
        S_PRIV_0 = 0x0

        self.uc.mem_map(GDT_ADDR, GDT_LIMIT)
        normal_entry = self.create_gdt_entry(0, 0xFFFFFFFF, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
        stack_entry = self.create_gdt_entry(0, 0xFFFFFFFF, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0, F_PROT_32)
        fs_entry = self.create_gdt_entry(fs, fs_size, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
        gs_entry = self.create_gdt_entry(gs, gs_size, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
        self.uc.mem_write(GDT_ADDR + 8, normal_entry + stack_entry + fs_entry + gs_entry)

        self.uc.reg_write(self._uc_const.UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT, 0x0))

        selector = self.create_selector(1, S_GDT | S_PRIV_0)
        self.uc.reg_write(self._uc_const.UC_X86_REG_CS, selector)
        self.uc.reg_write(self._uc_const.UC_X86_REG_DS, selector)
        self.uc.reg_write(self._uc_const.UC_X86_REG_ES, selector)
        selector = self.create_selector(2, S_GDT | S_PRIV_0)
        self.uc.reg_write(self._uc_const.UC_X86_REG_SS, selector)
        selector = self.create_selector(3, S_GDT | S_PRIV_0)
        self.uc.reg_write(self._uc_const.UC_X86_REG_FS, selector)
        selector = self.create_selector(4, S_GDT | S_PRIV_0)
        self.uc.reg_write(self._uc_const.UC_X86_REG_GS, selector)
        self.uc.mem_unmap(GDT_ADDR, GDT_LIMIT)

    @staticmethod
    def create_selector(idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret

    @staticmethod
    def create_gdt_entry(base, limit, access, flags):
        to_ret = limit & 0xffff
        to_ret |= (base & 0xffffff) << 16
        to_ret |= (access & 0xff) << 40
        to_ret |= ((limit >> 16) & 0xf) << 48
        to_ret |= (flags & 0xff) << 52
        to_ret |= ((base >> 24) & 0xff) << 56
        import struct
        return struct.pack('<Q', to_ret)


    # do NOT call either of these functions in a callback, lmao
    def read_msr(self, msr=0xC0000100):
        setup_code = '\x0f\x32'
        BASE = 0x100B000000
        self.uc.mem_map(BASE, 0x1000)
        self.uc.mem_write(BASE, setup_code)
        self.uc.reg_write(self._uc_const.UC_X86_REG_RCX, msr)
        self.uc.emu_start(BASE, BASE + len(setup_code))
        self.uc.mem_unmap(BASE, 0x1000)

        a = self.uc.reg_read(self._uc_const.UC_X86_REG_RAX)
        d = self.uc.reg_read(self._uc_const.UC_X86_REG_RDX)
        return (d << 32) + a

    def write_msr(self, val, msr=0xC0000100):
        setup_code = '\x0f\x30'
        BASE = 0x100B000000
        self.uc.mem_map(BASE, 0x1000)
        self.uc.mem_write(BASE, setup_code)
        self.uc.reg_write(self._uc_const.UC_X86_REG_RCX, msr)
        self.uc.reg_write(self._uc_const.UC_X86_REG_RAX, val & 0xFFFFFFFF)
        self.uc.reg_write(self._uc_const.UC_X86_REG_RDX, val >> 32)
        self.uc.emu_start(BASE, BASE + len(setup_code))
        self.uc.mem_unmap(BASE, 0x1000)

    def get_regs(self):
        ''' loading registers from unicorn '''
        for r, c in self._uc_regs.iteritems():
            if r in ('cs', 'ds', 'es', 'fs', 'gs', 'ss'):
                continue        # :/
            v = self.uc.reg_read(c)
            # l.debug('getting $%s = %#x', r, v)
            setattr(self.state.regs, r, v)

        # some architecture-specific register fixups
        if self.state.arch.qemu_name == 'i386':
            if self.jumpkind.startswith('Ijk_Sys'):
                # update the guest_AT_SYSCALL register
                self.state.registers.store(340, self.state.regs.eip - 2)

            # update the eflags
            self.state.regs.cc_dep1 = self.state.se.BVV(self.uc.reg_read(self._uc_const.UC_X86_REG_EFLAGS), self.state.arch.bits)
            self.state.regs.cc_op = ccall.data['X86']['OpTypes']['G_CC_OP_COPY']
        if self.state.arch.qemu_name == 'x86_64':
            if self.jumpkind.startswith('Ijk_Sys'):
                # update the guest_AT_SYSCALL register
                self.state.registers.store(912, self.state.regs.eip - 2)

            # update the eflags
            self.state.regs.cc_dep1 = self.state.se.BVV(self.uc.reg_read(self._uc_const.UC_X86_REG_EFLAGS), self.state.arch.bits)
            self.state.regs.cc_op = ccall.data['AMD64']['OpTypes']['G_CC_OP_COPY']

    def sync(self):
        for address, length in self._dirty.iteritems():
            s = self.uc.mem_read(address, length)
            l.debug('syncing [%#x, %#x] = %s', address, address + length, str(s).encode('hex'))
            self.state.memory.store(address, str(s))
        self._dirty.clear()

    def copy(self):
        u = Unicorn(
            syscall_hooks=dict(self.syscall_hooks),
            cache_key=self.cache_key,
            register_check_count=self._current_symbolic_registers + 1,
            runs_since_unicorn=self._current_nonunicorn_blocks + 1,
            runs_since_symbolic_data=self._current_symbolic_memory + 1,
            unicount=self._unicount,
            cooldown_symbolic_registers=self.cooldown_symbolic_registers,
            cooldown_symbolic_memory=self.cooldown_symbolic_memory,
            cooldown_nonunicorn_blocks=self.cooldown_nonunicorn_blocks,
            max_steps=self.max_steps,
        )
        return u

    def _check_registers(self):
        ''' check if this state might be used in unicorn (has no concrete register)'''
        for r in self.state.arch.uc_regs.iterkeys():
            v = getattr(self.state.regs, r)
            if v.symbolic:
                #l.info('detected symbolic register %s', r)
                return False

        flags = ccall._get_flags(self.state)[0]
        if flags is not None and flags.symbolic:
            #l.info("detected symbolic rflags/eflags")
            return False

        #l.debug('passed quick check')
        return True

    def check(self):
        if self._current_symbolic_registers < self.cooldown_symbolic_registers:
            #l.debug("not enough passed register checks")
            return False

        if self._current_symbolic_memory < self.cooldown_symbolic_memory:
            #l.debug("not enough runs since symbolic data")
            return False

        if self._current_nonunicorn_blocks < self.cooldown_nonunicorn_blocks:
            #l.debug("not enough runs since last unicorn")
            return False

        if not self._check_registers():
            l.debug("failed register check")
            #self._current_symbolic_registers = 0
            return False

        return True

from ..vex import ccall
SimStatePlugin.register_default('unicorn', Unicorn)
