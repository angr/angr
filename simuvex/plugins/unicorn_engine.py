import os
import sys
import ctypes
import logging
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

    def __init__(self, uc=None, syscall_hooks=None, cache_key=None, runs_since_unicorn=0, runs_since_symbolic_data=0, register_check_count=0):
        SimStatePlugin.__init__(self)

        self.uc = None
        self._syscall_pc = None
        self.jumpkind = 'Ijk_Boring'
        self.error = None
        self.errno = 0

        self.last_miss = 0 if uc is None else uc.last_miss
        self._runs_since_unicorn = runs_since_unicorn
        self._register_check_count = register_check_count
        self._runs_since_symbolic_data = runs_since_symbolic_data
        self.cache_key = hash(self) if cache_key is None else cache_key

        self._dirty = {}
        self.steps = 0
        self._mapped = 0

        # following variables are used in python level hook
        # we cannot see native hooks from python
        self._syscall_hook = None
        self._mem_unmapped_hook = None
        self.syscall_hooks = { } if syscall_hooks is None else syscall_hooks

        # native state in libsimunicorn
        self._uc_state = None
        self._uc_const = None
        self._uc_prefix = None
        self._uc_regs = None
        self.stop_reason = None

    @staticmethod
    def load_arch(arch):
        if str(arch) not in Unicorn.UC_CONFIG:
            if arch.qemu_name == 'x86_64':
                uc_args = (unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
                uc_const = unicorn.x86_const
                uc_prefix = 'UC_X86_'
            elif arch.qemu_name == 'i386':
                uc_args = (unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
                uc_const = unicorn.x86_const
                uc_prefix = 'UC_X86_'
            elif arch.qemu_name == 'mips':
                uc_args = (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS32 | unicorn.UC_MODE_BIG_ENDIAN)
                uc_const = unicorn.mips_const
                uc_prefix = 'UC_MIPS_'
            else:
                # TODO add more arch
                raise NotImplementedError('unsupported arch %r', arch)

            uc_regs = {}
            # map register names to unicorn const
            for r in arch.register_names.itervalues():
                reg_name = uc_prefix + 'REG_' + r.upper()
                if hasattr(uc_const, reg_name):
                    uc_regs[r] = getattr(uc_const, reg_name)

            Unicorn.UC_CONFIG[str(arch)] = (uc_const, uc_prefix, uc_regs, uc_args)

        return Unicorn.UC_CONFIG[str(arch)]

    def _setup_unicorn(self, arch):
        self._uc_const, self._uc_prefix, self._uc_regs, uc_args = self.load_arch(arch)
        self.uc = unicorn.Uc(*uc_args)

    def set_stops(self, stop_points):
        _UC_NATIVE.set_stops(self._uc_state,
            ctypes.c_uint64(len(stop_points)),
            (ctypes.c_uint64 * len(stop_points))(*map(ctypes.c_uint64, stop_points))
        )

    def hook(self):
        l.debug('adding native hooks')
        _UC_NATIVE.hook(self._uc_state) # prefer to use native hooks

        # some hooks are generic hooks, only hook them once
        if self._mem_unmapped_hook is None:
            self._mem_unmapped_hook = self.uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, self._hook_mem_unmapped, None, 1, 0)

        if self._syscall_hook is None:
            arch = self.state.arch.qemu_name
            if arch == 'x86_64':
                self._syscall_hook = self.uc.hook_add(unicorn.UC_HOOK_INTR, self._hook_intr_x86, None, 1, 0)
                self.uc.hook_add(unicorn.UC_HOOK_INSN, self._hook_syscall_x86_64, None,
                        self._uc_const.UC_X86_INS_SYSCALL)
            elif arch == 'i386':
                self._syscall_hook = self.uc.hook_add(unicorn.UC_HOOK_INTR, self._hook_intr_x86, None, 1, 0)
            elif arch == 'mips':
                self._syscall_hook = self.uc.hook_add(unicorn.UC_HOOK_INTR, self._hook_intr_mips, None, 1, 0)
            else:
                raise SimUnicornUnsupport

    def _unhook(self, hook_name):
        h = getattr(self, hook_name)
        if h is not None:
            self.uc.hook_del(h)
            setattr(self, hook_name, None)

    def unhook(self):
        _UC_NATIVE.unhook(self._uc_state)

    def _hook_intr_mips(self, uc, intno, user_data):
        if intno == 17: # EXCP_SYSCALL
            sysno = self.uc.reg_read(self._uc_regs['v0'])
            pc = self.uc.reg_read(self._uc_regs['pc'])
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
        sysno = self.uc.reg_read(self._uc_regs['rax'])
        pc = self.uc.reg_read(self._uc_regs['rip'])
        l.debug('hit sys_%d at %#x', sysno, pc)
        self._syscall_pc = pc + 2 # skip syscall instruction
        self._handle_syscall(uc, user_data)

    def _hook_syscall_i386(self, uc, user_data):
        sysno = self.uc.reg_read(self._uc_regs['eax'])
        pc = self.uc.reg_read(self._uc_regs['eip'])
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

        if start == 0:
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
            self.uc.mem_map(start, length, unicorn.UC_PROT_ALL)
        else:
            # map all pages read-only
            l.info('mmap [%#x, %#x] r-x', start, start + length - 1)
            self.uc.mem_map(start, length,
                            unicorn.UC_PROT_EXEC | unicorn.UC_PROT_READ)

        self._mapped += 1

        self.uc.mem_write(start, str(data))

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
        self._setup_unicorn(self.state.arch)
        # tricky: using unicorn handle form unicorn.Uc object
        self._uc_state = _UC_NATIVE.alloc(self.uc._uch, self.cache_key)

    def start(self, step=1):
        self.set_regs()
        addr = self.state.se.any_int(self.state.ip)

        self.jumpkind = 'Ijk_Boring'

        l.debug('emu_start at %#x (%d steps)', addr, step)
        self._runs_since_unicorn = 0
        self.errno = _UC_NATIVE.start(self._uc_state, addr, step)

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

        addr = self.state.se.any_int(self.state.ip)
        l.debug('finished emulation at %#x after %d steps', addr, self.steps)

        self.stop_reason = _UC_NATIVE.stop_reason(self._uc_state)
        # STOP.STOP_SYSCALL/STOP_EXECNONE/STOP_ZEROPAGE is already handled

    def destroy(self):
        l.debug('deallocting native state %r', self._uc_state)
        _UC_NATIVE.dealloc(self._uc_state)
        self.uc = None
        self._uc_state = None

    def set_regs(self):
        ''' setting unicorn registers '''
        for r, c in self._uc_regs.iteritems():
            if r in ('cs', 'ds', 'es', 'fs', 'gs', 'ss'):
                continue        # :/
            v = getattr(self.state.regs, r)
            if not v.symbolic:
                # l.debug('setting $%s = %#x', r, self.state.se.any_int(v))
                self.uc.reg_write(c, self.state.se.any_int(v))
            else:
                raise SimValueError('setting a symbolic register')

        if self.state.arch.qemu_name == 'x86_64':
            # segment registers like %fs, %gs might be tricky in unicorn
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
            register_check_count=self._register_check_count + 1,
            runs_since_unicorn=self._runs_since_unicorn + 1,
            runs_since_symbolic_data=self._runs_since_symbolic_data + 1
        )
        return u

    def _check_registers(self):
        ''' check if this state might be used in unicorn (has no concrete register)'''
        _, _, uc_regs, _ = Unicorn.load_arch(self.state.arch)

        for r in uc_regs.iterkeys():
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
        if not self._check_registers():
            l.debug("failed register check")
            #self._register_check_count = 0
            return False

        if self._register_check_count < 40:
            #l.debug("not enough passed register checks")
            return False

        if self._runs_since_symbolic_data < 40:
            #l.debug("not enough runs since symbolic data")
            return False

        if self._runs_since_unicorn < 20:
            #l.debug("not enough runs since last unicorn")
            return False

        return True

from ..vex import ccall
SimStatePlugin.register_default('unicorn', Unicorn)
