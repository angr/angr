import os
import sys
import ctypes
import logging
l = logging.getLogger('simuvex.plugins.unicorn')

from .plugin import SimStatePlugin
from ..s_errors import SimValueError
from .. import s_options as o

class MEM_PATCH(ctypes.Structure): # mem_update_t
    pass

MEM_PATCH._fields_ = [
        ('address', ctypes.c_uint64),
        ('length', ctypes.c_uint64),
        ('next', ctypes.POINTER(MEM_PATCH))
    ]

class STOP(): # stop_t
    STOP_NORMAL     = 0
    STOP_SYMBOLIC   = 1
    STOP_ERROR      = 2
    STOP_SYSCALL    = 3
    STOP_EXECNONE   = 4
    STOP_ZEROPAGE   = 5

class Unicorn(SimStatePlugin):
    '''
    setup the unicorn engine for a state
    '''

    UC_CONFIG = {} # config cache for each arch
    UC_NATIVE = None # native implemenation of hooks

    def __init__(self, arch=None):
        SimStatePlugin.__init__(self)

        self.uc = None
        self.arch = arch
        self.jumpkind = 'Ijk_Boring'
        self.error = None
        if arch is not None:
            self._setup_unicorn(arch)

        self._dirty = {}
        self.cur_steps = 0
        self.max_steps = 0

        # following variables are used in python level hook
        # we cannot see native hooks from python
        self._block_hook = None
        self._syscall_hook = None
        self._mem_prot_hook = None
        self._mem_access_hook = None
        self._mem_write_hook = None
        self._mem_fetch_hook = None
        self._mem_unmapped_hook = None

        # native state in libsimunicorn
        self._uc_state = None

    def set_state(self, state):

        super(Unicorn, self).set_state(state)

        if self.uc is None:
            self._setup_unicorn(state.arch)

            if o.UNICORN_DISABLE_NATIVE in self.state.options:
                self.UC_NATIVE = False

            if self.UC_NATIVE:
                if self._uc_state is not None:
                    l.debug('deallocting native state %r', self._uc_state)
                    self.UC_NATIVE.dealloc(self._uc_state)
                # tricky: using unicorn handle form unicorn.Uc object
                self._uc_state = self.UC_NATIVE.alloc(self.uc._uch)

    @staticmethod
    def load_arch(arch):
        if arch not in Unicorn.UC_CONFIG:
            if arch.qemu_name == 'x86_64':
                uc_args = (unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
                uc_const = unicorn.x86_const
                uc_prefix = 'UC_X86_'
            elif arch.qemu_name == 'i386':
                uc_args = (unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
                uc_const = unicorn.x86_const
                uc_prefix = 'UC_X86_'
            else:
                # TODO add more arch
                raise NotImplementedError('unsupported arch %r', arch)

            uc_regs = {}
            # map register names to unicorn const
            for r in arch.register_names.itervalues():
                reg_name = uc_prefix + 'REG_' + r.upper()
                if hasattr(uc_const, reg_name):
                    uc_regs[r] = getattr(uc_const, reg_name)

            Unicorn.UC_CONFIG[arch] = (uc_const, uc_prefix, uc_regs, uc_args)

            # here is a good place to do initialization, try to load native plugin
            if Unicorn.UC_NATIVE is None:
                Unicorn.UC_NATIVE = Unicorn._load_native()

        return Unicorn.UC_CONFIG[arch]

    @staticmethod
    def _load_native():
        libpath = os.path.join(os.path.dirname(os.path.abspath( __file__ )), '..', '..', 'simuvex_c')
        if sys.platform == 'darwin':
            libfile = os.path.join(libpath, 'sim_unicorn.dylib')
        else:
            libfile = os.path.join(libpath, 'sim_unicorn.so')
        try:
            h = ctypes.CDLL(libfile)

            state_t = ctypes.c_void_p
            uc_engine_t = ctypes.c_void_p

            def _setup_prototype(handle, func, restype, *argtypes):
                getattr(handle, func).restype = restype
                getattr(handle, func).argtypes = argtypes

            _setup_prototype(h, 'alloc', state_t, uc_engine_t)
            _setup_prototype(h, 'dealloc', None, state_t)
            _setup_prototype(h, 'hook', None, state_t)
            _setup_prototype(h, 'unhook', None, state_t)
            _setup_prototype(h, 'start', None, state_t, ctypes.c_uint64, ctypes.c_uint64)
            _setup_prototype(h, 'stop', None, state_t, ctypes.c_uint64)
            _setup_prototype(h, 'sync', ctypes.POINTER(MEM_PATCH), state_t)
            _setup_prototype(h, 'destroy', None, ctypes.POINTER(MEM_PATCH))
            _setup_prototype(h, 'step', ctypes.c_uint64, state_t)
            _setup_prototype(h, 'activate', None, state_t, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p)

            l.info('native plugin is enabled')

            return h
        except (OSError, AttributeError) as e:
            l.warning('failed loading "%s", native plugin is disabled', libfile)
            raise e

            return False

    def _setup_unicorn(self, arch):
        self.arch = arch
        self._uc_const, self._uc_prefix, self._uc_regs, uc_args = self.load_arch(arch)
        self.uc = unicorn.Uc(*uc_args)

    def hook(self):
        # some hooks are generic hooks, only hook them once
        if self._mem_unmapped_hook is None:
            self._mem_unmapped_hook = self.uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, self._hook_mem_unmapped)

        # FIXME x86_64 only
        if self._syscall_hook is not None:
            self._syscall_hook = self.uc.hook_add(unicorn.UC_HOOK_INSN, self._hook_syscall_x86_64, None,
                    self._uc_const.UC_X86_INS_SYSCALL)

        if self.UC_NATIVE is False:
            # do not support native speedup

            if self._mem_prot_hook is None:
                self._mem_prot_hook = self.uc.hook_add(unicorn.UC_HOOK_MEM_PROT, self._hook_mem_prot)

            # hook for mem access *in python* is not used for tainting, since
            # any page mapped as writable is marked as tainted. this hook is
            # just used for debugging.
            if self._mem_access_hook is None and l.level <= logging.DEBUG:
                # this hook is just for debugging
                self._mem_access_hook = self.uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, self._hook_mem_access)

            if self._block_hook is None:
                self._block_hook = self.uc.hook_add(unicorn.UC_HOOK_BLOCK, self._hook_block)
        else:
            self.UC_NATIVE.hook(self._uc_state)

    def _unhook(self, hook_name):
        h = getattr(self, hook_name)
        if h is not None:
            self.uc.hook_del(h)
            setattr(self, hook_name, None)

    def unhook(self, type, value, traceback):
        if  self.UC_NATIVE is False:
            self._unhook('_block_hook')
            self._unhook('_mem_prot_hook')
            self._unhook('_mem_access_hook')
        else:
            self.UC_NATIVE.unhook(self._uc_state)

    def _hook_block(self, uc, address, size, user_data):
        l.info('hit block %#x', address)
        if self.cur_steps >= self.max_steps:
            l.info('stop emulation')
            if self.UC_NATIVE is not False:
                self.UC_NATIVE.stop(self._uc_state, STOP.STOP_NORMAL)
            else:
                self.uc.emu_stop()
        else:
            self.cur_steps += 1

    def _hook_syscall_x86_64(self, uc, user_data):
        rax = self.uc.reg_read(self._uc_regs['rax'])
        rip = self.uc.reg_read(self._uc_regs['rip'])
        l.warning('hit sys_%d at %#x', rax, rip)
        self._handle_syscall(uc, user_data)

    def _handle_syscall(self, uc, user_data):
        # unicorn does not support syscall, we should giveup emulation
        # and send back to SimProcedure. (ignore is always False)
        l.info('stop emulation')
        if self.UC_NATIVE is not False:
            self.UC_NATIVE.stop(self._uc_state, STOP.STOP_SYSCALL)
        else:
            self.uc.emu_stop()
        self.jumpkind = 'Ijk_Sys_syscall'

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == unicorn.UC_MEM_WRITE:
            l.debug('write [%#x, %#x]', address, address + size)
        elif access == unicorn.UC_MEM_READ:
            l.debug('read [%#x, %#x]', address, address + size)
        elif access == unicorn.UC_MEM_FETCH:
            l.debug('fetch [%#x, %#x]', address, address + size)

    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        ''' load memory from current state'''
        start = address & (0xffffffffffffff000)
        length = ((address + size + 0xfff) & (0xffffffffffffff000)) - start

        if start == 0:
            # sometimes it happens because of %fs is not correctly set
            l.warning('accessing zero page')
            self.error = 'accessing zero page [%#x, %#x]' % (address, address + size)
            if self.UC_NATIVE is not False:
                # tell uc_state to rollback
                self.UC_NATIVE.stop(self._uc_state, STOP.STOP_ZEROPAGE)
            return False

        the_bytes, missing = self.state.memory.mem.load_bytes(start, length)

        if access == unicorn.UC_MEM_FETCH_UNMAPPED and len(the_bytes) == 0:
            l.warning('fetching empty page')
            # we can not initalize an empty page then execute on it
            self.error = 'fetching empty page [%#x, %#x]' % (address, address + size)
            if self.UC_NATIVE is not False:
                self.UC_NATIVE.stop(self._uc_state, STOP.STOP_EXECNONE)
            return False

        data = bytearray(length)

        partial_symbolic = False

        offsets = sorted(the_bytes.keys())
        offsets.append(length)

        for i in xrange(len(offsets)-1):
            pos = offsets[i]
            chunk = the_bytes[pos]
            size = min(len(chunk), offsets[i + 1] - pos)
            d = chunk.bytes_at(start + pos, size)
            if d.symbolic:
                if self.UC_NATIVE is not False:
                    l.debug('loading symbolic memory [%#x, %#x]', start + pos, start + pos + size)

                    if not partial_symbolic:
                        taint = ctypes.create_string_buffer(length)
                        partial_symbolic = True

                    ctypes.memset(byref(taint, pos), 0x2, size) # mark them as TAINT_SYMBOLIC
                else:
                    l.warning('partial symbolic memory is not support in python hooks')
                    return False
            data[pos:] = self.state.se.any_str(d)

        if access == unicorn.UC_MEM_WRITE_UNMAPPED:
            l.info('mmap [%#x, %#x] rwx', start, start + length)
            self.uc.mem_map(start, length, unicorn.UC_PROT_ALL)
            if self.UC_NATIVE is False:
                self._dirty[start] = length
        else:
            # map all pages read-only
            l.info('mmap [%#x, %#x] r-x', start, start + length)
            self.uc.mem_map(start, length,
                            unicorn.UC_PROT_EXEC | unicorn.UC_PROT_READ)

        self.uc.mem_write(start, str(data))

        if self.UC_NATIVE:
            l.info('mmap: activate new page [%#x, %#x]', start, start + length)
            if partial_symbolic:
                # we have initalized tainted bits for this case
                self.UC_NATIVE.activate(self._uc_state, start, length, taint)
            elif access == unicorn.UC_MEM_WRITE_UNMAPPED:
                # we didn't initalize the bitmap for this case, should provide
                # an empty bitmap
                self.UC_NATIVE.activate(self._uc_state, start, length, None)

        return True

    def _hook_mem_prot(self, uc, access, address, size, value, user_data):
        '''
        track dirty pages in python dict, so this handler is in python.
        however, this is not necessary if we hook all memory access
        '''
        start = address & (0xffffffffffffff000)
        length = ((address + size + 0xfff) & (0xffffffffffffff000)) - start
        # the only protection violation is writing somewhere
        # we should keep track of there dirty pages
        l.info('mprotect [%#x, %#x] rwx', start, start + length)
        self.uc.mem_protect(start, length, unicorn.UC_PROT_ALL)
        self._dirty[start] = length
        return True

    def start(self, step=1):
        self.set_regs()
        addr = self.state.se.any_int(self.state.ip)

        # step = 1000000

        self.cur_steps = 0
        self.max_steps = step

        l.debug('emu_start at %#x (%d steps)', addr, step)

        if self.UC_NATIVE is False:
            self.uc.emu_start(addr, until=0)
        else:
            self.UC_NATIVE.start(self._uc_state, addr, step)

    def finish(self):
        self.get_regs()
        if self.UC_NATIVE is not False:
            head = self.UC_NATIVE.sync(self._uc_state)
            p_update = head
            while bool(p_update):
                update = p_update.contents
                l.debug('Got dirty [%#x, %#x]', update.address, update.length)
                self._dirty[update.address] = update.length
                p_update = update.next

            self.UC_NATIVE.destroy(head)
            self.cur_steps = self.UC_NATIVE.step(self._uc_state)

        self.sync()

        l.debug('finished emulation after %d steps', self.cur_steps)

    def set_regs(self):
        ''' setting unicorn registers '''
        for r, c in self._uc_regs.iteritems():
            v = getattr(self.state.regs, r)
            if v.concrete:
                self.uc.reg_write(c, self.state.se.any_int(v))
            else:
                raise SimValueError('setting a symbolic register')

        if self.arch.qemu_name == 'x86_64':
            # segment registers like %fs, %gs might be tricky in unicorn
            self.uc.reg_write(self._uc_const.UC_X86_REG_FS, 0x41414141)
            self.uc.reg_write(self._uc_const.UC_X86_REG_GS, 0x41414141)
            pass
        elif self.arch.qemu_name == 'i386':
            pass

    def get_regs(self):
        ''' loading registers from unicorn '''
        for r, c in self._uc_regs.iteritems():
            v = self.uc.reg_read(c)
            setattr(self.state.regs, r, v)

    def sync(self):
        for address, length in self._dirty.iteritems():
            l.debug('syncing [%#x, %#x]', address, address + length)
            s = self.uc.mem_read(address, length)
            self.state.memory.store(address, str(s))
        self._dirty.clear()

    def copy(self):
        u = Unicorn()
        return u

try:
    import unicorn
    SimStatePlugin.register_default('unicorn', Unicorn)
except ImportError:
    pass
