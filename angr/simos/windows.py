from __future__ import annotations
import enum
import os
import logging
import collections
import random
import struct

import claripy
from archinfo import ArchX86, ArchAMD64
import cle.backends

from ..errors import (
    AngrSimOSError,
    SimSegfaultException,
    SimUnsupportedError,
    SimZeroDivisionException,
)
from .. import sim_options as o
from ..tablespecs import StringTableSpec
from ..procedures import SIM_LIBRARIES as L
from ..procedures.definitions import load_win32api_definitions
from .simos import SimOS

_l = logging.getLogger(name=__name__)


_VS_Security_Cookie = collections.namedtuple("_VS_Security_Cookie", ("default", "width"))
# security cookie details from visual studio, keyed by architecture name
VS_SECURITY_COOKIES = {"AMD64": _VS_Security_Cookie(0x2B992DDFA232, 48), "X86": _VS_Security_Cookie(0xBB40E64E, 32)}


class SecurityCookieInit(enum.Enum):
    NONE = 0
    RANDOM = 1
    STATIC = 2
    SYMBOLIC = 3


class SimWindows(SimOS):
    """
    Environment for the Windows Win32 subsystem. Does not support syscalls currently.
    """

    def __init__(self, project):
        super().__init__(project, name="Win32")

        load_win32api_definitions()

        self._exception_handler = None
        self.fmode_ptr = None
        self.commode_ptr = None
        self.acmdln_ptr = None
        self.wcmdln_ptr = None

    def configure_project(self):
        super().configure_project()

        # here are some symbols which we MUST hook, regardless of what the user wants
        self._weak_hook_symbol("GetProcAddress", L["kernel32.dll"].get("GetProcAddress", self.arch))
        self._weak_hook_symbol("LoadLibraryA", L["kernel32.dll"].get("LoadLibraryA", self.arch))
        self._weak_hook_symbol("LoadLibraryExW", L["kernel32.dll"].get("LoadLibraryExW", self.arch))

        self._exception_handler = self._find_or_make("KiUserExceptionDispatcher")
        self.project.hook(
            self._exception_handler, L["ntdll.dll"].get("KiUserExceptionDispatcher", self.arch), replace=True
        )

        self.fmode_ptr = self._find_or_make("_fmode")
        self.commode_ptr = self._find_or_make("_commode")
        self.acmdln_ptr = self._find_or_make("_acmdln")
        self.wcmdln_ptr = self._find_or_make("_wcmdln")

        self.is_dump = isinstance(self.project.loader.main_object, cle.backends.Minidump)

        if not self.is_dump:
            self.project.loader.tls.new_thread()

    def _find_or_make(self, name):
        sym = self.project.loader.find_symbol(name)
        if sym is None:
            return self.project.loader.extern_object.get_pseudo_addr(name)
        return sym.rebased_addr

    # pylint: disable=arguments-differ
    def state_entry(self, args=None, env=None, argc=None, **kwargs):
        state = super().state_entry(**kwargs)

        # Handle default values
        filename = self.project.filename or "dummy_filename"
        if args is None:
            args = [filename]

        if env is None:
            env = {}

        # Prepare argc
        if argc is None:
            argc = claripy.BVV(len(args), state.arch.bits)
        elif type(argc) is int:  # pylint: disable=unidiomatic-typecheck
            argc = claripy.BVV(argc, state.arch.bits)

        # Make string table for args and env
        table = StringTableSpec()
        table.append_args(args)
        table.append_env(env)

        # calculate full command line, since this is windows and that's how everything works
        cmdline = claripy.BVV(0, 0)
        for arg in args:
            if cmdline.length != 0:
                cmdline = cmdline.concat(claripy.BVV(b" "))

            if type(arg) is str:
                arg = arg.encode()
            if type(arg) is bytes:
                if b'"' in arg or b"\0" in arg:
                    raise AngrSimOSError("Can't handle windows args with quotes or nulls in them")
                arg = claripy.BVV(arg)
            elif isinstance(arg, claripy.ast.BV):
                for byte in arg.chop(8):
                    state.add_constraints(byte != claripy.BVV(b'"'))
                    state.add_constraints(byte != claripy.BVV(0, 8))
            else:
                raise TypeError("Argument must be str or bytes or bitvector")

            cmdline = cmdline.concat(claripy.BVV(b'"'), arg, claripy.BVV(b'"'))
        cmdline = cmdline.concat(claripy.BVV(0, 8))
        wcmdline = claripy.Concat(*(x.concat(0, 8) for x in cmdline.chop(8)))

        if not state.satisfiable():
            raise AngrSimOSError("Can't handle windows args with quotes or nulls in them")

        # Dump the table onto the stack, calculate pointers to args, env
        stack_ptr = state.regs.sp
        stack_ptr -= 16
        state.memory.store(stack_ptr, claripy.BVV(0, 8 * 16))

        stack_ptr -= cmdline.length // 8
        state.memory.store(stack_ptr, cmdline)
        state.mem[self.acmdln_ptr].long = stack_ptr

        stack_ptr -= wcmdline.length // 8
        state.memory.store(stack_ptr, wcmdline)
        state.mem[self.wcmdln_ptr].long = stack_ptr

        argv = table.dump(state, stack_ptr)
        envp = argv + ((len(args) + 1) * state.arch.bytes)

        # Put argc on stack and fix the stack pointer
        newsp = argv - state.arch.bytes
        state.memory.store(newsp, argc, endness=state.arch.memory_endness)
        state.regs.sp = newsp

        # store argc argv envp in the posix plugin
        state.posix.argv = argv
        state.posix.argc = argc
        state.posix.environ = envp

        state.regs.sp = state.regs.sp - 0x80  # give us some stack space to work with

        # fake return address from entry point
        return_addr = self.return_deadend
        kernel32 = self.project.loader.shared_objects.get("kernel32.dll", None)
        if kernel32:
            # some programs will use the return address from start to find the kernel32 base
            return_addr = kernel32.get_symbol("ExitProcess").rebased_addr

        if state.arch.name == "X86":
            state.mem[state.regs.sp].dword = return_addr

            # first argument appears to be PEB
            tib_addr = state.regs.fs.concat(claripy.BVV(0, 16))
            peb_addr = state.mem[tib_addr + 0x30].dword.resolved
            state.mem[state.regs.sp + 4].dword = peb_addr

        return state

    def state_blank(self, thread_idx=None, **kwargs):
        if self.project.loader.main_object.supports_nx:
            add_options = kwargs.get("add_options", set())
            add_options.add(o.ENABLE_NX)
            kwargs["add_options"] = add_options
        state = super().state_blank(thread_idx=thread_idx, **kwargs)

        if not self.is_dump:
            # yikes!!!
            fun_stuff_addr = state.heap.mmap_base
            if fun_stuff_addr & 0xFFFF != 0:
                fun_stuff_addr += 0x10000 - (fun_stuff_addr & 0xFFFF)
            state.memory.map_region(fun_stuff_addr, 0x2000, claripy.BVV(3, 3))

            TIB_addr = fun_stuff_addr
            PEB_addr = fun_stuff_addr + 0x1000

            if state.arch.name == "X86":
                LDR_addr = fun_stuff_addr + 0x2000
                if thread_idx is None:
                    thread_idx = 0

                state.mem[TIB_addr + 0].dword = -1  # Initial SEH frame
                state.mem[TIB_addr + 4].dword = state.regs.sp  # stack base (high addr)
                state.mem[TIB_addr + 8].dword = state.regs.sp - 0x100000  # stack limit (low addr)
                state.mem[TIB_addr + 0x18].dword = TIB_addr  # myself!
                state.mem[TIB_addr + 0x24].dword = 0xBAD76EAD  # thread id
                state.mem[TIB_addr + 0x2C].dword = self.project.loader.tls.threads[
                    thread_idx
                ].user_thread_pointer  # tls array pointer
                state.mem[TIB_addr + 0x30].dword = PEB_addr  # PEB addr, of course

                state.regs.fs = TIB_addr >> 16

                state.mem[PEB_addr + 0xC].dword = LDR_addr

                # OKAY IT'S TIME TO SUFFER
                # http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html
                THUNK_SIZE = 0x100
                num_pe_objects = len(self.project.loader.all_pe_objects)
                thunk_alloc_size = THUNK_SIZE * (num_pe_objects + 1)
                string_alloc_size = 0
                for obj in self.project.loader.all_pe_objects:
                    bin_name = obj.binary_basename if obj.binary is None else obj.binary
                    string_alloc_size += len(bin_name) * 2 + 2
                total_alloc_size = thunk_alloc_size + string_alloc_size
                if total_alloc_size & 0xFFF != 0:
                    total_alloc_size += 0x1000 - (total_alloc_size & 0xFFF)
                state.memory.map_region(LDR_addr, total_alloc_size, claripy.BVV(3, 3))
                state.heap.mmap_base = LDR_addr + total_alloc_size

                string_area = LDR_addr + thunk_alloc_size
                for i, obj in enumerate(self.project.loader.all_pe_objects):
                    # Create a LDR_MODULE, we'll handle the links later...
                    obj.module_id = i + 1  # HACK HACK HACK HACK
                    addr = LDR_addr + (i + 1) * THUNK_SIZE
                    state.mem[addr + 0x18].dword = obj.mapped_base
                    state.mem[addr + 0x1C].dword = obj.entry

                    # Allocate some space from the same region to store the paths
                    path = obj.binary_basename if obj.binary is None else obj.binary
                    string_size = len(path) * 2
                    tail_size = len(os.path.basename(path)) * 2
                    state.mem[addr + 0x24].short = string_size
                    state.mem[addr + 0x26].short = string_size
                    state.mem[addr + 0x28].dword = string_area
                    state.mem[addr + 0x2C].short = tail_size
                    state.mem[addr + 0x2E].short = tail_size
                    state.mem[addr + 0x30].dword = string_area + string_size - tail_size

                    for j, c in enumerate(path):
                        # if this segfaults, increase the allocation size
                        state.mem[string_area + j * 2].short = ord(c)
                    state.mem[string_area + string_size].short = 0
                    string_area += string_size + 2

                # handle the links. we construct a python list in the correct order for each, and then, uh,
                mem_order = sorted(self.project.loader.all_pe_objects, key=lambda x: x.mapped_base)
                init_order = []
                partially_loaded = set()

                def fuck_load(x):
                    if x.provides in partially_loaded:
                        return
                    partially_loaded.add(x.provides)
                    for dep in x.deps:
                        if dep in self.project.loader.shared_objects:
                            depo = self.project.loader.shared_objects[dep]
                            fuck_load(depo)
                            if depo not in init_order:
                                init_order.append(depo)

                fuck_load(self.project.loader.main_object)
                load_order = [self.project.loader.main_object, *init_order]

                def link(a, b):
                    state.mem[a].dword = b
                    state.mem[b + 4].dword = a

                # I have genuinely never felt so dead in my life as I feel writing this code
                def link_list(mods, offset):
                    if mods:
                        addr_a = LDR_addr + 12
                        addr_b = LDR_addr + THUNK_SIZE * mods[0].module_id
                        link(addr_a + offset, addr_b + offset)
                        for mod_a, mod_b in zip(mods[:-1], mods[1:]):
                            addr_a = LDR_addr + THUNK_SIZE * mod_a.module_id
                            addr_b = LDR_addr + THUNK_SIZE * mod_b.module_id
                            link(addr_a + offset, addr_b + offset)
                        addr_a = LDR_addr + THUNK_SIZE * mods[-1].module_id
                        addr_b = LDR_addr + 12
                        link(addr_a + offset, addr_b + offset)
                    else:
                        link(LDR_addr + 12, LDR_addr + 12)

                _l.debug("Load order: %s", load_order)
                _l.debug("In-memory order: %s", mem_order)
                _l.debug("Initialization order: %s", init_order)
                link_list(load_order, 0)
                link_list(mem_order, 8)
                link_list(init_order, 16)

            for loaded_object in self.project.loader.all_objects:
                if isinstance(loaded_object, cle.backends.pe.PE):
                    self._init_object_pe_security_cookie(loaded_object, state, kwargs)

        return state

    def handle_exception(self, successors, engine, exception):
        # don't bother handling non-vex exceptions
        if engine is not self.project.factory.default_engine:
            raise exception
        # don't bother handling symbolic-address exceptions
        if (
            type(exception) is SimSegfaultException
            and exception.original_addr is not None
            and exception.original_addr.symbolic
        ):
            raise exception

        _l.debug("Handling exception from block at %#x: %r", successors.addr, exception)

        # If our state was just living out the rest of an unsatisfiable guard, discard it
        # it's possible this is incomplete because of implicit constraints added by memory or ccalls...
        if not successors.initial_state.satisfiable(extra_constraints=(exception.guard,)):
            _l.debug("... NOT handling unreachable exception")
            successors.processed = True
            return

        # we'll need to wind up to the exception to get the correct state to resume from...
        # exc will be a SimError, for sure
        # executed_instruction_count is incremented when we see an imark BUT it starts at -1, so this is the correct val
        num_inst = exception.executed_instruction_count
        if num_inst >= 1:
            # scary...
            try:
                r = self.project.factory.default_engine.process(successors.initial_state, num_inst=num_inst)
                if len(r.flat_successors) != 1:
                    if exception.guard.is_true():
                        _l.error(
                            "Got %d successors while re-executing %d instructions at %#x "
                            "for unconditional exception windup",
                            len(r.flat_successors),
                            num_inst,
                            successors.initial_state.addr,
                        )
                        raise exception
                    # Try to figure out which successor is ours...
                    _, _, canon_guard = exception.guard.canonicalize()
                    for possible_succ in r.flat_successors:
                        _, _, possible_guard = possible_succ.recent_events[-1].constraint.canonicalize()
                        if canon_guard is possible_guard:
                            exc_state = possible_succ
                            break
                    else:
                        _l.error(
                            "None of the %d successors while re-executing %d instructions at %#x "
                            "for conditional exception windup matched guard",
                            len(r.flat_successors),
                            num_inst,
                            successors.initial_state.addr,
                        )
                        raise exception

                else:
                    exc_state = r.flat_successors[0]
            except Exception as e:
                # lol no
                _l.error(
                    "Got some weirdo error while re-executing %d instructions at %#x for exception windup",
                    num_inst,
                    successors.initial_state.addr,
                )
                raise exception from e
        else:
            # duplicate the history-cycle code here...
            exc_state = successors.initial_state.copy()
            exc_state.register_plugin("history", successors.initial_state.history.make_child())
            exc_state.history.recent_bbl_addrs.append(successors.initial_state.addr)

        _l.debug("... wound up state to %#x", exc_state.addr)

        # first check that we actually have an exception handler
        # we check is_true since if it's symbolic this is exploitable maybe?
        tib_addr = exc_state.regs._fs.concat(claripy.BVV(0, 16))
        if exc_state.solver.is_true(exc_state.mem[tib_addr].long.resolved == -1):
            _l.debug("... no handlers registered")
            exception.args = (f"Unhandled exception: {exception!r}",)
            raise exception
        # catch nested exceptions here with magic value
        if exc_state.solver.is_true(exc_state.mem[tib_addr].long.resolved == 0xBADFACE):
            _l.debug("... nested exception")
            exception.args = (f"Unhandled exception: {exception!r}",)
            raise exception

        # serialize the thread context and set up the exception record...
        self._dump_regs(exc_state, exc_state.regs._esp - 0x300)
        exc_state.regs.esp -= 0x400
        record = exc_state.regs._esp + 0x20
        context = exc_state.regs._esp + 0x100
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa363082(v=vs.85).aspx
        exc_state.mem[record + 0x4].uint32_t = 0  # flags = continuable
        exc_state.mem[record + 0x8].uint32_t = 0  # FUCK chained exceptions
        exc_state.mem[record + 0xC].uint32_t = exc_state.regs._eip  # exceptionaddress
        for i in range(16):  # zero out the arg count and args array
            exc_state.mem[record + 0x10 + 4 * i].uint32_t = 0
        # TOTAL SIZE: 0x50

        # the rest of the parameters have to be set per-exception type
        # https://msdn.microsoft.com/en-us/library/cc704588.aspx
        if type(exception) is SimSegfaultException:
            exc_state.mem[record].uint32_t = 0xC0000005  # STATUS_ACCESS_VIOLATION
            exc_state.mem[record + 0x10].uint32_t = 2
            exc_state.mem[record + 0x14].uint32_t = 1 if exception.reason.startswith("write-") else 0
            exc_state.mem[record + 0x18].uint32_t = exception.addr
        elif type(exception) is SimZeroDivisionException:
            exc_state.mem[record].uint32_t = 0xC0000094  # STATUS_INTEGER_DIVIDE_BY_ZERO
            exc_state.mem[record + 0x10].uint32_t = 0

        # set up parameters to userland dispatcher
        exc_state.mem[exc_state.regs._esp].uint32_t = 0xBADC0DE  # god help us if we return from this func
        exc_state.mem[exc_state.regs._esp + 4].uint32_t = record
        exc_state.mem[exc_state.regs._esp + 8].uint32_t = context

        # let's go let's go!
        # we want to use a true guard here. if it's not true, then it's already been added in windup.
        successors.add_successor(exc_state, self._exception_handler, claripy.true, "Ijk_Exception")
        successors.processed = True

    # these two methods load and store register state from a struct CONTEXT
    # https://www.nirsoft.net/kernel_struct/vista/CONTEXT.html
    @staticmethod
    def _dump_regs(state, addr):
        if state.arch.name != "X86":
            raise SimUnsupportedError("I don't know how to work with struct CONTEXT outside of i386")

        # I decline to load and store the floating point/extended registers
        state.mem[addr + 0].uint32_t = 0x07  # contextflags = control | integer | segments
        # dr0 - dr7 are at 0x4-0x18
        # fp state is at 0x1c: 8 ulongs plus a char[80] gives it size 0x70
        state.mem[addr + 0x8C].uint32_t = state.regs.gs.concat(claripy.BVV(0, 16))
        state.mem[addr + 0x90].uint32_t = state.regs.fs.concat(claripy.BVV(0, 16))
        state.mem[addr + 0x94].uint32_t = 0  # es
        state.mem[addr + 0x98].uint32_t = 0  # ds
        state.mem[addr + 0x9C].uint32_t = state.regs.edi
        state.mem[addr + 0xA0].uint32_t = state.regs.esi
        state.mem[addr + 0xA4].uint32_t = state.regs.ebx
        state.mem[addr + 0xA8].uint32_t = state.regs.edx
        state.mem[addr + 0xAC].uint32_t = state.regs.ecx
        state.mem[addr + 0xB0].uint32_t = state.regs.eax
        state.mem[addr + 0xB4].uint32_t = state.regs.ebp
        state.mem[addr + 0xB8].uint32_t = state.regs.eip
        state.mem[addr + 0xBC].uint32_t = 0  # cs
        state.mem[addr + 0xC0].uint32_t = state.regs.eflags
        state.mem[addr + 0xC4].uint32_t = state.regs.esp
        state.mem[addr + 0xC8].uint32_t = 0  # ss
        # and then 512 bytes of extended registers
        # TOTAL SIZE: 0x2cc

    @staticmethod
    def _load_regs(state, addr):
        if state.arch.name != "X86":
            raise SimUnsupportedError("I don't know how to work with struct CONTEXT outside of i386")

        # TODO: check contextflags to see what parts to deserialize
        state.regs.gs = state.mem[addr + 0x8C].uint32_t.resolved[31:16]
        state.regs.fs = state.mem[addr + 0x90].uint32_t.resolved[31:16]

        state.regs.edi = state.mem[addr + 0x9C].uint32_t.resolved
        state.regs.esi = state.mem[addr + 0xA0].uint32_t.resolved
        state.regs.ebx = state.mem[addr + 0xA4].uint32_t.resolved
        state.regs.edx = state.mem[addr + 0xA8].uint32_t.resolved
        state.regs.ecx = state.mem[addr + 0xAC].uint32_t.resolved
        state.regs.eax = state.mem[addr + 0xB0].uint32_t.resolved
        state.regs.ebp = state.mem[addr + 0xB4].uint32_t.resolved
        state.regs.eip = state.mem[addr + 0xB8].uint32_t.resolved
        state.regs.eflags = state.mem[addr + 0xC0].uint32_t.resolved
        state.regs.esp = state.mem[addr + 0xC4].uint32_t.resolved

    def initialize_segment_register_x64(self, state, concrete_target):
        """
        Set the gs register in the angr to the value of the fs register in the concrete process

        :param state:               state which will be modified
        :param concrete_target:     concrete target that will be used to read the fs register
        :return: None
        """
        _l.debug("Synchronizing gs segment register")
        state.regs.gs = self._read_gs_register_x64(concrete_target)

    def initialize_gdt_x86(self, state, concrete_target):
        """
        Create a GDT in the state memory and populate the segment registers.

        :param state:               state which will be modified
        :param concrete_target:     concrete target that will be used to read the fs register
        :return: the created GlobalDescriptorTable object
        """
        _l.debug("Creating Global Descriptor Table and synchronizing fs segment register")
        fs = self._read_fs_register_x86(concrete_target)
        gdt = self.generate_gdt(fs, 0x0)
        self.setup_gdt(state, gdt)
        return gdt

    @staticmethod
    def _read_fs_register_x86(concrete_target):
        """
        Injects small shellcode to leak the fs segment register address. In Windows x86 this address is pointed by
        gs:[0x18]
        :param concrete_target: ConcreteTarget which will be used to get the fs register address
        :return: fs register address
        :rtype string
        """
        exfiltration_reg = "eax"
        # instruction to inject for reading the value at segment value = offset
        read_fs0_x86 = b"\x64\xa1\x18\x00\x00\x00\x90\x90\x90\x90"  # mov eax, fs:[0x18]
        return concrete_target.execute_shellcode(read_fs0_x86, exfiltration_reg)

    @staticmethod
    def _read_gs_register_x64(concrete_target):
        """
        Injects small shellcode to leak the gs segment register address. In Windows x64 this address is pointed by
        gs:[0x30]
        :param concrete_target: ConcreteTarget which will be used to get the fs register address
        :return: gs register address
        :rtype string
        """
        exfiltration_reg = "rax"
        # instruction to inject for reading the value at segment value = offset
        read_gs0_x64 = b"\x65\x48\x8b\x04\x25\x30\x00\x00\x00\x90\x90\x90\x90"  # mov rax, gs:[0x30]
        return concrete_target.execute_shellcode(read_gs0_x64, exfiltration_reg)

    def get_segment_register_name(self):
        if isinstance(self.arch, ArchAMD64):
            for register in self.arch.register_list:
                if register.name == "gs":
                    return register.vex_offset
        elif isinstance(self.arch, ArchX86):
            for register in self.arch.register_list:
                if register.name == "fs":
                    return register.vex_offset
        return None

    def _init_object_pe_security_cookie(self, pe_object, state, state_kwargs):
        sc_init = state_kwargs.pop("security_cookie_init", SecurityCookieInit.STATIC)
        if sc_init is SecurityCookieInit.NONE or sc_init is None:
            return
        cookie = pe_object.load_config.get("SecurityCookie", None)
        if not cookie:
            return
        vs_cookie = VS_SECURITY_COOKIES.get(self.project.arch.name)
        if vs_cookie is None:
            _l.warning(
                "Unsupported architecture: %s for /GS, leaving _security_cookie uninitialized", self.project.arch.name
            )
            return
        if sc_init is SecurityCookieInit.RANDOM:
            sc_value = random.randint(1, (2**vs_cookie.width - 1))
            if sc_value == vs_cookie.default:
                sc_value += 1
        elif sc_init is SecurityCookieInit.STATIC:
            sc_value = struct.unpack(">I", b"cook")[0]
        elif sc_init is SecurityCookieInit.SYMBOLIC:
            sc_value = claripy.BVS("_security_cookie", state.arch.bits)
        else:
            raise TypeError(f"security_cookie_init must SecurityCookieInit, not {type(sc_init).__name__}")
        setattr(state.mem[cookie], f"uint{state.arch.bits}_t", sc_value)
