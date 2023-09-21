import os
import logging
import struct

import claripy
from cle import MetaELF
from cle.backends.elf.symbol import ELFSymbolType
from cle.backends.elf.elfcore import ELFCore
from cle.address_translator import AT
from cle.backends.elf.relocation.arm64 import R_AARCH64_TLSDESC
from archinfo import ArchX86, ArchAMD64, ArchARM, ArchAArch64, ArchMIPS32, ArchMIPS64, ArchPPC32, ArchPPC64

from ..tablespecs import StringTableSpec
from ..procedures import SIM_PROCEDURES as P, SIM_LIBRARIES as L
from ..state_plugins import SimFilesystem, SimHostFilesystem
from ..storage.file import SimFile, SimFileBase
from ..errors import AngrSyscallError
from .userland import SimUserland

_l = logging.getLogger(name=__name__)


class SimLinux(SimUserland):
    """
    OS-specific configuration for \\*nix-y OSes.
    """

    def __init__(self, project, **kwargs):
        super().__init__(
            project,
            syscall_library=L["linux"],
            syscall_addr_alignment=project.arch.instruction_alignment,
            name="Linux",
            **kwargs,
        )

        self._loader_addr = None
        self._loader_lock_addr = None
        self._loader_unlock_addr = None
        self._loader_destructor = 0
        self._error_catch_tsd_addr = None
        self._is_core = None
        self.vsyscall_addr = None

    def configure_project(self):  # pylint: disable=arguments-differ
        self._is_core = isinstance(self.project.loader.main_object, ELFCore)

        if not self._is_core:
            self._loader_addr = self.project.loader.extern_object.allocate()
            self._loader_lock_addr = self.project.loader.extern_object.allocate()
            self._loader_unlock_addr = self.project.loader.extern_object.allocate()
            self._loader_destructor = self.project.loader.extern_object.allocate()
            self._error_catch_tsd_addr = self.project.loader.extern_object.allocate()
            self.vsyscall_addr = self.project.loader.extern_object.allocate()
            self.project.hook(self._loader_addr, P["linux_loader"]["LinuxLoader"]())
            self.project.hook(self._loader_lock_addr, P["linux_loader"]["_dl_rtld_lock_recursive"]())
            self.project.hook(self._loader_unlock_addr, P["linux_loader"]["_dl_rtld_unlock_recursive"]())
            self.project.hook(self._loader_destructor, P["stubs"]["ReturnUnconstrained"](return_val=0))
            self.project.hook(
                self._error_catch_tsd_addr,
                P["linux_loader"]["_dl_initial_error_catch_tsd"](
                    static_addr=self.project.loader.extern_object.allocate()
                ),
            )
            self.project.hook(self.vsyscall_addr, P["linux_kernel"]["_vsyscall"]())

            # there are some functions we MUST use the simprocedures for, regardless of what the user wants
            self._weak_hook_symbol("__tls_get_addr", L["ld.so"].get("__tls_get_addr", self.arch))  # ld
            self._weak_hook_symbol("___tls_get_addr", L["ld.so"].get("___tls_get_addr", self.arch))  # ld
            self._weak_hook_symbol(
                "_dl_get_tls_static_info", L["ld.so"].get("_dl_get_tls_static_info", self.arch)
            )  # ld
            self._weak_hook_symbol("_dl_vdso_vsym", L["libc.so.6"].get("_dl_vdso_vsym", self.arch))  # libc

            # set up some static data in the loader object...
            _rtld_global = self.project.loader.find_symbol("_rtld_global")
            if _rtld_global is not None:
                try:
                    if isinstance(self.project.arch, ArchAMD64):
                        self.project.loader.memory.pack_word(_rtld_global.rebased_addr + 0xF08, self._loader_lock_addr)
                        self.project.loader.memory.pack_word(
                            _rtld_global.rebased_addr + 0xF10, self._loader_unlock_addr
                        )
                        self.project.loader.memory.pack_word(
                            _rtld_global.rebased_addr + 0x990, self._error_catch_tsd_addr
                        )
                    elif isinstance(self.project.arch, ArchARM):
                        self.project.loader.memory.pack_word(_rtld_global.rebased_addr + 0x7E8, self._loader_lock_addr)
                        self.project.loader.memory.pack_word(
                            _rtld_global.rebased_addr + 0x7EC, self._loader_unlock_addr
                        )
                except KeyError:
                    _l.error("KeyError while trying to set up rtld_global. Libc emulation may not work.")

            # TODO: what the hell is this
            _rtld_global_ro = self.project.loader.find_symbol("_rtld_global_ro")
            if _rtld_global_ro is not None:
                if isinstance(self.project.arch, ArchAMD64):
                    self.project.loader.memory.pack_word(
                        _rtld_global_ro.rebased_addr + 0x0D0, 2
                    )  # cpu features: kind = amd

            tls_obj = self.project.loader.tls.new_thread()
            if isinstance(self.project.arch, ArchAMD64):
                self.project.loader.memory.pack_word(tls_obj.thread_pointer + 0x28, 0x5F43414E41525900)  # _CANARY\x00
                self.project.loader.memory.pack_word(tls_obj.thread_pointer + 0x30, 0x5054524755415244)
            elif isinstance(self.project.arch, ArchX86):
                self.project.loader.memory.pack_word(tls_obj.thread_pointer + 0x10, self.vsyscall_addr)

        if isinstance(self.project.arch, ArchARM):
            # https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt
            for func_name in P["linux_kernel"]:
                if not func_name.startswith("_kuser_"):
                    continue
                func = P["linux_kernel"][func_name]
                self.project.hook(func.kuser_addr, func())
        elif isinstance(self.project.arch, ArchAArch64):
            self.project.hook(R_AARCH64_TLSDESC.RESOLVER_ADDR, P["linux_loader"]["tlsdesc_resolver"]())

        # maybe move this into archinfo?
        if self.arch.name == "X86":
            syscall_abis = ["i386"]
        elif self.arch.name == "AMD64":
            syscall_abis = ["i386", "amd64"]
        elif self.arch.name.startswith("ARM"):
            syscall_abis = ["arm"]
            if self.arch.name == "ARMHF":
                syscall_abis.append("armhf")
        elif self.arch.name == "AARCH64":
            syscall_abis = ["aarch64"]
        # https://www.linux-mips.org/wiki/WhatsWrongWithO32N32N64
        elif self.arch.name == "MIPS32":
            syscall_abis = ["mips-o32"]
        elif self.arch.name == "MIPS64":
            syscall_abis = ["mips-n32", "mips-n64"]
        elif self.arch.name == "PPC32":
            syscall_abis = ["ppc"]
        elif self.arch.name == "PPC64":
            syscall_abis = ["ppc64"]
        elif self.arch.name == "RISCV":
            syscall_abis = ["riscv32"]
        else:
            syscall_abis = []  # ?

        super().configure_project(syscall_abis)

        if not self._is_core:
            # Only set up ifunc resolution if we are using the ELF backend on AMD64
            if isinstance(self.project.loader.main_object, MetaELF):
                if isinstance(self.project.arch, (ArchAMD64, ArchX86)):
                    for binary in self.project.loader.all_objects:
                        if not isinstance(binary, MetaELF):
                            continue
                        for reloc in binary.relocs:
                            if reloc.symbol is None or reloc.resolvedby is None:
                                continue
                            try:
                                if reloc.resolvedby.subtype != ELFSymbolType.STT_GNU_IFUNC:
                                    continue
                            except ValueError:  # base class Symbol throws this, meaning we don't have an ELFSymbol, etc
                                continue
                            gotaddr = reloc.rebased_addr
                            gotvalue = self.project.loader.memory.unpack_word(gotaddr)
                            if self.project.is_hooked(gotvalue):
                                continue
                            if self.project._eager_ifunc_resolution:
                                # Resolve it!
                                resolver = self.project.factory.callable(gotvalue, "void *x()", concrete_only=True)
                                result = resolver().concrete_value
                                self.project.loader.memory.pack_word(gotaddr, result)
                            else:
                                # Replace it with an ifunc-resolve simprocedure!
                                proc = P["linux_loader"]["IFuncResolver"](
                                    display_name="IFuncResolver." + reloc.symbol.name,
                                    funcaddr=gotvalue,
                                )
                                self.project.hook(gotvalue, proc, replace=True)

    def syscall_abi(self, state):
        if state.arch.name != "AMD64":
            return None
        jk = state.history.jumpkind
        if jk is None:
            # we are being invoked in the middle of a step
            jk = state.history.parent.jumpkind
        if jk == "Ijk_Sys_int128":
            return "i386"
        elif jk == "Ijk_Sys_syscall":
            return "amd64"
        else:
            raise AngrSyscallError("Unknown syscall jumpkind %s" % jk)

    # pylint: disable=arguments-differ
    def state_blank(
        self,
        fs=None,
        concrete_fs=False,
        chroot=None,
        cwd=None,
        pathsep=b"/",
        thread_idx=None,
        init_libc=False,
        **kwargs,
    ):
        state = super().state_blank(thread_idx=thread_idx, **kwargs)

        # pre-grow the stack by 0x20 pages. unsure if this is strictly required or just a hack around a compiler bug
        if not self._is_core and hasattr(state.memory, "allocate_stack_pages"):
            state.memory.allocate_stack_pages(state.solver.eval(state.regs.sp) - 1, 0x20 * 0x1000)

        tls_obj = self.project.loader.tls.threads[thread_idx if thread_idx is not None else 0]
        if isinstance(state.arch, ArchAMD64):
            state.regs.fs = tls_obj.user_thread_pointer
        elif isinstance(state.arch, ArchX86):
            state.regs.gs = tls_obj.user_thread_pointer >> 16
        elif isinstance(state.arch, (ArchMIPS32, ArchMIPS64)):
            state.regs.ulr = tls_obj.user_thread_pointer
        elif isinstance(state.arch, ArchPPC32):
            state.regs.r2 = tls_obj.user_thread_pointer
        elif isinstance(state.arch, ArchPPC64):
            state.regs.r13 = tls_obj.user_thread_pointer
        elif isinstance(state.arch, ArchAArch64):
            state.regs.tpidr_el0 = tls_obj.user_thread_pointer

        if fs is None:
            fs = {}

        for name in fs:
            if type(fs[name]) is str:
                fs[name] = fs[name].encode("utf-8")
            if type(fs[name]) is bytes:
                fs[name] = claripy.BVV(fs[name])
            if isinstance(fs[name], claripy.Bits):
                fs[name] = SimFile(name, content=fs[name])
            if not isinstance(fs[name], SimFileBase):
                raise TypeError("Provided fs initializer with unusable type %r" % type(fs[name]))

        mounts = {}
        if concrete_fs:
            if fs:
                raise TypeError("Providing both fs and concrete_fs doesn't make sense")
            if chroot is not None:
                chroot = os.path.abspath(chroot)
            else:
                chroot = os.path.sep
            mounts[pathsep] = SimHostFilesystem(chroot)
            if cwd is None:
                cwd = os.getcwd()

                if chroot != os.path.sep:
                    # try to translate the cwd into the chroot
                    if cwd.startswith(chroot):
                        cwd = cwd[len(chroot) :]
                    else:
                        cwd = os.path.sep
                cwd = cwd.encode()
        else:
            if cwd is None:
                cwd = b"/home/user"

        state.register_plugin("fs", SimFilesystem(files=fs, pathsep=pathsep, cwd=cwd, mountpoints=mounts))

        if isinstance(self.project.loader.main_object, MetaELF) and self.project.loader.main_object.is_ppc64_abiv1:
            state.libc.ppc64_abiv = "ppc64_1"
        if init_libc:
            libc_start_main = P["glibc"]["__libc_start_main"]()
            libc_start_main.state = state
            libc_start_main._initialize_ctype_table()
            libc_start_main._initialize_errno()
        return state

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
            argc = claripy.BVV(len(args), 32)
        elif type(argc) is int:  # pylint: disable=unidiomatic-typecheck
            argc = claripy.BVV(argc, 32)

        # Make string table for args/env/auxv
        table = StringTableSpec()

        # Add args to string table
        table.append_args(args)

        # Add environment to string table
        table.append_env(env)

        # Prepare the auxiliary vector and add it to the end of the string table
        # TODO: Actually construct a real auxiliary vector
        # current vector is an AT_RANDOM entry where the "random" value is 0xaec0aec0aec0...
        aux = [(25, b"\xAE\xC0" * 8)]
        for a, b in aux:
            table.add_pointer(a)
            if isinstance(b, bytes):
                table.add_string(b)
            else:
                table.add_pointer(b)

        table.add_null()
        table.add_null()

        # Dump the table onto the stack, calculate pointers to args, env, and auxv
        state.memory.store(state.regs.sp - 16, claripy.BVV(0, 8 * 16))
        argv = table.dump(state, state.regs.sp - 16)
        envp = argv + ((len(args) + 1) * state.arch.bytes)
        auxv = argv + ((len(args) + len(env) + 2) * state.arch.bytes)

        # Put argc on stack and fix the stack pointer
        newsp = argv - state.arch.bytes
        if len(argc) < state.arch.bits:
            argc_bvv = claripy.ZeroExt(state.arch.bits - len(argc), argc)
        else:
            argc_bvv = argc
        state.memory.store(newsp, argc_bvv, endness=state.arch.memory_endness)
        state.regs.sp = newsp

        if state.arch.name in ("PPC32",):
            state.stack_push(claripy.BVV(0, 32))
            state.stack_push(claripy.BVV(0, 32))
            state.stack_push(claripy.BVV(0, 32))
            state.stack_push(claripy.BVV(0, 32))

        # store argc argv envp auxv in the posix plugin
        state.posix.argv = argv
        state.posix.argc = argc
        state.posix.environ = envp
        state.posix.auxv = auxv
        self.set_entry_register_values(state)

        # set __progname
        progname_full = 0
        progname = 0
        if args:
            progname_full = state.mem[argv].long.concrete
            progname_cur = progname_full
            progname = progname_full
            while True:
                byte = state.mem[progname_cur].byte.resolved
                if byte.symbolic:
                    break
                else:
                    if state.solver.eval(byte) == ord("/"):
                        progname = progname_cur + 1
                    elif state.solver.eval(byte) == 0:
                        break

                progname_cur += 1

        # there will be multiple copies of these symbol but the canonical ones (in the main binary,
        # or elsewhere if the main binary didn't have one) should get picked up here
        for name, val in [
            ("__progname_full", progname_full),
            ("__progname", progname),
            ("__environ", envp),
            ("environ", envp),
            ("__libc_stack_end", state.regs.sp),
        ]:
            sym = self.project.loader.find_symbol(name)
            if sym is not None:
                if sym.size != self.arch.bytes:
                    _l.warning("Something is wrong with %s - bad size", name)
                else:
                    state.memory.store(
                        sym.rebased_addr, val, size=state.arch.bytes, endness=state.arch.memory_endness, priv=True
                    )

        return state

    def set_entry_register_values(self, state):
        for reg, val in state.arch.entry_register_values.items():
            if isinstance(val, int):
                state.registers.store(reg, val)
            elif isinstance(val, (str,)):
                if val == "argc":
                    state.registers.store(reg, state.posix.argc, size=state.arch.bytes)
                elif val == "argv":
                    state.registers.store(reg, state.posix.argv)
                elif val == "envp":
                    state.registers.store(reg, state.posix.environ)
                elif val == "auxv":
                    state.registers.store(reg, state.posix.auxv)
                elif val == "ld_destructor":
                    # a pointer to the dynamic linker's destructor routine, to be called at exit
                    state.registers.store(reg, self._loader_destructor)
                elif val == "toc":
                    if self.project.loader.main_object.is_ppc64_abiv1:
                        state.registers.store(reg, self.project.loader.main_object.ppc64_initial_rtoc)
                elif val == "entry":
                    state.registers.store(reg, state.registers.load("pc"))
                elif val == "thread_pointer":
                    state.registers.store(reg, self.project.loader.tls.threads[0].user_thread_pointer)
                else:
                    _l.warning('Unknown entry point register value indicator "%s"', val)
            else:
                _l.error("What the ass kind of default value is %s?", val)

        if state.arch.name == "PPC64":
            # store argc at the top of the stack if the program is statically linked, otherwise 0
            # see sysdeps/powerpc/powerpc64/dl-machine.h, _dl_start_user
            # stack_top = state.posix.argc.sign_extend(32) if state.project.loader.linux_loader_object is None else 0
            # UMMMMMM actually nvm we're going to lie about it
            stack_top = state.posix.argc.sign_extend(32)
            state.mem[state.regs.sp].qword = stack_top

    def state_full_init(self, **kwargs):
        kwargs["addr"] = self._loader_addr
        return super().state_full_init(**kwargs)

    def prepare_function_symbol(self, symbol_name, basic_addr=None):
        """
        Prepare the address space with the data necessary to perform relocations pointing to the given symbol.

        Returns a 2-tuple. The first item is the address of the function code, the second is the address of the
        relocation target.
        """
        if self.project.loader.main_object.is_ppc64_abiv1:
            if basic_addr is not None:
                pointer = self.project.loader.memory.unpack_word(basic_addr)
                return pointer, basic_addr

            pseudo_hookaddr = self.project.loader.extern_object.get_pseudo_addr(symbol_name)
            pseudo_toc = self.project.loader.extern_object.allocate(size=0x18)
            self.project.loader.extern_object.memory.pack_word(
                AT.from_mva(pseudo_toc, self.project.loader.extern_object).to_rva(), pseudo_hookaddr
            )
            return pseudo_hookaddr, pseudo_toc
        else:
            if basic_addr is None:
                basic_addr = self.project.loader.extern_object.get_pseudo_addr(symbol_name)
            return basic_addr, basic_addr

    def initialize_segment_register_x64(self, state, concrete_target):
        """
        Set the fs register in the angr to the value of the fs register in the concrete process

        :param state:               state which will be modified
        :param concrete_target:     concrete target that will be used to read the fs register
        :return: None
        """
        _l.debug("Synchronizing fs segment register")
        state.regs.fs = self._read_fs_register_x64(concrete_target)

    def initialize_gdt_x86(self, state, concrete_target):
        """
        Create a GDT in the state memory and populate the segment registers.
        Rehook the vsyscall address using the real value in the concrete process memory

        :param state:               state which will be modified
        :param concrete_target:     concrete target that will be used to read the fs register
        :return:
        """
        _l.debug("Creating fake Global Descriptor Table and synchronizing gs segment register")
        gs = self._read_gs_register_x86(concrete_target)
        gdt = self.generate_gdt(0x0, gs)
        self.setup_gdt(state, gdt)

        # Synchronize the address of vsyscall in simprocedures dictionary with the concrete value
        _vsyscall_address = concrete_target.read_memory(gs + 0x10, state.project.arch.bits / 8)
        _vsyscall_address = struct.unpack(state.project.arch.struct_fmt(), _vsyscall_address)[0]
        state.project.rehook_symbol(_vsyscall_address, "_vsyscall", True)

        return gdt

    @staticmethod
    def _read_fs_register_x64(concrete_target):
        """
        Injects a small shellcode to leak the fs segment register address. In Linux x64 this address is pointed by fs[0]
        :param concrete_target: ConcreteTarget which will be used to get the fs register address
        :return: fs register address
        :rtype string
        """
        # register used to read the value of the segment register
        exfiltration_reg = "rax"
        # instruction to inject for reading the value at segment value = offset
        read_fs0_x64 = b"\x64\x48\x8B\x04\x25\x00\x00\x00\x00\x90\x90\x90\x90"  # mov rax, fs:[0]

        return concrete_target.execute_shellcode(read_fs0_x64, exfiltration_reg)

    @staticmethod
    def _read_gs_register_x86(concrete_target):
        """
        Injects a small shellcode to leak the gs segment register address. In Linux x86 this address is pointed by gs[0]
        :param concrete_target: ConcreteTarget which will be used to get the gs register address
        :return: gs register address
        :rtype :str
        """
        # register used to read the value of the segment register
        exfiltration_reg = "eax"
        # instruction to inject for reading the value at segment value = offset
        read_gs0_x64 = b"\x65\xA1\x00\x00\x00\x00\x90\x90\x90\x90"  # mov eax, gs:[0]
        return concrete_target.execute_shellcode(read_gs0_x64, exfiltration_reg)

    def get_segment_register_name(self):
        if isinstance(self.arch, ArchAMD64):
            for register in self.arch.register_list:
                if register.name == "fs":
                    return register.vex_offset
        elif isinstance(self.arch, ArchX86):
            for register in self.arch.register_list:
                if register.name == "gs":
                    return register.vex_offset
        return None
