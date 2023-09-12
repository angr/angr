import copy
import speakeasy.winenv.api.winapi
import speakeasy.winenv.api.api
import speakeasy.winenv.arch
import speakeasy.common
import angr
import archinfo

FUNCTION_TO_API = {}
FUNCTION_TO_METHOD = {}
X86_REG_LOOKUP = {
    val: name[len("X86_REG_") :].lower()
    for name, val in vars(speakeasy.winenv.arch).items()
    if name.startswith("X86_REG_")
}
AMD64_REG_LOOKUP = {
    val: name[len("AMD64_REG_") :].lower()
    for name, val in vars(speakeasy.winenv.arch).items()
    if name.startswith("AMD64_REG_")
}

for _, api in speakeasy.winenv.api.winapi.API_HANDLERS:
    for _, member in vars(api).items():
        hookinfo = getattr(member, "__apihook__", None)
        if hookinfo is None:
            continue
        name = hookinfo[0]
        FUNCTION_TO_API[name] = api
        FUNCTION_TO_METHOD[name] = member


def translate_cc(scc: int, argc: int, arch: archinfo.Arch):
    if isinstance(arch, archinfo.ArchAMD64):
        cc = angr.calling_conventions.SimCCStdcall(arch)
        if scc == speakeasy.winenv.arch.CALL_CONV_FLOAT:
            ty = angr.types.SimTypeDouble()
        else:
            ty = angr.types.SimTypePointer(angr.types.SimTypeChar())
    else:
        if scc == speakeasy.winenv.arch.CALL_CONV_CDECL:
            cc = angr.calling_conventions.SimCCMicrosoftCdecl(arch)
            ty = angr.types.SimTypePointer(angr.types.SimTypeChar())
        elif scc == speakeasy.winenv.arch.CALL_CONV_STDCALL:
            cc = angr.calling_conventions.SimCCStdcall(arch)
            ty = angr.types.SimTypePointer(angr.types.SimTypeChar())
        elif scc == speakeasy.winenv.arch.CALL_CONV_FASTCALL:
            cc = angr.calling_conventions.SimCCMicrosoftFastcall(arch)
            ty = angr.types.SimTypePointer(angr.types.SimTypeChar())
        elif scc == speakeasy.winenv.arch.CALL_CONV_FLOAT:
            cc = angr.calling_conventions.SimCCStdcall(arch)
            ty = angr.types.SimTypeDouble()
        else:
            raise NotImplementedError()

    return cc, angr.types.SimTypeFunction([ty] * argc, ty)


def translate_perms(perms: int) -> int:
    prot = 0
    if perms & speakeasy.common.PERM_MEM_READ:
        prot |= 1
    if perms & speakeasy.common.PERM_MEM_WRITE:
        prot |= 2
    if perms & speakeasy.common.PERM_MEM_EXEC:
        prot |= 4
    return prot


class SpeakeasySimProcedure(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        name = kwargs["display_name"]  # provide these or die!
        project = kwargs["project"]

        _, _, argc, scc, _ = FUNCTION_TO_METHOD[name].__apihook__
        kwargs["cc"], kwargs["prototype"] = translate_cc(scc, argc, project.arch)
        super().__init__(*args, **kwargs)

    def get_api(self) -> speakeasy.winenv.api.api.ApiHandler:
        global_apis = dict(self.state.globals.get("global_apis", {}))
        self.state.globals["global_apis"] = global_apis

        api_cls = FUNCTION_TO_API[self.display_name]
        api_inst = global_apis.get(api_cls, None)
        if api_inst is None:
            api_inst = api_cls(SimStateSpeakeasyWrapper(self.state))
            api_inst.emu = None
        else:
            api_inst = copy.deepcopy(api_inst)
        global_apis[api_cls] = api_inst
        return api_inst

    def run(self, *args, **kwargs):
        api = self.get_api()
        func = getattr(api, self.display_name)
        ctx = {"func_name": self.display_name}
        emu = SimStateSpeakeasyWrapper(self.state)
        argv = [self.state.make_concrete_int(arg) for arg in args]
        api.emu = emu
        try:
            func(emu, argv, ctx)
        finally:
            api.emu = None


class SimStateSpeakeasyWrapper(speakeasy.Win32Emulator):
    def __init__(self, state: angr.SimState):
        self.state = state
        self.reg_lookup = AMD64_REG_LOOKUP if isinstance(state.arch, archinfo.ArchAMD64) else X86_REG_LOOKUP
        super().__init__({"emu_engine": "unicorn", "command_line": "prog"})
        self.mem_allocations = {}

    def reg_write(self, reg, val):
        self.state.registers.store(self.reg_lookup[reg], val)

    def reg_read(self, reg):
        return self.state.make_concrete_int(self.state.registers.load(self.reg_lookup[reg]))

    def mem_map(
        self, size, base=None, perms=speakeasy.common.PERM_MEM_RWX, tag=None, flags=0, shared=False, process=None
    ):
        if base is None:
            base = self.allocate_memory(size)
        prot = translate_perms(perms)
        self.state.memory.map_region(base, size, prot, init_zero=True)
        self.mem_allocations[base] = size
        return base

    def allocate_memory(self, size):
        addr = self.state.heap.mmap_base
        new_base = addr + size

        if new_base & 0xFFF:
            new_base = (new_base & ~0xFFF) + 0x1000

        self.state.heap.mmap_base = new_base

        return addr

    def mem_free(self, base):
        self.state.memory.unmap_region(base, self.mem_allocations[base])
        del self.mem_allocations[base]

    def mem_unmap(self, base, size):
        self.state.memory.unmap_region(base, size)
        del self.mem_allocations[base]

    def mem_remap(self, frm, to):
        raise NotImplementedError()

    def mem_write(self, addr, data):
        self.state.memory.store(addr, data)

    def mem_read(self, addr, size):
        value = self.state.memory.load(addr, size)
        value_int: int = self.state.make_concrete_int(value)
        value_bytes = value_int.to_bytes(size)
        return value_bytes

    def mem_protect(self, addr, size, perms):
        for subaddr in range(addr, addr + size, 0x1000):
            self.state.memory.permissions(subaddr, translate_perms(perms))

    def get_address_map(self, address):
        return None

    def get_reserve_map(self, address):
        raise NotImplementedError()

    def is_address_valid(self, address):
        raise NotImplementedError()

    def get_address_tag(self, address):
        return None

    def mem_reserve(self, *args, **kwargs):
        raise NotImplementedError()

    def purge_memory(self):
        raise NotImplementedError()

    def get_mem_maps(self):
        raise NotImplementedError()

    def mem_map_reserve(self, mapped_base):
        raise NotImplementedError()

    def get_mem_regions(self):
        raise NotImplementedError()

    def get_valid_ranges(self, size, addr=None):
        raise NotImplementedError()

    def get_arch(self):
        if isinstance(self.state.arch, archinfo.ArchAMD64):
            return speakeasy.winenv.arch.ARCH_AMD64
        elif isinstance(self.state.arch, archinfo.ArchX86):
            return speakeasy.winenv.arch.ARCH_X86
        else:
            raise ValueError()

    def get_ptr_size(self):
        return self.state.arch.bytes
