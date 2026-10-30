"""
Bounded concrete emulation of a VM (unicorn) to find where it hands control back to native code.
"""

from __future__ import annotations

import logging
import time

import unicorn as uc_mod
from unicorn import x86_const as X

from .vm_protected_functions import VMExit

l = logging.getLogger(name=__name__)

_RET_SENTINEL = {64: 0x7EAD_DEAD_0000, 32: 0x7EAD0000}
_STACK = {64: 0x7FF0_0000_0000, 32: 0x7F000000}
_STACK_SIZE = 0x200000
_MAX_DEMAND_PAGES = 4096

# (value returned by native callees, value returned by APIs, dword pattern for stack and registers). 0, 1 and -1 are
# the usual success/failure results.
DEFAULT_CONFIGS = tuple(
    (callee, api, fill) for fill in (0, 1, 0x10) for callee in (0, 1) for api in (0, 1, -1)
)


class VMExitEmulator:
    max_calls = 256
    time_budget = 20.0

    def __init__(self, analysis, func):
        self.a = analysis
        self.f = func
        self.project = analysis.project
        self.bits = self.project.arch.bits
        self.word = self.bits // 8
        self.prot = [(s.addr, s.end) for s in analysis.protector_sections]
        sec = analysis._section_of(func.stub_start)
        self.native = [
            (s.addr, s.end) for s in analysis.sections if s.executable and s.raw_size and s not in analysis.protector_sections
        ]
        if sec is not None and (sec.addr, sec.end) not in self.native:
            self.native.append((sec.addr, sec.end))

    def _in(self, ranges, addr):
        return any(lo <= addr < hi for lo, hi in ranges)

    def _is_ret(self, addr: int) -> bool:
        ins = self.a._insn(addr)
        return ins is not None and ins.mnemonic == "ret"

    def _reenters(self, addr: int, max_insns: int = 8) -> bool:
        """Does straight-line code at ``addr`` transfer into a protector section right away (a re-entry stub)?"""
        for _ in range(max_insns):
            ins = self.a._insn(addr)
            if ins is None:
                return False
            if ins.mnemonic in ("jmp", "call") and ins.op_str.startswith("0x"):
                tgt = int(ins.op_str, 16)
                if self._in(self.prot, tgt):
                    return True
                if ins.mnemonic == "call":
                    return False
                addr = tgt
                continue
            if ins.mnemonic.startswith(("j", "ret", "call", "loop")):
                return False
            addr = ins.address + ins.size
        return False

    def _stdcall_bytes(self, addr: int, sp: int, sp0: int) -> int:
        """Bytes of arguments an x86 callee pops: from the import's prototype, else back to the region's frame."""
        if self.bits != 32:
            return 0
        sym = self.project.loader.find_symbol(addr)
        if sym is not None:
            import angr  # pylint:disable=import-outside-toplevel

            reloc = getattr(self.project.loader.main_object, "imports", {}).get(sym.name)
            dll = str(getattr(reloc, "resolvewith", "") or "").lower()
            if dll.startswith(("msvcr", "ucrtbase", "api-ms-win-crt", "vcruntime")):
                return 0
            for lib in angr.SIM_LIBRARIES.get(dll) or []:
                proto = lib.get_prototype(sym.name) if hasattr(lib, "get_prototype") else None
                if proto is not None:
                    return 4 * len(proto.args)
            return 0
        # unknown callee (a dumped image's IAT points into the dumped process' DLLs): most Win32 APIs are stdcall, and
        # virtualized code calls with the region's frame as the base of the arguments
        return max(0, sp0 - (sp + 4))

    def run(self, configs=None, max_insns: int = 20_000_000) -> list[VMExit]:
        exits: dict[tuple, VMExit] = {}
        for cfg in configs or DEFAULT_CONFIGS:
            try:
                events = self._run_one(*cfg, max_insns=max_insns)
            except uc_mod.UcError as ex:
                l.debug("exit emulation failed for %s: %s", self.f, ex)
                continue
            for kind, addr, reentry, sp_delta in events:
                key = (kind, addr, reentry)
                if key in exits:
                    exits[key].hits += 1
                else:
                    exits[key] = VMExit(addr, kind, reentry, sp_delta=sp_delta)
        return sorted(exits.values(), key=lambda e: (e.kind, e.addr or 0, e.reentry or 0))

    def _start(self) -> int:
        """The protected function's start when the stub lies in its body: its prologue builds the native frame."""
        f = self.f
        if f.function_addr is not None and f.function_extent and f.function_addr <= f.stub_start < f.function_extent[1]:
            return f.function_addr
        return f.stub_start

    def _run_one(self, callee_ret: int, api_ret: int, fill: int, max_insns: int, start: int | None = None):
        start = self._start() if start is None else start
        bits, word = self.bits, self.word
        uc = uc_mod.Uc(uc_mod.UC_ARCH_X86, uc_mod.UC_MODE_64 if bits == 64 else uc_mod.UC_MODE_32)
        mo = self.project.loader.main_object
        lo, hi = mo.min_addr & ~0xFFF, (mo.max_addr + 0x1000) & ~0xFFF
        uc.mem_map(lo, hi - lo)
        for addr, data in self.project.loader.memory.backers():
            if lo <= addr < hi:
                uc.mem_write(addr, bytes(data[: hi - addr]))

        stack = _STACK[bits]
        uc.mem_map(stack - _STACK_SIZE // 2, _STACK_SIZE)
        if fill:
            uc.mem_write(stack - _STACK_SIZE // 2, fill.to_bytes(4, "little") * (_STACK_SIZE // 4))
        sp0 = stack - 0x1000
        sentinel = _RET_SENTINEL[bits]
        uc.mem_write(sp0, sentinel.to_bytes(word, "little"))
        teb = stack + _STACK_SIZE
        uc.mem_map(teb, 0x10000)
        if bits == 64:
            SP, BP, IP, AX = X.UC_X86_REG_RSP, X.UC_X86_REG_RBP, X.UC_X86_REG_RIP, X.UC_X86_REG_RAX
            others = (
                X.UC_X86_REG_RBX, X.UC_X86_REG_RCX, X.UC_X86_REG_RDX, X.UC_X86_REG_RSI, X.UC_X86_REG_RDI,
                X.UC_X86_REG_R8, X.UC_X86_REG_R9, X.UC_X86_REG_R10, X.UC_X86_REG_R11, X.UC_X86_REG_R12,
                X.UC_X86_REG_R13, X.UC_X86_REG_R14, X.UC_X86_REG_R15,
            )  # fmt: skip
            uc.reg_write(X.UC_X86_REG_GS_BASE, teb)
            uc.mem_write(teb + 0x30, teb.to_bytes(8, "little"))
        else:
            SP, BP, IP, AX = X.UC_X86_REG_ESP, X.UC_X86_REG_EBP, X.UC_X86_REG_EIP, X.UC_X86_REG_EAX
            others = (X.UC_X86_REG_EBX, X.UC_X86_REG_ECX, X.UC_X86_REG_EDX, X.UC_X86_REG_ESI, X.UC_X86_REG_EDI)
        for r in (AX, *others):
            uc.reg_write(r, fill)
        uc.reg_write(BP, sp0 + 0x800)
        uc.reg_write(SP, sp0)

        events = []
        st = {"entered": False, "pages": 0, "stub": set(self.f.stub_addrs) | {self.f.stub_start}, "pending": None}
        st["sp_stub"] = sp0

        def top():
            return int.from_bytes(uc.mem_read(uc.reg_read(SP), word), "little")

        def vm_code(addr):
            return self._in(self.prot, addr) or addr in st["stub"]

        # Native code runs on the native frame; while the VM is active its saved context lies between the native frame
        # and the stack pointer. VMProtect 3.6+ also places handler fragments and re-entry stubs in .text, inside the
        # virtualized body, sometimes reached by call; the VM never calls into the body it replaced.
        n_ctx = (len(others) + 2) * word
        ext = self.f.function_extent or (self.f.stub_start, self.f.stub_start)

        # a call out of the VM is completed outside the emulator: stop, fake the return, restart
        def on_native(_uc, addr, _size, _ud):
            if not st["entered"]:
                if self.f.stub_start <= addr <= self.f.entry_site:
                    st["stub"].add(addr)
                return
            if addr in st["stub"] or st["pending"] is not None:
                return
            ra = top()
            inside = self.f.entry_kind == "call" and ext[0] <= addr < ext[1]
            if uc.reg_read(SP) < st["sp_stub"] - n_ctx or (inside and vm_code(ra)):
                st["stub"].add(addr)
                return
            if vm_code(ra):
                st["pending"] = ("call", addr, ra, callee_ret, 0)
            elif not ext[0] <= addr < ext[1] and self.f.function_extent is not None:
                # the VM leaves for another function without a VM return address: a tail or no-return call
                st["pending"] = ("call", addr, ra, None, 0)
            elif self._reenters(addr) or (uc.reg_read(SP) < st["sp_stub"] and self._is_ret(addr)):
                # a re-entry stub, or a ret gadget the VM routes through (a native return would be above the frame)
                st["stub"].add(addr)
                return
            else:
                st["pending"] = ("native", addr, None, None, 0)
            uc.emu_stop()

        def on_prot(_uc, _addr, _size, _ud):
            if not st["entered"]:
                st["entered"] = True
                for h in st["prot_hooks"]:
                    uc.hook_del(h)

        def on_unmapped(_uc, access, addr, size, _value, _ud):
            if access in (uc_mod.UC_MEM_FETCH_UNMAPPED, uc_mod.UC_MEM_FETCH_PROT):
                if addr == sentinel:
                    st["pending"] = ("return", None, None, None, 0)
                else:
                    ra = top()
                    if vm_code(ra) or self._in(self.native, ra):
                        ret = api_ret if st["entered"] else 0
                        pops = self._stdcall_bytes(addr, uc.reg_read(SP), st["sp_stub"])
                        st["pending"] = ("call", addr, ra, ret, pops)
                return False
            if st["pages"] >= _MAX_DEMAND_PAGES:
                return False
            page = addr & ~0xFFF
            n = ((addr + size + 0xFFF) & ~0xFFF) - page
            try:
                uc.mem_map(page, n)
                if fill:
                    uc.mem_write(page, fill.to_bytes(4, "little") * (n // 4))
            except uc_mod.UcError:
                return False
            st["pages"] += n // 0x1000
            return True

        def on_stub(_uc, _addr, _size, _ud):
            if not st["entered"]:
                st["sp_stub"] = uc.reg_read(SP)

        uc.hook_add(uc_mod.UC_HOOK_CODE, on_stub, begin=self.f.stub_start, end=self.f.stub_start)
        for nlo, nhi in self.native:
            uc.hook_add(uc_mod.UC_HOOK_BLOCK, on_native, begin=nlo, end=nhi - 1)
        st["prot_hooks"] = [uc.hook_add(uc_mod.UC_HOOK_BLOCK, on_prot, begin=plo, end=phi - 1) for plo, phi in self.prot]
        uc.hook_add(uc_mod.UC_HOOK_MEM_UNMAPPED | uc_mod.UC_HOOK_MEM_FETCH_PROT, on_unmapped)

        pc, end = start, (1 << bits) - 1
        deadline = time.monotonic() + self.time_budget
        for _ in range(self.max_calls):
            st["pending"] = None
            try:
                uc.emu_start(pc, end, count=max_insns)
            except uc_mod.UcError as ex:
                if st["pending"] is None:
                    l.debug("emulation of %#x stopped: %s at %#x", self.f.stub_start, ex, uc.reg_read(IP))
            p = st["pending"]
            if p is None:
                l.debug("run ended without event at %#x", uc.reg_read(IP))
                break
            kind, addr, ra, ret_value, extra = p
            delta = uc.reg_read(SP) - st["sp_stub"]
            l.debug("event %s %s ra=%s sp delta %d", kind, hex(addr) if addr else None, hex(ra) if ra else None, delta)
            if st["entered"]:
                events.append((kind, addr, ra, delta))
            if kind != "call" or ret_value is None or time.monotonic() > deadline:
                break
            uc.reg_write(SP, uc.reg_read(SP) + word + extra)
            uc.reg_write(AX, ret_value & ((1 << bits) - 1))
            pc = ra
        l.debug("config %s: %d events, last %s", (callee_ret, api_ret, fill), len(events), events[-1:])
        if not st["entered"] and start != self.f.stub_start:
            return self._run_one(callee_ret, api_ret, fill, max_insns, start=self.f.stub_start)
        return events
