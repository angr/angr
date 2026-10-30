"""
Locate code virtualized by VMProtect and Themida/WinLicense in a PE image (a loaded file or a memory dump loaded as a
blob), so that VMDeobfuscation can be pointed at it without hand-picked addresses.

A virtualized function (or region of a function, for SDK markers) keeps its address; its bytes are replaced by a
transfer into the protector's section, where a VM entry handler saves every general-purpose register and the flags
before it starts interpreting bytecode. Both halves are checked:

* candidates: ``jmp/call rel32`` from one executable section into another, and
* confirmation: concrete execution from the candidate, with each register holding a distinct tag, must store every
  tag and push the flags within a small instruction budget.
"""

from __future__ import annotations

import bisect
import logging
import re
from dataclasses import dataclass, field

import capstone

from angr import sim_options as o
from angr.state_plugins.inspect import BP_AFTER
from .analysis import Analysis, AnalysesHub

l = logging.getLogger(name=__name__)

_SCN_EXECUTE = 0x20000000
_SCN_WRITE = 0x80000000
_THEMIDA_SECTIONS = (".themida", ".winlice", ".winlicen", ".boot")
_VMP_SECTIONS = (".vmp0", ".vmp1", ".vmp2")
_VMP_NAME = re.compile(r"^\.[A-Za-z0-9]{3}[01]$")  # VMProtect's randomized section names
_OREANS_SECTIONS = (".v-lizer",)
_GPRS = {
    64: ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
    32: ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"),
}


@dataclass
class PESection:
    name: str
    addr: int
    end: int
    raw_size: int
    writable: bool
    executable: bool

    def __contains__(self, addr: int) -> bool:
        return self.addr <= addr < self.end

    @property
    def init_end(self) -> int:
        return self.addr + min(self.end - self.addr, self.raw_size) if self.raw_size else self.addr


@dataclass
class VMProtectedFunction:
    function_addr: int | None
    function_extent: tuple[int, int] | None
    stub_start: int
    entry_site: int
    entry_kind: str
    vm_entry: int
    protector: str
    variant: str
    confidence: float
    whole_function: bool
    stub_addrs: list[int] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def vmdeobfuscation_kwargs(self) -> dict:
        """
        Parameters for VMDeobfuscation/CFGVMDeobfuscation. ``start_addr`` is where callers enter (the native
        prologue runs first); interpretation is switched on at ``vm_entry``, the first block in the protector.
        """
        start = self.function_addr if self.function_addr is not None else self.stub_start
        kw = {
            "start_addr": start,
            "vm_start_addr": start,
            "vm_entry_sites": sorted({self.stub_start, self.entry_site, *self.stub_addrs}),
            "vm_function_extent": self.function_extent,
        }
        if self.whole_function:
            kw["start_deobfuscation_immediately"] = True
        else:
            kw["deobfuscation_start_addr"] = self.vm_entry
        return kw

    def __repr__(self):
        f = "%#x" % self.function_addr if self.function_addr is not None else "?"
        return (
            f"<VMProtectedFunction {self.protector}/{self.variant} func={f} stub={self.stub_start:#x} "
            f"vm_entry={self.vm_entry:#x} conf={self.confidence:.2f}>"
        )


class VMProtectedFunctionsAnalysis(Analysis):
    """
    Find VMProtect- and Themida-virtualized functions and regions.

    :param max_save_insns:  Instruction budget within which the entry must have saved every register and the flags.
    """

    def __init__(
        self,
        max_save_insns: int = 1000,
        back_search_bytes: int = 96,
        store_in_kb: bool = True,
    ):
        self._max_save_insns = max_save_insns
        self._back_search_bytes = back_search_bytes
        self._bits = self.project.arch.bits
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self._bits == 64 else capstone.CS_MODE_32)

        self.image_base, self.sections, self._pe = self._load_sections()
        self._table = None
        self.protector_sections: list[PESection] = []
        self.functions: list[VMProtectedFunction] = []
        self.candidates: list[tuple[int, int, str]] = []
        self.unreachable_stubs: list[int] = []

        if self.project.arch.name not in ("AMD64", "X86"):
            l.warning("VMProtectedFunctions supports x86 and AMD64 only")
            return
        self._analyze()
        if store_in_kb:
            self.kb.obfuscations.vm_protected_functions = {f.stub_start: f for f in self.functions}

    #
    # Image layout
    #

    def _mem(self, addr: int, size: int) -> bytes:
        try:
            return bytes(self.project.loader.memory.load(addr, size))
        except KeyError:
            out = bytearray()
            a = addr
            while a < addr + size:
                n = min(0x1000 - (a & 0xFFF), addr + size - a)
                try:
                    out += self.project.loader.memory.load(a, n)
                except KeyError:
                    out += b"\0" * n
                a += n
            return bytes(out)

    def _load_sections(self):
        """
        Sections from the PE header in memory: present both for a loaded PE and for a dumped image loaded as a blob.
        """
        import pefile  # pylint:disable=import-outside-toplevel

        mo = self.project.loader.main_object
        base = mo.mapped_base
        hdr = self._mem(base, 0x1000)
        if hdr[:2] != b"MZ":
            return base, [], None
        try:
            pe = pefile.PE(data=hdr, fast_load=True)
        except pefile.PEFormatError:
            return base, [], None
        secs = [
            PESection(
                s.Name.rstrip(b"\0").decode(errors="replace"),
                base + s.VirtualAddress,
                base + s.VirtualAddress + s.Misc_VirtualSize,
                s.SizeOfRawData,
                bool(s.Characteristics & _SCN_WRITE),
                bool(s.Characteristics & _SCN_EXECUTE),
            )
            for s in pe.sections
            if s.Misc_VirtualSize
        ]
        return base, secs, pe

    def _section_of(self, addr: int) -> PESection | None:
        for s in self.sections:
            if addr in s:
                return s
        return None

    def _function_table(self) -> list[tuple[int, int]]:
        """(begin, end) of every RUNTIME_FUNCTION in the exception directory (x64)."""
        if self._table is None:
            self._table = self._load_function_table()
        return self._table

    def _load_function_table(self) -> list[tuple[int, int]]:
        if self._pe is None or self._bits != 64:
            return []
        dd = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(dd) <= 3 or not dd[3].VirtualAddress or not dd[3].Size:
            return []
        raw = self._mem(self.image_base + dd[3].VirtualAddress, dd[3].Size)
        out = []
        for i in range(0, len(raw) - 11, 12):
            b, e = int.from_bytes(raw[i : i + 4], "little"), int.from_bytes(raw[i + 4 : i + 8], "little")
            if 0 < b < e:
                out.append((self.image_base + b, self.image_base + e))
        return sorted(out)

    def _is_prologue(self, addr: int) -> bool:
        ins = self._insn(addr)
        if ins is None:
            return False
        ops = ins.op_str.replace(" ", "")
        return (
            (ins.mnemonic == "push" and "ptr" not in ops and not ops.startswith("0x"))
            or (ins.mnemonic == "sub" and ops.split(",")[0] in ("esp", "rsp"))
            or (ins.mnemonic == "mov" and ops in ("edi,edi", "rax,rsp", "r11,rsp"))
            or (ins.mnemonic == "mov" and ops.startswith("qwordptr[rsp+"))
        )

    def _known_function_starts(self, native: list[PESection]) -> set[int]:
        starts = {f for f in self.kb.functions} if len(self.kb.functions) else set()
        table = self._function_table()
        starts |= {b for b, _ in table}
        mo = self.project.loader.main_object
        if getattr(mo, "entry", None):
            starts.add(mo.entry)
        for sym in getattr(mo, "symbols", ()):
            if sym.is_function or getattr(sym, "is_export", False):
                starts.add(sym.rebased_addr)
        starts = {a for a in starts if any(a in s for s in native)}
        # direct call targets within native code
        for s in native:
            starts.add(s.addr)
            data = self._mem(s.addr, s.init_end - s.addr)
            for m in re.finditer(b"\xe8", data):
                i = m.start()
                if i + 5 > len(data):
                    break
                tgt = s.addr + i + 5 + int.from_bytes(data[i + 1 : i + 5], "little", signed=True)
                if s.addr <= tgt < s.init_end:
                    starts.add(tgt)
            # a prologue after int3 padding: functions called only from virtualized code have lost their call sites
            if not table:
                for m in re.finditer(b"\xcc+", data):
                    a = s.addr + m.end()
                    if a % 16 == 0 and a < s.init_end and self._is_prologue(a):
                        starts.add(a)
        return starts

    #
    # Entry discovery
    #

    def _scan_cross_section_transfers(self) -> list[tuple[int, int, str]]:
        xs = [s for s in self.sections if s.executable and s.raw_size]
        out = []
        for s in xs:
            data = self._mem(s.addr, s.init_end - s.addr)
            for m in re.finditer(b"[\xe8\xe9]", data):
                i = m.start()
                if i + 5 > len(data):
                    break
                tgt = s.addr + i + 5 + int.from_bytes(data[i + 1 : i + 5], "little", signed=True)
                for t in xs:
                    if t is not s and t.addr <= tgt < t.init_end:
                        out.append((s.addr + i, tgt, "jmp" if data[i] == 0xE9 else "call"))
                        break
        return out

    def _insn(self, addr: int):
        for ins in self._md.disasm(self._mem(addr, 16), addr):
            return ins
        return None

    def _plausible_target(self, tgt: int) -> bool:
        ins = self._insn(tgt)
        return ins is not None and (ins.mnemonic.startswith("push") or ins.mnemonic in ("call", "jmp"))

    def register_save(self, addr: int, max_insns: int | None = None) -> dict:
        """
        Concretely execute from ``addr`` with every GPR set to a distinct tag. Returns which tags were stored to the
        stack, whether the flags were pushed, the instruction count at which the save completed, and the trace.
        """
        max_insns = max_insns or self._max_save_insns
        regs = _GPRS[self._bits]
        st = self.project.factory.blank_state(
            addr=addr,
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        tags = {}
        for i, r in enumerate(regs):
            v = (0x5A17 << 48 | (i + 1) << 40 | 0x1234) if self._bits == 64 else (0x5A000000 | (i + 1) << 16 | 0x123)
            setattr(st.regs, r, v)
            tags[v] = r
        sp0 = st.solver.eval(st.regs.sp)
        word = self._bits // 8
        mask = (1 << self._bits) - 1
        saved: dict[str, int] = {}
        saved_at: list[int] = []
        count = [0]

        def on_write(state):
            a, e = state.inspect.attrs.mem_write_address, state.inspect.attrs.mem_write_expr
            if a is None or e is None or a.symbolic or e.symbolic:
                return
            a = state.solver.eval(a)
            if not sp0 - 0x4000 <= a < sp0:
                return
            v, n = state.solver.eval(e), e.size() // 8
            for k in range(0, n - word + 1, 4):
                r = tags.get((v >> (8 * k)) & mask)
                if r is not None and r not in saved:
                    saved[r] = count[0]
                    saved_at.append(state.scratch.ins_addr)

        st.inspect.b("mem_write", when=BP_AFTER, action=on_write)
        res = {"saved": saved, "saved_at": saved_at, "pushf": None, "insns": 0, "trace": [], "stop": None}
        cur = st
        while True:
            try:
                blk = self.project.factory.block(cur.addr)
                insns = blk.capstone.insns
            except Exception:  # pylint:disable=broad-except
                res["stop"] = "decode"
                break
            if not insns:
                res["stop"] = "decode"
                break
            for ins in insns:
                if res["pushf"] is None and ins.mnemonic.startswith("pushf"):
                    res["pushf"] = count[0]
                res["trace"].append(ins.address)
                count[0] += 1
            try:
                succs = self.project.factory.successors(cur, irsb=blk.vex).flat_successors
            except Exception:  # pylint:disable=broad-except
                res["stop"] = "step"
                break
            if len(saved) == len(regs) and res["pushf"] is not None:
                res["stop"] = "saved"
                break
            if not succs or count[0] >= max_insns:
                res["stop"] = "budget" if succs else "nosucc"
                break
            if count[0] >= 128 and len(saved) < 3 and res["pushf"] is None:
                # VM entries start saving registers right away
                res["stop"] = "nosave"
                break
            cur = succs[0]
            if self._section_of(cur.addr) is None:
                res["stop"] = "left"
                break
        res["insns"] = count[0]
        res["ok"] = res["stop"] == "saved"
        return res

    def _back_starts(self, site: int, anchor: int | None) -> list[int]:
        """
        Instruction starts within the window before ``site``: those of a linear sweep from ``anchor`` (a known
        function start) when it lands on ``site``, else every start whose linear decode lands exactly on ``site``.
        """
        w = self._back_search_bytes
        if anchor is not None and 0 < site - anchor <= 0x4000:
            out, a = [], anchor
            data = self._mem(anchor, site - anchor)
            for ins in self._md.disasm(data, anchor):
                if ins.address >= site - w:
                    out.append(ins.address)
                a = ins.address + ins.size
                if a >= site:
                    break
            if a == site:
                return out[::-1]
            if site - anchor <= w:
                w = site - anchor
        data = self._mem(site - w, w)
        out = []
        for d in range(1, w + 1):
            for ins in self._md.disasm(data[w - d :], site - d):
                end = ins.address + ins.size
                if end == site:
                    out.append(site - d)
                if end >= site:
                    break
        return out

    def _reachable(self, site: int, seeds: list[int], window: int = 0x4000) -> bool:
        """Is ``site`` an instruction start reached by native control flow (direct branches, fallthrough) from a seed?"""
        lo = site - window
        seen = set()
        work = [a for a in seeds if lo <= a <= site]
        while work:
            a = work.pop()
            while lo <= a <= site and a not in seen:
                if a == site:
                    return True
                seen.add(a)
                ins = self._insn(a)
                if ins is None or ins.mnemonic.startswith("ret") or ins.mnemonic in ("int3", "hlt", "ud2"):
                    break
                if a < site < a + ins.size:
                    break
                tgt = int(ins.op_str, 16) if ins.op_str.startswith("0x") else None
                if ins.mnemonic == "jmp":
                    if tgt is None:
                        break
                    a = tgt
                    continue
                if (ins.mnemonic.startswith("j") or ins.mnemonic.startswith("loop")) and tgt is not None:
                    work.append(tgt)
                a = ins.address + ins.size
        return False

    def _confirm(self, site: int, tgt: int, kind: str, func_start: int | None):
        r = self.register_save(site)
        if r["ok"]:
            return site, r
        # VMProtect 3.6+ builds the "push <bytecode ref>; call <entry>" in place, ahead of the call: find the stub
        # start. Starting inside the stub restores garbage into the registers it borrowed, so the shortest complete
        # save marks the stub start.
        if kind != "call" or r["pushf"] is None:
            return None
        best = None
        for p in self._back_starts(site, func_start):
            rr = self.register_save(p, max_insns=min(600, self._max_save_insns))
            if rr["ok"] and site in rr["trace"] and (best is None or rr["insns"] < best[1]["insns"]):
                best = (p, rr)
        return best

    def _analyze(self):
        cands = self._scan_cross_section_transfers()
        self.candidates = cands
        execs = [s for s in self.sections if s.executable and s.raw_size]
        table = self._function_table()
        anchors = None

        found = []
        for site, tgt, kind in cands:
            if not self._plausible_target(tgt):
                continue
            entry = self._containing_table_entry(table, site)
            if entry is not None:
                anchor = entry[0]
            else:
                if anchors is None:
                    anchors = sorted(self._known_function_starts(execs))
                k = bisect.bisect_right(anchors, site) - 1
                anchor = anchors[k] if k >= 0 else None
            r = self._confirm(site, tgt, kind, anchor)
            if r is None:
                continue
            found.append((site, tgt, kind, r[0], r[1]))

        # The registers must be saved by code in another section than the transfer's own: that section is a
        # protector section, and transfers originating in one are VM internals.
        valid, prot = [], set()
        for f in found:
            sec = self._save_section(f[4])
            if sec is not None and sec is not self._section_of(f[0]):
                valid.append(f)
                prot.add(id(sec))
        found = [f for f in valid if id(self._section_of(f[0])) not in prot]
        self.protector_sections = [s for s in execs if id(s) in prot]
        native = [s for s in execs if id(s) not in prot]
        starts = sorted(self._known_function_starts(native))

        # Stubs reached only by the VM (re-entry stubs VMProtect puts in the space a virtualized body freed) are not
        # function entries: the entry must be reached by the function's native code.
        if table or starts:
            reach = []
            for f in found:
                entry = self._containing_table_entry(table, f[3])
                seeds = [entry[0]] if entry is not None else starts
                if self._reachable(f[3], seeds):
                    reach.append(f)
                else:
                    self.unreachable_stubs.append(f[3])
            found = reach

        by_stub = {}
        for site, tgt, kind, stub, r in found:
            if stub in by_stub and by_stub[stub][4]["insns"] <= r["insns"]:
                continue
            by_stub[stub] = (site, tgt, kind, stub, r)
        for site, tgt, kind, stub, r in sorted(by_stub.values(), key=lambda x: x[3]):
            self.functions.append(self._describe(site, tgt, kind, stub, r, table, starts, native))

    def _save_section(self, r) -> PESection | None:
        counts = {}
        for a in r["saved_at"]:
            sec = self._section_of(a)
            if sec is not None:
                counts[id(sec)] = (counts.get(id(sec), (0, sec))[0] + 1, sec)
        if not counts:
            return None
        return max(counts.values(), key=lambda x: x[0])[1]

    @staticmethod
    def _containing_table_entry(table, addr):
        lo, hi = 0, len(table)
        while lo < hi:
            mid = (lo + hi) // 2
            if table[mid][0] <= addr:
                lo = mid + 1
            else:
                hi = mid
        if lo and table[lo - 1][0] <= addr < table[lo - 1][1]:
            return table[lo - 1]
        return None

    def _describe(self, site, tgt, kind, stub, r, table, starts, native) -> VMProtectedFunction:
        ssec, tsec = self._section_of(site), self._section_of(tgt)
        ev = []
        n_regs = len(_GPRS[self._bits])
        ev.append(
            f"{kind} {site:#x} ({ssec.name if ssec else '?'}) -> {tgt:#x} ({tsec.name if tsec else '?'}, "
            f"{'RWX' if tsec and tsec.writable else 'R-X'})"
        )
        ev.append(f"all {n_regs} GPRs and flags saved to the stack within {r['insns']} instructions from {stub:#x}")

        i0 = self._insn(tgt)
        i1 = self._insn(tgt + i0.size) if i0 is not None else None
        push_call = (
            i0 is not None
            and i1 is not None
            and i0.mnemonic == "push"
            and i0.op_str.lstrip("-").startswith("0x")
            and i1.mnemonic == "call"
            and i1.op_str.startswith("0x")
            and self._section_of(int(i1.op_str, 16)) is tsec
        )
        push_jmp = (
            i0 is not None
            and i1 is not None
            and i0.mnemonic == "push"
            and i0.op_str.lstrip("-").startswith("0x")
            and i1.mnemonic == "jmp"
            and i1.op_str.startswith("0x")
            and (self._insn(int(i1.op_str, 16)) or i0).mnemonic.startswith(("pushal", "pushad", "pushf"))
        )
        name = tsec.name.lower() if tsec else ""
        if stub != site or kind == "call":
            protector, variant = "vmprotect", "3.6+ inline entry stub"
            ev.append(f"mutated push/call entry stub built in place at {stub:#x}, ends in call into {tsec.name if tsec else '?'}")
            conf = 0.8
        elif push_call:
            protector, variant = "vmprotect", "3.x push/call entry stub"
            ev.append(f"vm entry {tgt:#x}: push {i0.op_str}; call {i1.op_str}")
            conf = 0.9
        elif i0 is not None and i0.mnemonic.startswith("pushf"):
            protector, variant = "themida", "pushf entry"
            ev.append(f"vm entry {tgt:#x} begins with {i0.mnemonic}")
            conf = 0.85 if tsec and tsec.writable else 0.75
        elif push_jmp:
            protector, variant, conf = "oreans", "push/jmp entry", 0.75
            ev.append(f"vm entry {tgt:#x}: push {i0.op_str}; jmp {i1.op_str} to a pushad/pushf handler")
        else:
            protector, variant, conf = "unknown", "register-saving entry", 0.6
        if name.startswith(_THEMIDA_SECTIONS):
            ev.append(f"target section {tsec.name} is a Themida/WinLicense section")
            conf = min(1.0, conf + 0.1) if protector == "themida" else conf
        elif name.startswith(_VMP_SECTIONS) or _VMP_NAME.match(tsec.name if tsec else ""):
            ev.append(f"target section {tsec.name} is named like VMProtect's sections")
            if protector == "unknown":
                protector = "vmprotect"
            conf = min(1.0, conf + 0.1) if protector == "vmprotect" else conf
        elif name.startswith(_OREANS_SECTIONS):
            ev.append(f"target section {tsec.name} is a Code Virtualizer section")
            conf = min(1.0, conf + 0.1) if protector == "oreans" else conf

        entry = self._containing_table_entry(table, stub)
        if entry is not None:
            fstart, extent = entry[0], entry
            ev.append(f"exception directory: function {entry[0]:#x}-{entry[1]:#x}")
        else:
            k = bisect.bisect_right(starts, stub) - 1
            fstart = starts[k] if k >= 0 else None
            nxt = starts[k + 1] if k + 1 < len(starts) else None
            sec_end = ssec.init_end if ssec else None
            extent = (fstart, min(x for x in (nxt, sec_end) if x is not None)) if fstart is not None else None
            if fstart is not None:
                ev.append(f"nearest preceding function start {fstart:#x}")
        if fstart is not None and fstart <= stub and fstart in starts:
            conf = min(1.0, conf + 0.05)
        whole = fstart == stub
        # the stub is the part of the trace before control leaves the stub's section
        prefix = []
        for a in r["trace"]:
            if ssec is None or a not in ssec:
                break
            prefix.append(a)
        stub_blocks = sorted(self._block_starts(prefix)) if prefix else [stub]
        return VMProtectedFunction(
            function_addr=fstart,
            function_extent=tuple(extent) if extent else None,
            stub_start=stub,
            entry_site=site,
            entry_kind=kind,
            vm_entry=tgt,
            protector=protector,
            variant=variant,
            confidence=round(conf, 2),
            whole_function=whole,
            stub_addrs=stub_blocks,
            evidence=ev,
        )

    def _block_starts(self, prefix: list[int]) -> set[int]:
        """Starts of the blocks along a straight-line instruction trace (first insn and every branch target)."""
        out = {prefix[0]}
        for a, b in zip(prefix, prefix[1:]):
            ins = self._insn(a)
            if ins is None or a + ins.size != b:
                out.add(b)
        return out

AnalysesHub.register_default("VMProtectedFunctions", VMProtectedFunctionsAnalysis)
