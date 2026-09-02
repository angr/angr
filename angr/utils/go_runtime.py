# pylint:disable=too-many-boolean-expressions
"""
Identification of Go runtime functions that never return.

angr has no built-in knowledge of the Go runtime, so the two families of stubs that the Go compiler
emits at essentially every call site -- the goroutine stack-growth stub (``runtime.morestack``) and
the bounds-check panic stubs -- are recovered as returning functions. That attaches a large amount of
unreachable code to every Go function: a fake self-recursive tail after each ``morestack`` call site,
and one dead panic branch per bounds check.

Two identification strategies are provided, because the interesting targets are usually stripped:

* by name, when symbols (or a ``.gopclntab``-derived symbol table) are available;
* by shape, which is what actually carries stripped binaries.

A false positive here silently deletes real code, so every shape-based rule below requires either
overwhelming corroboration across the binary or an assembly signature that no compiler emits for
ordinary code.
"""

from __future__ import annotations

import logging
import struct
from collections import Counter
from typing import TYPE_CHECKING

import capstone

if TYPE_CHECKING:
    from angr.project import Project

log = logging.getLogger(name=__name__)


# Bounds-check panic kinds. The Go compiler emits a ``runtime.panic<Kind>`` ABI shim that tail-jumps
# into the ``runtime.goPanic<Kind>`` implementation; both end in runtime.gopanic.
_BOUNDS_KINDS = (
    "Index",
    "IndexU",
    "SliceAlen",
    "SliceAlenU",
    "SliceAcap",
    "SliceAcapU",
    "SliceB",
    "SliceBU",
    "Slice3Alen",
    "Slice3AlenU",
    "Slice3Acap",
    "Slice3AcapU",
    "Slice3B",
    "Slice3BU",
    "Slice3C",
    "Slice3CU",
    "SliceConvert",
)


def _bounds_names() -> set[str]:
    names = set()
    for kind in _BOUNDS_KINDS:
        for prefix in ("runtime.panic", "runtime.goPanic", "runtime.panicExtend", "runtime.goPanicExtend"):
            names.add(prefix + kind)
    return names


#: Go runtime (and a few closely related standard library) functions that never transfer control back
#: to the instruction following their call site. ``runtime.morestack`` and friends do resume the
#: caller, but at its entry point rather than at the return address, so they do not "return" in the
#: sense CFG recovery cares about.
#:
#: Deliberately excluded because they can fall through to their caller despite the suggestive names:
#: ``runtime.mexit`` (returns when running on an OS-provided stack, and with it ``runtime.mstart0``
#: and ``runtime.mstart``), ``runtime.badsystemstack``, ``runtime.badmorestackg0``,
#: ``runtime.badmorestackgsignal`` (all only print), ``runtime.systemstack``, ``runtime.panicCheck1``,
#: ``runtime.panicCheck2``, ``runtime.startpanic_m``, ``runtime.dopanic_m``.
GO_NORETURN_NAMES: frozenset[str] = frozenset(
    {
        # goroutine stack growth
        "runtime.morestack",
        "runtime.morestack_noctxt",
        "runtime.morestackc",
        # traps and process/thread exit
        "runtime.abort",
        "runtime.exit",
        "runtime.exitThread",
        "runtime.throw",
        "runtime.fatal",
        "runtime.fatalthrow",
        "runtime.fatalpanic",
        "runtime.badmcall",
        "runtime.badmcall2",
        "runtime.badreflectcall",
        "runtime.badctxt",
        "os.Exit",
        # scheduling: control leaves through gogo/mcall, never through a return
        "runtime.gogo",
        "runtime.mcall",
        "runtime.goexit",
        "runtime.goexit0",
        "runtime.goexit1",
        "runtime.Goexit",
        "runtime.schedule",
        "runtime.goschedImpl",
        "runtime.park_m",
        "runtime.exitsyscall0",
        "runtime.main",
        # panics
        "runtime.gopanic",
        "runtime.panicwrap",
        "runtime.sigpanic",
        "runtime.sigpanic0",
        "runtime.panicdivide",
        "runtime.panicshift",
        "runtime.panicoverflow",
        "runtime.panicfloat",
        "runtime.panicmem",
        "runtime.panicmemAddr",
        "runtime.panicdottypeE",
        "runtime.panicdottypeI",
        "runtime.panicnildottype",
        "runtime.panicmakeslicelen",
        "runtime.panicmakeslicecap",
        "runtime.panicunsafeslicelen",
        "runtime.panicunsafeslicelen1",
        "runtime.panicunsafeslicenilptr",
        "runtime.panicunsafeslicenilptr1",
        "runtime.panicunsafestringlen",
        "runtime.panicunsafestringlen1",
        "runtime.panicunsafestringnilptr",
        "runtime.panicunsafestringnilptr1",
        # go1.25+ collapsed the bounds-check stubs into one register-spilling dispatcher
        "runtime.panicBounds",
        "runtime.panicBounds32",
        "runtime.panicBounds64",
    }
    | _bounds_names()
)

# Suffixes the Go linker appends when a function has more than one ABI wrapper.
_GO_ABI_SUFFIXES = (".abi0", ".abiinternal")

# amd64 general-purpose registers spilled by the go1.25+ bounds-check dispatcher. RSP and R14 (the
# goroutine pointer) are the two it deliberately skips.
_AMD64_GPRS = frozenset(
    {"rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r15"}
)

# runtime.abort: INT $3 followed by a self-loop.
_ABORT_PATTERNS = (b"\xcd\x03\xeb\xfe", b"\xcc\xeb\xfd")

# How many registers the spill dispatcher must save, and how many call sites it must have, before we
# believe it. The real thing saves 14 and is called once per bounds check in the whole program.
_SPILL_MIN_REGS = 12
_SPILL_MIN_CALLSITES = 32

# A morestack candidate must be the callee of at least this many stack-check preambles, and of at
# least this fraction of all of them.
_MORESTACK_MIN_VOTES = 4
_MORESTACK_MIN_VOTE_RATIO = 0.01

_MAX_STUB_BYTES = 64

# Instructions that end a straight-line run for the purposes of the stub matchers below, on top of
# the jump/call/return capstone groups.
_TERMINATORS = frozenset({"int", "int1", "int3", "into", "syscall", "sysenter", "sysexit", "ud0", "ud1", "ud2", "hlt"})


def _is_straight_line(ins) -> bool:
    return not (
        ins.mnemonic in _TERMINATORS
        or ins.group(capstone.CS_GRP_JUMP)
        or ins.group(capstone.CS_GRP_CALL)
        or ins.group(capstone.CS_GRP_RET)
        or ins.group(capstone.CS_GRP_INT)
        or ins.group(capstone.CS_GRP_IRET)
        or ins.group(capstone.CS_GRP_PRIVILEGE)
    )


# Sections the Go toolchain emits, and the marker Go stamps into .go.buildinfo, which survives even
# when section headers do not.
_GO_SECTION_NAMES = frozenset({".gopclntab", ".gosymtab", ".go.buildinfo", ".noptrdata", ".noptrbss"})
_GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def has_go_hint(project: Project) -> bool:
    """
    Cheap test for "this might be a Go binary", to keep the (much more expensive) LanguageDetector
    off the vast majority of binaries.
    """
    obj = project.loader.main_object
    if obj.sections:
        return any(section.name in _GO_SECTION_NAMES for section in obj.sections)
    # no section table: fall back to the .go.buildinfo marker in the raw image
    memory = getattr(obj, "memory", None)
    if memory is None:
        return False
    return any(isinstance(data, (bytes, bytearray)) and _GO_BUILDINFO_MAGIC in data for _, data in memory.backers())


def normalize_go_func_name(name: str) -> str:
    """
    Strip the ABI wrapper suffix the Go linker appends to duplicated symbols.
    """
    for suffix in _GO_ABI_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def is_go_noreturn_name(name: str) -> bool:
    return normalize_go_func_name(name) in GO_NORETURN_NAMES


def find_go_noreturn_functions(project: Project, kb=None, use_names: bool = True) -> dict[int, str]:
    """
    Identify Go runtime functions in ``project`` that never return.

    The caller is responsible for having established that this is a Go binary.

    :param use_names:   Consult symbol names. Set to False to exercise the shape-based path that
                        stripped binaries depend on.
    :return:            A mapping from function address to a short description of the evidence.
    """
    verdicts: dict[int, str] = {}
    if use_names:
        _collect_by_name(project, kb if kb is not None else project.kb, verdicts)
    if project.arch.name == "AMD64":
        _collect_by_shape(project, verdicts)
    _propagate_through_jump_thunks(project, verdicts)
    return verdicts


#
# Name-based identification
#


def _collect_by_name(project: Project, kb, verdicts: dict[int, str]) -> None:
    for obj in project.loader.all_objects:
        for sym in getattr(obj, "symbols", None) or []:
            name = sym.name
            if not name or sym.is_import or not sym.rebased_addr:
                continue
            if is_go_noreturn_name(name):
                verdicts.setdefault(sym.rebased_addr, f"symbol {name}")

    # names may also reach the knowledge base without a matching symbol, e.g. from a .gopclntab
    for name in GO_NORETURN_NAMES:
        for candidate in (name, *(name + suffix for suffix in _GO_ABI_SUFFIXES)):
            for addr in kb.functions.get_addrs_by_name(candidate):
                verdicts.setdefault(addr, f"name {candidate}")


#
# Shape-based identification
#


def _executable_ranges(project: Project) -> list[tuple[int, int]]:
    obj = project.loader.main_object
    regions = [s for s in (obj.sections or []) if s.is_executable and s.memsize > 0]
    if not regions:
        regions = [s for s in (obj.segments or []) if s.is_executable and s.memsize > 0]
    return [(r.vaddr, r.memsize) for r in regions]


def _load(project: Project, addr: int, size: int) -> bytes:
    try:
        return bytes(project.loader.memory.load(addr, size))
    except KeyError:
        return b""


def _collect_by_shape(project: Project, verdicts: dict[int, str]) -> None:
    ranges = _executable_ranges(project)
    if not ranges:
        return
    blobs = [(start, _load(project, start, size)) for start, size in ranges]
    md = project.arch.capstone

    for addr, votes, total in _find_morestack(blobs, md):
        verdicts.setdefault(addr, f"stack-growth stub ({votes}/{total} stack-check preambles)")

    callsites = _direct_call_sites(blobs)
    for addr, nregs, callee in _find_spill_dispatcher(project, md, callsites):
        verdicts.setdefault(addr, f"bounds-check dispatcher ({nregs} spilled registers)")
        if callee is not None:
            # The dispatcher's only action is to spill registers and call this; if the callee
            # returned, the dispatcher would return through the epilogue that follows the call.
            verdicts.setdefault(callee, f"callee of bounds-check dispatcher {addr:#x}")

    for start, data in blobs:
        for pattern in _ABORT_PATTERNS:
            pos = data.find(pattern)
            while pos >= 0:
                if start + pos in callsites:
                    verdicts.setdefault(start + pos, "int3 self-loop (runtime.abort)")
                pos = data.find(pattern, pos + 1)


def _direct_call_sites(blobs: list[tuple[int, bytes]]) -> Counter[int]:
    """
    Count the direct ``call rel32`` sites of every target in the executable regions. This is an
    unaligned byte scan, so it over-approximates; it is only used to enumerate candidates and to
    corroborate them by call-site count.
    """
    sites: Counter[int] = Counter()
    for start, data in blobs:
        limit = len(data) - 5
        pos = data.find(b"\xe8")
        while 0 <= pos <= limit:
            (rel,) = struct.unpack("<i", data[pos + 1 : pos + 5])
            sites[start + pos + 5 + rel] += 1
            pos = data.find(b"\xe8", pos + 1)
    return sites


def _find_morestack(blobs, md) -> list[tuple[int, int, int]]:
    """
    Every non-leaf Go function starts with a goroutine stack-check preamble::

        [lea r12, [rsp - frame]]
        cmp  rsp/r12, [r14 + 0x10]      ; 49/4d 3b 66 10
        jbe  grow
        ...
      grow:
        <reload arguments>
        call runtime.morestack_noctxt
        jmp  <function entry>

    The callee of that ``call`` is morestack by construction. Requiring the trailing backwards jump
    rules out preamble look-alikes, and the verdict is only accepted when thousands of independent
    preambles agree on the same target.
    """
    votes: Counter[int] = Counter()
    total = 0
    for start, data in blobs:
        end = len(data)
        pos = data.find(b"\x3b\x66\x10")
        while pos >= 0:
            cur, pos = pos, data.find(b"\x3b\x66\x10", pos + 1)
            if cur == 0 or data[cur - 1] not in (0x49, 0x4D):
                continue
            after = cur + 3
            if after + 2 <= end and data[after] == 0x76:
                target = start + after + 2 + struct.unpack("<b", data[after + 1 : after + 2])[0]
            elif after + 6 <= end and data[after] == 0x0F and data[after + 1] == 0x86:
                target = start + after + 6 + struct.unpack("<i", data[after + 2 : after + 6])[0]
            else:
                continue
            preamble = start + cur - 1
            if not preamble < target < start + end:
                continue
            total += 1
            callee = _morestack_callee(data, start, target, preamble, md)
            if callee is not None:
                votes[callee] += 1

    if not votes:
        return []
    threshold = max(_MORESTACK_MIN_VOTES, int(total * _MORESTACK_MIN_VOTE_RATIO))
    return [(addr, count, total) for addr, count in votes.items() if count >= threshold]


def _morestack_callee(data: bytes, start: int, target: int, preamble: int, md) -> int | None:
    offset = target - start
    callee = None
    for ins in md.disasm(data[offset : offset + _MAX_STUB_BYTES], target):
        if ins.mnemonic == "call":
            if callee is not None:
                return None
            operand = ins.operands[0] if ins.operands else None
            if operand is None or operand.type != capstone.x86.X86_OP_IMM:
                return None
            callee = operand.imm
        elif ins.mnemonic == "jmp":
            operand = ins.operands[0] if ins.operands else None
            if operand is not None and operand.type == capstone.x86.X86_OP_IMM and operand.imm <= preamble:
                return callee
            return None
        elif not _is_straight_line(ins):
            return None
    return None


def _find_spill_dispatcher(project: Project, md, callsites: Counter[int]):
    """
    go1.25 replaced the per-kind bounds-check stubs with a single ``runtime.panicBounds`` dispatcher
    that spills every general-purpose register except RSP and R14 to fixed stack slots, then calls
    the Go-level implementation. It has an epilogue and a ``ret`` after that call, but they are
    unreachable, so no amount of structural analysis will conclude that it does not return.

    Nothing a compiler emits for ordinary code opens with a dozen register spills to ``[rsp + disp]``
    followed immediately by a direct call, and we additionally require the program-wide call-site
    count of a bounds-check stub.
    """
    results = []
    for addr, count in callsites.items():
        if count < _SPILL_MIN_CALLSITES:
            continue
        found = _match_spill_dispatcher(project, md, addr)
        if found is not None:
            results.append((addr, found[0], found[1]))
    return results


def _match_spill_dispatcher(project: Project, md, addr: int) -> tuple[int, int | None] | None:
    data = _load(project, addr, 256)
    if not data:
        return None
    regs: set[str] = set()
    for ins in md.disasm(data, addr):
        if ins.mnemonic == "mov" and len(ins.operands) == 2:
            dst, src = ins.operands
            if (
                dst.type == capstone.x86.X86_OP_MEM
                and dst.size == 8
                and dst.mem.index == 0
                and ins.reg_name(dst.mem.base) == "rsp"
                and src.type == capstone.x86.X86_OP_REG
                and ins.reg_name(src.reg) in _AMD64_GPRS
            ):
                regs.add(ins.reg_name(src.reg))
                continue
        if ins.mnemonic == "call":
            if len(regs) < _SPILL_MIN_REGS:
                return None
            operand = ins.operands[0] if ins.operands else None
            callee = None
            if (
                operand is not None
                and operand.type == capstone.x86.X86_OP_IMM
                and _returns_right_after(md, data, addr, ins.address + ins.size)
            ):
                callee = operand.imm
            return len(regs), callee
        if not _is_straight_line(ins):
            return None
    return None


def _returns_right_after(md, data: bytes, base: int, addr: int) -> bool:
    """Whether ``addr`` starts a branch-free epilogue that ends in a ``ret``."""
    for ins in md.disasm(data[addr - base :], addr):
        if ins.group(capstone.CS_GRP_RET):
            return True
        if not _is_straight_line(ins):
            return False
    return False


def _propagate_through_jump_thunks(project: Project, verdicts: dict[int, str]) -> None:
    """
    A branch-free stub that ends in ``jmp target`` returns exactly when ``target`` does, so every
    such stub already known to be non-returning proves its target non-returning too. This is what
    connects ``runtime.morestack_noctxt`` to ``runtime.morestack`` and the ``runtime.panic<Kind>``
    shims to their ``runtime.goPanic<Kind>`` implementations.
    """
    if project.arch.name != "AMD64":
        return
    md = project.arch.capstone
    pending = list(verdicts)
    for _ in range(4):
        discovered = []
        for addr in pending:
            target = _jump_thunk_target(project, md, addr)
            if target is not None and target not in verdicts:
                verdicts[target] = f"jump thunk target of {addr:#x}"
                discovered.append(target)
        if not discovered:
            break
        pending = discovered


def _jump_thunk_target(project: Project, md, addr: int) -> int | None:
    data = _load(project, addr, _MAX_STUB_BYTES)
    if not data:
        return None
    for ins in md.disasm(data, addr):
        if ins.mnemonic == "jmp":
            operand = ins.operands[0] if ins.operands else None
            if operand is not None and operand.type == capstone.x86.X86_OP_IMM and operand.imm != addr:
                return operand.imm
            return None
        if not _is_straight_line(ins):
            return None
    return None
