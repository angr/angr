# pylint:disable=too-many-boolean-expressions
"""
Identification of Go runtime functions whose control flow CFG recovery cannot infer on its own.

angr has no built-in knowledge of the Go runtime, which gets two families of functions wrong:

* Functions that never return to their call site, chiefly the bounds-check panic stubs emitted at
  essentially every index expression. Recovered as returning, they attach one dead panic branch per
  bounds check to every Go function.
* Functions that never execute a ``ret`` but still resume their caller at the return address:
  ``runtime.morestack`` (called from the stack-check trampoline of every non-leaf function) and
  ``runtime.mcall``. Both save the caller's return address in ``g.sched`` and the scheduler later
  resumes it with ``gogo``. Inferred from their bodies, they look non-returning, which cuts the
  argument-reload stub after every ``morestack`` call site off its function and stops recovery of
  every caller of ``runtime.gopark`` at the park.

Two identification strategies are provided, because the interesting targets are usually stripped:

* by name, when symbols (or a ``.gopclntab``-derived symbol table) are available;
* by shape, which is what actually carries stripped binaries.

A false positive here silently deletes real code, so every shape-based rule below requires either
overwhelming corroboration across the binary or an assembly signature that no compiler emits for
ordinary code.
"""

from __future__ import annotations

import logging
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
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


#: Panic helpers that only compiler-inserted checks call: bounds/slice checks (per-kind stubs before go1.25, the
#: ``panicBounds`` dispatcher after), integer division/shift checks, and the unsafe.Slice/String checks.
GO_CHECK_PANIC_NAMES: frozenset[str] = frozenset(
    {
        "runtime.panicBounds",
        "runtime.panicBounds32",
        "runtime.panicBounds64",
        "runtime.panicdivide",
        "runtime.panicshift",
        "runtime.panicoverflow",
        "runtime.panicunsafeslicelen",
        "runtime.panicunsafeslicelen1",
        "runtime.panicunsafeslicenilptr",
        "runtime.panicunsafeslicenilptr1",
        "runtime.panicunsafestringlen",
        "runtime.panicunsafestringlen1",
        "runtime.panicunsafestringnilptr",
        "runtime.panicunsafestringnilptr1",
    }
    | _bounds_names()
)


#: Failure stubs of type assertions (``x.(T)``): the check that guards them is the assertion itself.
GO_ASSERT_PANIC_NAMES: frozenset[str] = frozenset(
    {"runtime.panicdottypeE", "runtime.panicdottypeI", "runtime.panicnildottype"}
)


#: Go runtime (and a few closely related standard library) functions that never transfer control back
#: to the instruction following their call site, checked against the runtime sources of go1.4 to go1.27.
#:
#: Deliberately excluded because they can fall through to their caller despite the suggestive names:
#: ``runtime.mexit`` (returns when running on an OS-provided stack, and with it ``runtime.mstart0``
#: and ``runtime.mstart``), ``runtime.badsystemstack``, ``runtime.badmorestackg0``,
#: ``runtime.badmorestackgsignal`` (all only print), ``runtime.systemstack``, ``runtime.panicCheck1``,
#: ``runtime.panicCheck2``, ``runtime.startpanic_m``, ``runtime.dopanic_m``, and the functions in
#: :data:`GO_RESUMING_NAMES`.
GO_NORETURN_NAMES: frozenset[str] = frozenset(
    {
        # the stack-growth stub of //go:systemstack functions: throw (go1.11+) or systemstack(throw) (go1.9, go1.10)
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
        "runtime.goexit",
        "runtime.goexit0",
        "runtime.goexit1",
        "runtime.Goexit",
        "runtime.schedule",
        "runtime.execute",
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
        "runtime.panicunsafestringnilptr",
        # go1.25+ collapsed the bounds-check stubs into one register-spilling dispatcher
        "runtime.panicBounds",
        "runtime.panicBounds32",
        "runtime.panicBounds64",
        # their 32-bit counterpart for 64-bit indexes (386, arm)
        "runtime.panicExtend",
        "runtime.panicBounds32X",
    }
    | _bounds_names()
)

#: Go runtime functions that never execute a ``ret``, but whose callers are resumed at the return address:
#: they save it in ``g.sched`` and the scheduler later continues there through ``gogo``. Their bodies end
#: in calls that do not return (``abort``, ``badmcall2``), so they must be marked as returning explicitly.
GO_RESUMING_NAMES: frozenset[str] = frozenset({"runtime.morestack", "runtime.morestack_noctxt", "runtime.mcall"})

#: The goroutine stack-growth stubs called from function preambles: ``morestack`` (and ``morestack_noctxt``)
#: grows the stack and resumes the caller after the call, which reloads its arguments and restarts itself;
#: ``morestackc`` is called instead by //go:systemstack functions and throws.
GO_STACK_GROWTH_NAMES: frozenset[str] = frozenset(
    {"runtime.morestack", "runtime.morestack_noctxt", "runtime.morestackc"}
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
# least this fraction of all stackguard0 ones.
_MORESTACK_MIN_VOTES = 4
_MORESTACK_MIN_VOTE_RATIO = 0.01

_MAX_STUB_BYTES = 64

# offsets of g.stackguard0 and g.stackguard1
_STACKGUARD0 = 0x10
_STACKGUARD1 = 0x18
# cmp rsp/r12, [r14 + guard] (go1.17+) or cmp rsp/rax, [rcx + guard] (before), then jbe
_STACK_CHECK = re.compile(
    rb"(?:[\x49\x4d]\x3b\x66|\x48\x3b[\x41\x61])(?P<guard>[\x10\x18])(?:\x76(?P<rel8>.)|\x0f\x86(?P<rel32>.{4}))",
    re.DOTALL,
)
# how far into a function its stack check may start (after a TLS load of g and a frame-bottom computation)
_PREAMBLE_WINDOW = 32

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
_GO_SECTION_NAMES = frozenset(
    {
        # ELF
        ".gopclntab",
        ".gosymtab",
        ".go.buildinfo",
        ".noptrdata",
        ".noptrbss",
        # Mach-O
        "__gopclntab",
        "__gosymtab",
        "__go_buildinfo",
        "__noptrdata",
        "__noptrbss",
    }
)
_GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def has_go_hint(project: Project) -> bool:
    """
    Cheap test for "this might be a Go binary", to keep the (much more expensive) LanguageDetector
    off the vast majority of binaries.
    """
    obj = project.loader.main_object
    if obj.sections and any(section.name in _GO_SECTION_NAMES for section in obj.sections):
        return True
    # no section table, or one without Go names (PE): fall back to the .go.buildinfo marker in the raw image
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


def is_go_resuming_name(name: str) -> bool:
    return normalize_go_func_name(name) in GO_RESUMING_NAMES


def is_go_stack_growth_name(name: str) -> bool:
    return normalize_go_func_name(name) in GO_STACK_GROWTH_NAMES


@dataclass
class GoRuntimeFunctions:
    """
    Go runtime functions identified in a binary, each mapped to a short description of the evidence.

    :ivar noreturn:     Functions that never return to their call site.
    :ivar resuming:     Functions that never execute a ``ret`` but resume their caller at the return address.
    :ivar stack_growth: The stack-growth stubs that function preambles call (morestack and morestackc). Each is
                        in ``noreturn`` or ``resuming`` as well.
    """

    noreturn: dict[int, str] = field(default_factory=dict)
    resuming: dict[int, str] = field(default_factory=dict)
    stack_growth: dict[int, str] = field(default_factory=dict)


def find_go_runtime_functions(project: Project, kb=None, use_names: bool = True) -> GoRuntimeFunctions:
    """
    Identify the Go runtime functions in ``project`` whose control flow CFG recovery must be told about.

    The caller is responsible for having established that this is a Go binary.

    :param use_names:   Consult symbol names. Set to False to exercise the shape-based path that
                        stripped binaries depend on.
    """
    found = GoRuntimeFunctions()
    if use_names:
        _collect_by_name(project, kb if kb is not None else project.kb, found)
    if project.arch.name == "AMD64":
        _collect_by_shape(project, found)
    # a jump thunk returns exactly when its target does
    _propagate_through_jump_thunks(project, found.noreturn)
    _propagate_through_jump_thunks(project, found.resuming)
    _propagate_through_jump_thunks(project, found.stack_growth)
    for addr in found.resuming:
        found.noreturn.pop(addr, None)
    return found


def find_go_noreturn_functions(project: Project, kb=None, use_names: bool = True) -> dict[int, str]:
    """
    Identify Go runtime functions in ``project`` that never return. See :func:`find_go_runtime_functions`.

    :return:            A mapping from function address to a short description of the evidence.
    """
    return find_go_runtime_functions(project, kb=kb, use_names=use_names).noreturn


#
# Name-based identification
#


_NAME_TABLES = (
    ("noreturn", GO_NORETURN_NAMES),
    ("resuming", GO_RESUMING_NAMES),
    ("stack_growth", GO_STACK_GROWTH_NAMES),
)


def _collect_by_name(project: Project, kb, found: GoRuntimeFunctions) -> None:
    for obj in project.loader.all_objects:
        for sym in getattr(obj, "symbols", None) or []:
            name = sym.name
            if not name or sym.is_import or not sym.rebased_addr:
                continue
            normalized = normalize_go_func_name(name)
            for attr, names in _NAME_TABLES:
                if normalized in names:
                    getattr(found, attr).setdefault(sym.rebased_addr, f"symbol {name}")

    # names may also reach the knowledge base without a matching symbol, e.g. from a .gopclntab
    for attr, names in _NAME_TABLES:
        verdicts = getattr(found, attr)
        for name in names:
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


def _collect_by_shape(project: Project, found: GoRuntimeFunctions) -> None:
    ranges = _executable_ranges(project)
    if not ranges:
        return
    blobs = [(start, _load(project, start, size)) for start, size in ranges]
    md = project.arch.capstone

    for addr, guard, votes, total in _find_stack_growth_stubs(blobs, md):
        evidence = f"stack-growth stub ({votes}/{total} stack-check preambles on g+{guard:#x})"
        found.stack_growth.setdefault(addr, evidence)
        if guard == _STACKGUARD0:
            found.resuming.setdefault(addr, evidence)
        else:
            found.noreturn.setdefault(addr, evidence)

    verdicts = found.noreturn
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


def _find_stack_growth_stubs(blobs, md) -> list[tuple[int, int, int, int]]:
    """
    Every non-leaf Go function starts with a goroutine stack-check preamble::

        [lea r12, [rsp - frame]]
        cmp  rsp/r12, [g + guard]
        jbe  grow
        ...
      grow:
        <spill register arguments>
        call runtime.morestack_noctxt
        <reload register arguments>
        jmp  <function entry>

    ``g`` is r14 from go1.17 on, and rcx (loaded from TLS) before. The guard is ``g.stackguard0``, except in
    //go:systemstack functions, which check ``g.stackguard1`` and call ``runtime.morestackc`` instead.

    The callee of that ``call`` is the stack-growth stub by construction. Requiring the trailing backwards
    jump rules out preamble look-alikes, and a verdict is only accepted when many independent preambles agree
    on the same target.

    :return:    ``(callee, guard offset, votes, preambles)`` per accepted stub.
    """
    votes: Counter[tuple[int, int]] = Counter()
    totals: Counter[int] = Counter()
    for start, data in blobs:
        end = len(data)
        for mo in _STACK_CHECK.finditer(data):
            guard = data[mo.start("guard")]
            rel8, rel32 = mo.group("rel8"), mo.group("rel32")
            disp = struct.unpack("<b", rel8)[0] if rel8 is not None else struct.unpack("<i", rel32)[0]
            target = start + mo.end() + disp
            preamble = start + mo.start()
            if not preamble < target < start + end:
                continue
            totals[guard] += 1
            callee = _morestack_callee(data, start, target, preamble, md)
            if callee is not None:
                votes[(guard, callee)] += 1

    results = []
    morestack = set()
    threshold = max(_MORESTACK_MIN_VOTES, int(totals[_STACKGUARD0] * _MORESTACK_MIN_VOTE_RATIO))
    for (guard, addr), count in votes.items():
        if guard == _STACKGUARD0 and count >= threshold:
            results.append((addr, guard, count, totals[guard]))
            morestack.add(addr)

    # morestackc: the one callee that (nearly) all stackguard1 preambles agree on; it is nosplit itself
    matched = sum(count for (guard, _), count in votes.items() if guard == _STACKGUARD1)
    for (guard, addr), count in votes.items():
        if (
            guard == _STACKGUARD1
            and count >= _MORESTACK_MIN_VOTES
            and count * 2 > matched
            and addr not in morestack
            and not _starts_with_stack_check(blobs, addr)
        ):
            results.append((addr, guard, count, totals[guard]))
    return results


def _starts_with_stack_check(blobs, addr: int) -> bool:
    for start, data in blobs:
        if start <= addr < start + len(data):
            offset = addr - start
            return _STACK_CHECK.search(data[offset : offset + _PREAMBLE_WINDOW]) is not None
    return False


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
    verdict about such a stub carries over to its target. This is what connects the
    ``runtime.panic<Kind>`` shims to their ``runtime.goPanic<Kind>`` implementations, and
    ``runtime.morestack_noctxt`` to ``runtime.morestack``.
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
