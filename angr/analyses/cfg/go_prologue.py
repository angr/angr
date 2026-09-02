"""
Recognition of the Go (gc) goroutine stack-growth preamble.

Every non-nosplit Go function starts with a check of the current stack pointer (or of the
prospective frame bottom) against ``g.stackguard0``, followed by a forward branch to a
``runtime.morestack`` trampoline appended after the function body. The conventional prologue the
architecture's ``function_prologs`` describe only comes *after* that check, so a plain prologue scan
reports function starts several instructions past the real entry.

``g.stackguard0`` sits at ``2 * ptrSize`` in ``g`` -- ``[reg + 0x10]`` on 64-bit targets,
``[reg + 8]`` on 32-bit ones. The register holding ``g`` is architectural on most targets (r14 on
amd64, x28 on arm64, r10 on arm), so the compare alone identifies the check. 386 has no dedicated g
register and reaches ``g`` through TLS with an OS-specific sequence, which is therefore part of the
pattern there.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass

# --- amd64 -----------------------------------------------------------------------------------
# reload the g pointer from TLS; only emitted in entry wrappers
_AMD64_G_LOAD = (
    rb"(?:"
    rb"\x64\x4c\x8b\x34\x25[\x00-\xff]{4}"  # mov r14, qword ptr fs:[disp32]           (linux)
    rb"|\x4c\x8b\x35[\x00-\xff]{4}\x65\x4d\x8b\x36\x4d\x8b\x36"  # via runtime.tls_g   (windows)
    rb")?"
)
# frame-bottom computation preceding the compare
_AMD64_FRAME_BOTTOM = (
    rb"(?:"
    rb"\x4c\x8d\x64\x24[\x00-\xff]"  # lea r12, [rsp + disp8]
    rb"|\x4c\x8d\xa4\x24[\x00-\xff]{4}"  # lea r12, [rsp + disp32]
    rb"|\x49\x89\xe4"  # mov r12, rsp
    rb"(?:\x49\x83\xec[\x00-\xff]|\x49\x81\xec[\x00-\xff]{4})"  # sub r12, imm
    rb"(?:\x72[\x00-\xff]|\x0f\x82[\x00-\xff]{4})"  # jb <stack growth>
    rb")"
)
_AMD64_CMP_RSP = rb"\x49\x3b\x66\x10"  # cmp rsp, qword ptr [r14 + 0x10]
_AMD64_CMP_R12 = rb"\x4d\x3b\x66\x10"  # cmp r12, qword ptr [r14 + 0x10]
_X86_JBE = rb"(?:(?P<rel8>\x76[\x00-\xff])|\x0f\x86(?P<rel32>[\x00-\xff]{4}))"

_AMD64 = re.compile(
    _AMD64_G_LOAD + rb"(?:" + _AMD64_CMP_RSP + rb"|" + _AMD64_FRAME_BOTTOM + _AMD64_CMP_R12 + rb")" + _X86_JBE
)

# --- 386 -------------------------------------------------------------------------------------
# g lives in TLS; ecx ends up holding it. Without this prefix the compare is far too generic.
_X86_G_LOAD = (
    rb"(?:"
    # mov ecx, dword ptr [runtime.tls_g]; mov ecx, dword ptr fs:[ecx]; mov ecx, dword ptr [ecx]
    rb"\x8b\x0d[\x00-\xff]{4}\x64\x8b\x09\x8b\x09"  # (windows)
    # mov ecx, dword ptr gs:[disp32]; mov ecx, dword ptr [ecx + disp32]
    rb"|\x65\x8b\x0d[\x00-\xff]{4}\x8b\x89[\x00-\xff]{4}"  # (linux)
    rb")"
)
_X86_FRAME_BOTTOM = (
    rb"(?:"
    rb"\x8d\x44\x24[\x00-\xff]"  # lea eax, [esp + disp8]
    rb"|\x8d\x84\x24[\x00-\xff]{4}"  # lea eax, [esp + disp32]
    rb"|\x89\xe0\x2d[\x00-\xff]{4}"  # mov eax, esp; sub eax, imm32
    rb"(?:\x72[\x00-\xff]|\x0f\x82[\x00-\xff]{4})"  # jb <stack growth>
    rb")"
)
_X86_CMP_ESP = rb"\x3b\x61\x08"  # cmp esp, dword ptr [ecx + 8]
_X86_CMP_EAX = rb"\x3b\x41\x08"  # cmp eax, dword ptr [ecx + 8]

_X86 = re.compile(_X86_G_LOAD + rb"(?:" + _X86_CMP_ESP + rb"|" + _X86_FRAME_BOTTOM + _X86_CMP_EAX + rb")" + _X86_JBE)

# --- arm -------------------------------------------------------------------------------------
# instruction words, stored little-endian
_ARM_G_LOAD = b"\x08\x10\x9a\xe5"  # ldr r1, [r10, #8]
_ARM_FRAME_BOTTOM = (
    rb"(?:"
    rb"[\x00-\xff][\x20-\x2f]\x4d\xe2"  # sub r2, sp, #imm
    rb"|[\x00-\xff][\xb0-\xbf][\x00-\x0f]\xe3\x0b\x20\x5d\xe0"  # movw r11, #imm16; subs r2, sp, r11
    rb"|[\x00-\xff][\xb0-\xbf]\x9f\xe5\x0b\x20\x8d\xe0"  # ldr r11, [pc, #imm]; add r2, sp, r11
    rb")"
)
_ARM_CMP_SP = rb"\x01\x00\x5d\xe1"  # cmp sp, r1
_ARM_CMP_R2 = rb"\x01\x00\x52[\xe1\x21]"  # cmp r2, r1 (unconditional, or cs after subs)
_ARM_BLS = rb"(?P<b>[\x00-\xff]{3}\x9a)"  # bls <stack growth>

_ARM = re.compile(
    re.escape(_ARM_G_LOAD) + rb"(?:" + _ARM_CMP_SP + rb"|" + _ARM_FRAME_BOTTOM + _ARM_CMP_R2 + rb")" + _ARM_BLS
)

# --- arm64 -----------------------------------------------------------------------------------
_A64_G_LOAD = b"\x90\x0b\x40\xf9"  # ldr x16, [x28, #0x10]
_A64_X27 = rb"[\x1b\x3b\x5b\x7b\x9b\xbb\xdb\xfb]"  # low byte of a movz/movk into x27
_A64_BCC = rb"[\x03\x23\x43\x63\x83\xa3\xc3\xe3][\x00-\xff]{2}\x54"  # b.cc <stack growth>
_A64_MOVZ_X27 = _A64_X27 + rb"[\x00-\xff][\x80-\x9f]\xd2"  # movz x27, #imm16
_A64_MOVK_X27 = _A64_X27 + rb"[\x00-\xff][\xa0-\xbf]\xf2"  # movk x27, #imm16, lsl #16
_A64_FRAME_BOTTOM = (
    rb"(?:"
    + rb"\xf1[\x00-\xff][\x00-\x7f]\xd1"  # sub x17, sp, #imm12
    + rb"|\xf1[\x00-\xff][\x00-\x7f]\xf1"  # subs x17, sp, #imm12
    + _A64_BCC
    + rb"|"
    + _A64_MOVZ_X27
    + rb"(?:"
    + _A64_MOVK_X27
    + rb")?\xf1\x63\x3b\xeb"  # subs x17, sp, x27
    + _A64_BCC
    + rb")"
)
_A64_CMP_SP = rb"\xff\x63\x30\xeb"  # cmp sp, x16
_A64_CMP_X17 = rb"\x3f\x02\x10\xeb"  # cmp x17, x16
_A64_BLS = rb"(?P<b>[\x09\x29\x49\x69\x89\xa9\xc9\xe9][\x00-\xff]{2}\x54)"  # b.ls <stack growth>

_A64 = re.compile(
    re.escape(_A64_G_LOAD) + rb"(?:" + _A64_CMP_SP + rb"|" + _A64_FRAME_BOTTOM + _A64_CMP_X17 + rb")" + _A64_BLS
)


def _x86_branch_target(mo: re.Match[bytes]) -> int:
    rel8 = mo.group("rel8")
    disp = struct.unpack("<b", rel8[1:])[0] if rel8 is not None else struct.unpack("<i", mo.group("rel32"))[0]
    return mo.end() + disp


def _arm_branch_target(mo: re.Match[bytes]) -> int:
    word = struct.unpack("<I", mo.group("b"))[0]
    disp = (word & 0xFFFFFF) - (0x1000000 if word & 0x800000 else 0)
    # arm branches are pc-relative with the two-instruction pipeline offset, in words
    return mo.end() - 4 + 8 + disp * 4


def _aarch64_branch_target(mo: re.Match[bytes]) -> int:
    word = struct.unpack("<I", mo.group("b"))[0]
    imm19 = (word >> 5) & 0x7FFFF
    disp = imm19 - (0x80000 if imm19 & 0x40000 else 0)
    return mo.end() - 4 + disp * 4


@dataclass(frozen=True)
class _GoPreamble:
    """The Go stack-growth preamble of one architecture."""

    regex: re.Pattern[bytes]
    branch_target: Callable[[re.Match[bytes]], int]
    alignment: int = 1
    # fixed leading bytes; set on fixed-width architectures so that an unaligned match cannot shadow
    # the aligned one that follows it
    anchor: bytes | None = None


_PREAMBLES: dict[str, _GoPreamble] = {
    "AMD64": _GoPreamble(_AMD64, _x86_branch_target),
    "X86": _GoPreamble(_X86, _x86_branch_target),
    "ARMEL": _GoPreamble(_ARM, _arm_branch_target, alignment=4, anchor=_ARM_G_LOAD),
    "ARMHF": _GoPreamble(_ARM, _arm_branch_target, alignment=4, anchor=_ARM_G_LOAD),
    "AARCH64": _GoPreamble(_A64, _aarch64_branch_target, alignment=4, anchor=_A64_G_LOAD),
}


def go_preamble_supported(arch_name: str) -> bool:
    """
    Whether the Go stack-growth preamble is recognized on the named architecture.
    """

    return arch_name in _PREAMBLES


def _matches(preamble: _GoPreamble, blob: bytes, base: int) -> Iterator[re.Match[bytes]]:
    if preamble.anchor is None:
        yield from preamble.regex.finditer(blob)
        return
    pos = blob.find(preamble.anchor)
    while pos != -1:
        if (base + pos) % preamble.alignment == 0:
            mo = preamble.regex.match(blob, pos)
            if mo is not None:
                yield mo
        pos = blob.find(preamble.anchor, pos + 1)


def find_go_stack_check_preambles(blob: bytes, arch_name: str, base: int = 0) -> Iterator[tuple[int, int, int]]:
    """
    Find every Go goroutine stack-growth preamble in ``blob``.

    :param blob:        A blob of machine code.
    :param arch_name:   ``archinfo`` name of the architecture ``blob`` is code for.
    :param base:        The address ``blob`` starts at, used to enforce instruction alignment.
    :return:            An iterator of ``(start, end, branch_target)`` offsets into ``blob``. Only
                        preambles whose stack-growth branch goes forward are reported; the caller
                        must still check that ``branch_target`` lies in the same executable region.
    """

    preamble = _PREAMBLES.get(arch_name)
    if preamble is None:
        return
    for mo in _matches(preamble, blob, base):
        target = preamble.branch_target(mo)
        if target > mo.end():
            yield mo.start(), mo.end(), target
