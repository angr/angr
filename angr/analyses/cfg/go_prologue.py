"""
Recognition of the Go (gc) goroutine stack-growth preamble on x86-64.

Every non-nosplit Go function starts with a check of the current stack pointer (or of the
prospective frame bottom) against ``g.stackguard0`` at ``[r14 + 0x10]``, followed by a forward ``jbe``
to a ``runtime.morestack`` trampoline appended after the function body. The conventional
``push rbp; mov rbp, rsp`` prologue only comes *after* that check, so a plain prologue scan reports
function starts 6 to 31 bytes past the real entry.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterator

# mov r14, qword ptr fs:[disp32] -- reload the g pointer; only emitted in entry wrappers
_G_LOAD = rb"(?:\x64\x4c\x8b\x34\x25[\x00-\xff]{4})?"
# frame-bottom computation preceding the compare
_FRAME_BOTTOM = (
    rb"(?:"
    rb"\x4c\x8d\x64\x24[\x00-\xff]"  # lea r12, [rsp + disp8]
    rb"|\x4c\x8d\xa4\x24[\x00-\xff]{4}"  # lea r12, [rsp + disp32]
    rb"|\x49\x89\xe4"  # mov r12, rsp
    rb"(?:\x49\x83\xec[\x00-\xff]|\x49\x81\xec[\x00-\xff]{4})"  # sub r12, imm
    rb"(?:\x72[\x00-\xff]|\x0f\x82[\x00-\xff]{4})"  # jb <stack growth>
    rb")"
)
_CMP_RSP = rb"\x49\x3b\x66\x10"  # cmp rsp, qword ptr [r14 + 0x10]
_CMP_R12 = rb"\x4d\x3b\x66\x10"  # cmp r12, qword ptr [r14 + 0x10]
_JBE = rb"(?:(?P<rel8>\x76[\x00-\xff])|\x0f\x86(?P<rel32>[\x00-\xff]{4}))"

GO_STACK_CHECK_PREAMBLE = re.compile(_G_LOAD + rb"(?:" + _CMP_RSP + rb"|" + _FRAME_BOTTOM + _CMP_R12 + rb")" + _JBE)


def find_go_stack_check_preambles(blob: bytes) -> Iterator[tuple[int, int, int]]:
    """
    Find every Go goroutine stack-growth preamble in ``blob``.

    :param blob:    A blob of x86-64 machine code.
    :return:        An iterator of ``(start, end, branch_target)`` offsets into ``blob``. Only
                    preambles whose ``jbe`` branches forward are reported; the caller must still
                    check that ``branch_target`` lies in the same executable region.
    """

    for mo in GO_STACK_CHECK_PREAMBLE.finditer(blob):
        rel8 = mo.group("rel8")
        disp = struct.unpack("<b", rel8[1:])[0] if rel8 is not None else struct.unpack("<i", mo.group("rel32"))[0]
        if disp > 0:
            yield mo.start(), mo.end(), mo.end() + disp
