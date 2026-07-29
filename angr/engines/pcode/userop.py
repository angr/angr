from __future__ import annotations

from pypcode import LowlevelError, OpCode, PcodeOp, Varnode

X86_REAL_MODE_LANGUAGE_ID = "x86:LE:16:Real Mode"
X86_REAL_MODE_SEGMENT_USEROP_KEY = (X86_REAL_MODE_LANGUAGE_ID, "segment")
X86_REAL_MODE_ADDRESS_MASK = (1 << 20) - 1


def get_named_userop_key(language_id: str, op: PcodeOp) -> tuple[str, str]:
    """
    Return the language-qualified name of a CALLOTHER operation.

    SLEIGH userop identifiers are local to a language, so the language ID is
    part of the dispatch key. This prevents an operation with the same name in
    another processor specification from accidentally receiving these
    semantics.
    """
    if op.opcode != OpCode.CALLOTHER:
        raise ValueError(f"Expected CALLOTHER, got {op.opcode}")
    if not op.inputs:
        raise ValueError("CALLOTHER has no userop identifier")

    try:
        name = op.inputs[0].getUserDefinedOpName()
    except LowlevelError as ex:
        raise ValueError("CALLOTHER has an unknown userop identifier") from ex
    if not name:
        raise ValueError("CALLOTHER has an unknown userop identifier")
    return language_id, name


def get_x86_real_mode_segment_varnodes(op: PcodeOp) -> tuple[Varnode, Varnode, Varnode]:
    """
    Validate and return the output, segment, and offset varnodes for the x86
    real-mode ``segment`` userop.

    The sizes come from ``x86-16-real.pspec``: two 16-bit inputs and one
    32-bit output.
    """
    output = op.output
    if output is None or len(op.inputs) != 3:
        raise ValueError("x86 real-mode segment userop must have an output and two operands")

    segment, offset = op.inputs[1:]
    if output.size != 4 or segment.size != 2 or offset.size != 2:
        raise ValueError("x86 real-mode segment userop must have a 32-bit output and two 16-bit operands")

    return output, segment, offset
