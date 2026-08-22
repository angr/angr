from __future__ import annotations

from pypcode import LowlevelError, OpCode, PcodeOp, Varnode

X86_REAL_MODE_LANGUAGE_ID = "x86:LE:16:Real Mode"
X86_REAL_MODE_SEGMENT_USEROP_KEY = (X86_REAL_MODE_LANGUAGE_ID, "segment")
X86_REAL_MODE_SWI_USEROP_KEY = (X86_REAL_MODE_LANGUAGE_ID, "swi")
X86_REAL_MODE_LOCK_USEROP_KEY = (X86_REAL_MODE_LANGUAGE_ID, "LOCK")
X86_REAL_MODE_UNLOCK_USEROP_KEY = (X86_REAL_MODE_LANGUAGE_ID, "UNLOCK")
X86_REAL_MODE_ADDRESS_MASK = (1 << 20) - 1
X86_PROTECTED_MODE_LANGUAGE_ID = "x86:LE:16:Protected Mode"
X86_PROTECTED_MODE_SEGMENT_USEROP_KEY = (X86_PROTECTED_MODE_LANGUAGE_ID, "segment")
X86_PROTECTED_MODE_SWI_USEROP_KEY = (X86_PROTECTED_MODE_LANGUAGE_ID, "swi")
X86_PROTECTED_MODE_LOCK_USEROP_KEY = (X86_PROTECTED_MODE_LANGUAGE_ID, "LOCK")
X86_PROTECTED_MODE_UNLOCK_USEROP_KEY = (X86_PROTECTED_MODE_LANGUAGE_ID, "UNLOCK")
X86_LOCK_MARKER_USEROP_KEYS = frozenset(
    {
        X86_REAL_MODE_LOCK_USEROP_KEY,
        X86_REAL_MODE_UNLOCK_USEROP_KEY,
        X86_PROTECTED_MODE_LOCK_USEROP_KEY,
        X86_PROTECTED_MODE_UNLOCK_USEROP_KEY,
    }
)


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


def validate_x86_lock_marker(op: PcodeOp) -> None:
    """Validate an x86 ``LOCK``/``UNLOCK`` p-code sequencing marker.

    SLEIGH brackets the ordinary load/modify/store p-code for a lock-prefixed
    instruction with these zero-operand markers. They carry no value data of
    their own; angr's AIL and symbolic-execution memory models are sequential,
    so the enclosed operations already have the semantics those models can
    represent.
    """
    if op.output is not None or len(op.inputs) != 1:
        raise ValueError("x86 lock marker must have no output or value operands")


def get_x86_segment_varnodes(op: PcodeOp) -> tuple[Varnode, Varnode, Varnode]:
    """
    Validate and return the output, selector, and offset varnodes for an x86
    ``segment`` userop in a 16-bit language.

    Real- and protected-mode SLEIGH specifications use a 16-bit selector, a
    16- or 32-bit offset (according to operand size), and a 32-bit output. The
    caller supplies the mode-specific address semantics.
    """
    output = op.output
    if output is None or len(op.inputs) != 3:
        raise ValueError("x86-16 segment userop must have an output and two operands")

    segment, offset = op.inputs[1:]
    if output.size != 4 or segment.size != 2 or offset.size not in {2, 4}:
        raise ValueError("x86 segment userop must have a 32-bit output, 16-bit selector, and 16- or 32-bit offset")

    return output, segment, offset


def get_x86_real_mode_segment_varnodes(op: PcodeOp) -> tuple[Varnode, Varnode, Varnode]:
    """Compatibility wrapper for callers that specifically handle real-mode addresses."""
    return get_x86_segment_varnodes(op)


def get_x86_swi_varnodes(op: PcodeOp) -> tuple[Varnode, Varnode]:
    """Validate and return the target output and vector input of an x86-16 ``swi`` userop."""
    output = op.output
    if output is None or len(op.inputs) != 2:
        raise ValueError("x86-16 swi userop must have a target output and one vector operand")
    vector = op.inputs[1]
    if output.size != 4 or vector.space.name != "const" or vector.size not in {1, 2}:
        raise ValueError("x86-16 swi userop must have a 32-bit target output and a constant interrupt vector")
    return output, vector
