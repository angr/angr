"""Reads of ``KUSER_SHARED_DATA``, the page Windows maps read-only at the fixed
virtual address ``0x7FFE0000`` in every user-mode process (x86, x64 and ARM64
alike). ntdll, kernel32 and countless drivers read its fields through the
``SharedUserData`` macro of ntddk.h/wdm.h, which compiles to a bare load from an
absolute constant address::

    SharedUserData->NtMajorVersion   ==   *(volatile ULONG *)0x7FFE026C

Kernel-mode code reaches the same page through ``KI_USER_SHARED_DATA``
(``0xFFDF0000`` on x86, ``0xFFFFF78000000000`` on x64), so each field's pattern
accepts the user- and the arch-appropriate kernel-mode address.

The absolute address *is* the guard here: there is no plausible non-Windows
meaning for a load from ``0x7FFE0000 + small offset``, so these are default-on
and take no parameters (``params=()``) -- the synthesized call is a nullary
accessor whose return type is the field's type.

Field offsets are those of the WDK ``ddk/ntddk.h`` ``KUSER_SHARED_DATA``
(cross-checked with ``offsetof`` on i686 and x86_64, and against Geoff
Chappell's version-annotated layout); only offsets that have been stable from
Windows XP through Windows 11 are default-on. Calibrated against
tests/x86_64/windows/known_patterns_wdk_ksud.exe (-O2, mingw).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .dsl import PBinOp, PChoice, PConst, PLoad, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

# the user-mode mapping of KUSER_SHARED_DATA (identical on x86/x64/arm64)
USER_SHARED_DATA_VA = 0x7FFE0000
# the kernel-mode mapping (ntddk.h KI_USER_SHARED_DATA), per architecture
KI_USER_SHARED_DATA = {
    "X86": 0xFFDF0000,
    "AMD64": 0xFFFFF78000000000,
}

_CTYPE_BY_SIZE = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int", 8: "unsigned long long"}


@dataclass(frozen=True)
class KsudField:
    """One KUSER_SHARED_DATA field access: its byte offset, the load width used
    to read it, and the accessor's name.

    ``stable`` is False for offsets that moved between Windows versions; those
    templates exist but are not enabled by default.
    """

    offset: int
    name: str
    size: int
    stable: bool = True


# KUSER_SHARED_DATA fields, WDK ddk/ntddk.h layout. KSYSTEM_TIME fields
# (InterruptTime/SystemTime/TimeZoneBias/TickCount) are read either as a whole
# 64-bit quad or as their 32-bit LowPart, so both widths get an entry.
KUSER_SHARED_DATA_FIELDS: tuple[KsudField, ...] = (
    KsudField(0x000, "TickCountLow", 4),  # TickCountLowDeprecated since 5.2
    KsudField(0x004, "TickCountMultiplier", 4),
    KsudField(0x008, "InterruptTime", 8),
    KsudField(0x008, "InterruptTimeLowPart", 4),
    KsudField(0x014, "SystemTime", 8),
    KsudField(0x014, "SystemTimeLowPart", 4),
    KsudField(0x020, "TimeZoneBias", 8),
    KsudField(0x020, "TimeZoneBiasLowPart", 4),
    KsudField(0x02C, "ImageNumberLow", 2),
    KsudField(0x02E, "ImageNumberHigh", 2),
    KsudField(0x240, "TimeZoneId", 4),
    KsudField(0x244, "LargePageMinimum", 4),
    KsudField(0x264, "NtProductType", 4),
    KsudField(0x268, "ProductTypeIsValid", 1),
    KsudField(0x26C, "NtMajorVersion", 4),
    KsudField(0x270, "NtMinorVersion", 4),
    KsudField(0x2D0, "SuiteMask", 4),
    KsudField(0x2D4, "KdDebuggerEnabled", 1),
    KsudField(0x2D8, "ActiveConsoleId", 4),
    KsudField(0x2E8, "NumberOfPhysicalPages", 4),
    KsudField(0x2EC, "SafeBootMode", 1),
    KsudField(0x2F0, "SharedDataFlags", 4),
    KsudField(0x320, "TickCountQuad", 8),
    KsudField(0x320, "TickCountLowPart", 4),
    KsudField(0x330, "Cookie", 4),
    # SystemCall sits at 0x300 up to Windows 7 and at 0x308 from Windows 8 on
    # (QpcFrequency took 0x300); neither offset can be named with confidence
    # without knowing the target's Windows version, so both are opt-in.
    KsudField(0x300, "SystemCall_pre_win8", 4, stable=False),
    KsudField(0x308, "SystemCall_win8", 4, stable=False),
)


def _base_addrs(ctx: PatternContext) -> list[int]:
    """The addresses KUSER_SHARED_DATA is mapped at on ``ctx``'s architecture:
    the user-mode VA plus, where known, the kernel-mode VA."""
    addrs = [USER_SHARED_DATA_VA]
    km = KI_USER_SHARED_DATA.get(ctx.arch_name)
    if km is not None:
        addrs.append(km)
    return addrs


def make_shared_user_data_template(field: KsudField):
    """A ``SharedUserData->`` field-read template for one KUSER_SHARED_DATA
    field: a load of ``field.size`` bytes from the field's fixed address."""
    call_name = f"SharedUserData_{field.name}"

    def build(ctx: PatternContext) -> KnownPattern:
        addr_pats = [PConst(base + field.offset) for base in _base_addrs(ctx)]
        addr = addr_pats[0] if len(addr_pats) == 1 else PChoice(*addr_pats)
        return KnownPattern(
            name=f"ksud_{field.name.lower()}_{field.size}",
            display_name=f"SharedUserData->{field.name}",
            call_name=call_name,
            pattern=PLoad(addr, size=field.size),
            params=(),
            returnty=_CTYPE_BY_SIZE[field.size],
        )

    return make_template(
        call_name,
        build,
        platforms=("windows",),
        enabled_by_default=field.stable,
        name=f"ksud_{field.name.lower()}_{field.size}",
    )


#
# NTSTATUS severity predicates (ntdef.h)
#
#     NT_INFORMATION(s) == (((ULONG)(s)) >> 30) == 1
#     NT_WARNING(s)     == (((ULONG)(s)) >> 30) == 2
#     NT_ERROR(s)       == (((ULONG)(s)) >> 30) == 3
#
# Both gcc and MSVC rewrite the shift-and-compare into a mask-and-compare
# against the severity field, ``(s & 0xC0000000) == sev << 30``, so both shapes
# are accepted. ``NT_SUCCESS(s) == (NTSTATUS)(s) >= 0`` is deliberately absent:
# it is a bare sign test on a signed integer and matches essentially every
# ``x >= 0`` in a binary.
#

NTSTATUS_SEVERITY_MASK = 0xC0000000

NTSTATUS_SEVERITIES: tuple[tuple[str, int], ...] = (
    ("NT_INFORMATION", 1),
    ("NT_WARNING", 2),
    ("NT_ERROR", 3),
)


def make_ntstatus_severity_template(macro: str, severity: int):
    """An NTSTATUS severity-predicate template: ``(s >> 30) == severity``, in
    either the literal shift form or the mask form the compilers prefer."""

    def build(ctx: PatternContext) -> KnownPattern:  # pylint:disable=unused-argument
        return KnownPattern(
            name=macro.lower(),
            display_name=macro,
            call_name=macro,
            pattern=PChoice(
                PBinOp(
                    "CmpEQ",
                    (
                        PBinOp("And", (PVVar("s"), PConst(NTSTATUS_SEVERITY_MASK))),
                        PConst(severity << 30),
                    ),
                ),
                PBinOp(
                    "CmpEQ",
                    (
                        PBinOp(frozenset({"Shr", "Sar"}), (PVVar("s"), PConst(30))),
                        PConst(severity),
                    ),
                ),
            ),
            # NTSTATUS is a 32-bit signed LONG; spell it "int" so the argument
            # width is 32 bits on LLP64 targets too
            params=(PatternParam("s", type="int"),),
            returnty="int",
        )

    return make_template(macro, build, platforms=("windows",), name=macro.lower())


ALL_NTSTATUS_TEMPLATES = [make_ntstatus_severity_template(m, sev) for m, sev in NTSTATUS_SEVERITIES]

ALL_WDK_TEMPLATES = [make_shared_user_data_template(f) for f in KUSER_SHARED_DATA_FIELDS] + ALL_NTSTATUS_TEMPLATES
