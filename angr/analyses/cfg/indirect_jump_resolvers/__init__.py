from __future__ import annotations

from .aarch64_macho_got import AArch64MachOGotResolver
from .amd64_elf_got import AMD64ElfGotResolver
from .amd64_pe_iat import AMD64PeIatResolver
from .arm_elf_fast import ArmElfFastResolver
from .const_resolver import ConstantResolver
from .fast_jumptable import FastJumpTableResolver
from .jumptable import JumpTableResolver
from .memload_resolver import MemoryLoadResolver
from .mips_elf_fast import MipsElfFastResolver
from .mips_elf_got import MipsElfGotResolver
from .syscall_resolver import SyscallResolver
from .x86_elf_pic_plt import X86ElfPicPltResolver
from .x86_pe_iat import X86PeIatResolver

__all__ = (
    "AArch64MachOGotResolver",
    "AMD64ElfGotResolver",
    "AMD64PeIatResolver",
    "ArmElfFastResolver",
    "ConstantResolver",
    "FastJumpTableResolver",
    "JumpTableResolver",
    "MemoryLoadResolver",
    "MipsElfFastResolver",
    "MipsElfGotResolver",
    "SyscallResolver",
    "X86ElfPicPltResolver",
    "X86PeIatResolver",
)
