from __future__ import annotations

from .mips_elf_fast import MipsElfFastResolver
from .mips_elf_got import MipsElfGotResolver
from .x86_elf_pic_plt import X86ElfPicPltResolver
from .jumptable import JumpTableResolver
from .x86_pe_iat import X86PeIatResolver
from .amd64_elf_got import AMD64ElfGotResolver
from .arm_elf_fast import ArmElfFastResolver
from .const_resolver import ConstantResolver
from .amd64_pe_iat import AMD64PeIatResolver
from .memload_resolver import MemoryLoadResolver
from .syscall_resolver import SyscallResolver


__all__ = (
    "AMD64ElfGotResolver",
    "AMD64PeIatResolver",
    "ArmElfFastResolver",
    "ConstantResolver",
    "JumpTableResolver",
    "MemoryLoadResolver",
    "MipsElfFastResolver",
    "MipsElfGotResolver",
    "SyscallResolver",
    "X86ElfPicPltResolver",
    "X86PeIatResolver",
)
