from __future__ import annotations

from .mips_elf_fast import MipsElfFastResolver
from .x86_elf_pic_plt import X86ElfPicPltResolver
from .jumptable import JumpTableResolver
from .x86_pe_iat import X86PeIatResolver
from .amd64_elf_got import AMD64ElfGotResolver
from .arm_elf_fast import ArmElfFastResolver
from .const_resolver import ConstantResolver
from .amd64_pe_iat import AMD64PeIatResolver


__all__ = (
    "MipsElfFastResolver",
    "X86ElfPicPltResolver",
    "JumpTableResolver",
    "X86PeIatResolver",
    "AMD64ElfGotResolver",
    "ArmElfFastResolver",
    "ConstantResolver",
    "AMD64PeIatResolver",
)
