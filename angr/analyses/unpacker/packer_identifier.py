from __future__ import annotations

import collections
import math
import re
import struct
from dataclasses import dataclass, field

import capstone
import pefile

from angr.analyses.analysis import AnalysesHub, Analysis

from .vmprotect_static import has_packer_info

IMAGE_SCN_CNT_CODE = 0x20
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
IMAGE_SCN_MEM_EXECUTE = 0x20000000
_CODE_AND_DATA = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA

_STD_CODE_NAMES = {".text", "code", ".itext", ".text2", "text", ".textbss"}
_THEMIDA_NAMES = {".themida", ".winlice", ".boot", ".taggant"}
_OUTER_PACKERS = (
    (re.compile(r"^\.?upx\d", re.IGNORECASE), "UPX"),
    (re.compile(r"^\.mpress\d", re.IGNORECASE), "MPRESS"),
    (re.compile(r"^\.(aspack|adata)", re.IGNORECASE), "ASPack"),
    (re.compile(r"^pec\d", re.IGNORECASE), "PECompact"),
    (re.compile(r"^\.?petite", re.IGNORECASE), "Petite"),
    (re.compile(r"^\.?nsp\d", re.IGNORECASE), "NsPack"),
    (re.compile(r"^\.enigma\d", re.IGNORECASE), "Enigma"),
    (re.compile(r"^\.?mew", re.IGNORECASE), "MEW"),
)
_ENTROPY_SAMPLE = 4 << 20


def entropy(data: bytes) -> float:
    data = data[:_ENTROPY_SAMPLE]
    if not data:
        return 0.0
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in collections.Counter(data).values())


def call_target_score(data: bytes, va: int, lo: int, hi: int) -> int:
    """
    This function counts the distinct targets inside the image that at least three `call rel32` instructions share.
    Compiler output scores from tens to thousands. Compressed or encrypted bytes score about zero.
    """
    data = data[:_ENTROPY_SAMPLE]
    hits: collections.Counter[int] = collections.Counter()
    pos = data.find(b"\xe8")
    while 0 <= pos <= len(data) - 5:
        target = va + pos + 5 + struct.unpack_from("<i", data, pos + 1)[0]
        if lo <= target < hi:
            hits[target] += 1
        pos = data.find(b"\xe8", pos + 1)
    return sum(1 for count in hits.values() if count >= 3)


def section_name(section: pefile.SectionStructure) -> str:
    return section.Name.split(b"\0")[0].decode("latin-1")


@dataclass
class SectionFeatures:
    """
    The measurements of a section that we use to identify the packer.
    """

    name: str
    rva: int
    vsize: int
    raw_size: int
    characteristics: int
    entropy: float
    calls: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)


@dataclass
class PackerInfo:
    """
    The result of packer identification on a PE file.
    """

    protector: str | None = None
    packed: bool | None = None
    outer_packer: str | None = None
    reason: str = ""
    evidence: list[str] = field(default_factory=list)
    sections: list[SectionFeatures] = field(default_factory=list)
    code_section: int | None = None
    ep_section: int | None = None


def _vmp_section_group(names: list[str]) -> list[int]:
    group = [i for i, name in enumerate(names) if name.lower().startswith(".vmp")]
    if group:
        return group
    for name in names:
        if len(name) >= 2 and name.endswith("1") and name[:-1] + "0" in names:
            prefix = name[:-1]
            if not any(pattern.match(prefix + "0") for pattern, _ in _OUTER_PACKERS):
                return [i for i, other in enumerate(names) if other in (prefix + "0", prefix + "1", prefix + "2")]
    return []


def _entry_mnemonics(pe: pefile.PE, sections: list[SectionFeatures]) -> tuple[list[str], int | None]:
    """
    This function follows the direct jumps from the entry point and returns the mnemonics on the way.
    If the code reaches a `push imm32; call rel32` VM entry of VMProtect, this function also returns the index of the
    section that the call targets.
    """
    is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32)
    base = pe.OPTIONAL_HEADER.ImageBase
    rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    mnemonics: list[str] = []
    for _ in range(16):
        try:
            code = pe.get_data(rva, 64)
        except pefile.PEFormatError:
            break
        insns = list(md.disasm(code, base + rva))
        jumped = False
        for idx, insn in enumerate(insns):
            mnemonics.append(insn.mnemonic)
            nxt = insns[idx + 1] if idx + 1 < len(insns) else None
            if insn.bytes[0] == 0x68 and insn.size == 5 and nxt is not None and nxt.bytes[0] == 0xE8:
                target = int(nxt.op_str, 16) - base
                vm_section = next((i for i, s in enumerate(sections) if s.rva <= target < s.rva + s.vsize), None)
                return mnemonics, vm_section
            if insn.bytes[0] in (0xE9, 0xEB):
                rva = int(insn.op_str, 16) - base
                jumped = True
                break
            if insn.mnemonic in ("ret", "int3") or (insn.bytes[0] == 0xFF and insn.mnemonic in ("jmp", "call")):
                return mnemonics, None
        if not jumped or len(mnemonics) >= 40:
            break
    return mnemonics, None


def _code_verdict(code: SectionFeatures, outer: str | None) -> tuple[bool | None, str]:
    size = min(code.raw_size, code.vsize) if code.vsize else code.raw_size
    coverage = size / max(1, code.vsize or code.raw_size)
    if outer is not None:
        return True, f"original code is inside a {outer} section"
    if code.calls >= 20 or (size < 0x10000 and code.calls >= 3 and coverage >= 0.9 and code.entropy < 6.9):
        return False, f"original code is readable on disk ({code.calls} repeated call targets)"
    if coverage < 0.1:
        return True, f"original code section is mostly absent from the file ({code.raw_size:#x}/{code.vsize:#x})"
    if code.entropy > 7.2:
        return True, f"original code section is compressed (entropy {code.entropy:.2f})"
    if size >= 0x8000 and code.calls < 3:
        return True, f"original code section is encrypted (entropy {code.entropy:.2f}, no call structure)"
    return None, f"small code section ({size:#x} bytes, entropy {code.entropy:.2f}, {code.calls} call targets)"


def identify_packer(data: bytes) -> PackerInfo:
    """
    This function identifies VMProtect, Themida and common outer packers on a PE file, and decides whether the
    original code is packed.
    """
    info = PackerInfo()
    pe = pefile.PE(data=data, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    image_end = base + pe.OPTIONAL_HEADER.SizeOfImage
    for section in pe.sections:
        raw = section.get_data()[
            : max(0, min(section.SizeOfRawData, section.Misc_VirtualSize or section.SizeOfRawData))
        ]
        info.sections.append(
            SectionFeatures(
                section_name(section),
                section.VirtualAddress,
                section.Misc_VirtualSize,
                section.SizeOfRawData,
                section.Characteristics,
                entropy(raw),
                call_target_score(raw, base + section.VirtualAddress, base, image_end) if raw else 0,
            )
        )
    secs = info.sections
    if not secs:
        info.reason = "no sections"
        return info
    names = [s.name for s in secs]
    lowered = [name.strip().lower() for name in names]
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    info.ep_section = next((i for i, s in enumerate(secs) if s.rva <= ep < s.rva + max(s.vsize, s.raw_size)), None)
    info.code_section = next((i for i, s in enumerate(secs) if s.executable), 0)
    epi, code_idx = info.ep_section, info.code_section
    for pattern, packer in _OUTER_PACKERS:
        if epi is not None and pattern.match(names[epi]):
            info.outer_packer = packer
    ep_appended = epi is not None and epi > code_idx and lowered[epi] not in _STD_CODE_NAMES
    ep_exec = epi is not None and secs[epi].executable
    mnemonics, vm_entry = _entry_mnemonics(pe, secs)
    head = mnemonics[:10]

    group = _vmp_section_group(names)
    if (
        group
        and (any(secs[i].characteristics & _CODE_AND_DATA == _CODE_AND_DATA for i in group) or epi in group)
        and not all(secs[i].vsize < 0x1000 for i in group)
    ):
        info.evidence.append("vmp-sections")
    if (
        vm_entry is not None
        and vm_entry != code_idx
        and (epi != code_idx or secs[vm_entry].characteristics & _CODE_AND_DATA == _CODE_AND_DATA)
    ):
        info.evidence.append("vmp-vm-entry")
    if any(
        i > code_idx
        and s.name.endswith("0")
        and s.characteristics & _CODE_AND_DATA == _CODE_AND_DATA
        and s.executable
        and s.vsize >= 0x1000
        for i, s in enumerate(secs)
    ):
        info.evidence.append("vmp-lone-section")
    if ep_appended and ep_exec and ("pushfd" in head or "pushfq" in head) and b"\x50\xf0\x1f\xfd\xfd" in data:
        info.evidence.append("vmp-mutated-entry")
    if not info.evidence and ep_appended and has_packer_info(data):
        info.evidence.append("vmp-packer-info")
    is_vmp = bool(info.evidence)

    themida_named = [i for i, name in enumerate(lowered) if name in _THEMIDA_NAMES and secs[i].vsize >= 0x1000]
    random_named = [i for i, name in enumerate(names) if re.fullmatch(r"[a-z]{8}", name)]
    blank_first = pe.sections[0].Name.replace(b"\0", b" ").strip() == b""
    plain_entry = head[:2] == ["push", "mov"] and epi is not None and secs[epi].calls >= 20
    themida: list[str] = []
    if themida_named and (epi in themida_named or epi in random_named or ep_appended) and not plain_entry:
        themida.append("themida-sections")
    if blank_first and random_named and epi != 0:
        themida.append("themida-2.x-layout")
    if themida and is_vmp and "themida-sections" not in themida and "vmp-sections" not in info.evidence:
        themida = []
    info.evidence += themida

    if themida and is_vmp:
        info.protector = "Themida+VMProtect"
    elif themida:
        info.protector = "Themida"
    elif is_vmp:
        info.protector = "VMProtect"
    elif info.outer_packer is not None:
        info.protector = info.outer_packer

    code = secs[code_idx]
    code_in_outer = next((packer for pattern, packer in _OUTER_PACKERS if pattern.match(code.name)), None)
    if info.outer_packer is not None and epi is not None and secs[epi].calls >= 20:
        info.packed, info.reason = False, f"code in the {info.outer_packer}-named entry section is readable"
    elif info.outer_packer is not None:
        info.packed, info.reason = True, f"{info.outer_packer} is the outermost layer"
    elif info.protector is None:
        packed, reason = _code_verdict(code, None)
        info.packed = packed if packed is False or (epi is not None and epi != code_idx) else None
        info.reason = reason
    else:
        info.packed, info.reason = _code_verdict(code, code_in_outer)
        if info.packed is None and is_vmp and not themida:
            size = min(code.raw_size, code.vsize)
            if size >= 0.7 * code.vsize and code.entropy < 6.9:
                info.packed, info.reason = False, "small original code section is fully on disk"
    return info


class PackerIdentifier(Analysis):
    """
    This analysis identifies the protector of the main PE object, which is VMProtect, Themida, WinLicense or a common
    compressor. The analysis also reports whether the original code is packed.
    The analysis only uses static features of the sections and the entry point.
    """

    def __init__(self):
        binary = self.project.loader.main_object.binary
        if binary is None:
            raise ValueError("PackerIdentifier requires a file-backed main object")
        with open(binary, "rb") as f:
            self.info = identify_packer(f.read())
        self.protector = self.info.protector
        self.packed = self.info.packed


AnalysesHub.register_default("PackerIdentifier", PackerIdentifier)
