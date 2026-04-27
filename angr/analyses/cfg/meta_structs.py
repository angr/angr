from __future__ import annotations

import logging

import cle
from cle.backends import PE
from cle.backends.pe.relocation.generic import IMAGE_REL_BASED_ABSOLUTE
from cle.structs import DataDirectory, MemRegion, MemRegionSort

from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort

log = logging.getLogger(name=__name__)

# Mapping from MemRegionSort to the MemoryDataSort used in CFGFast's _seg_list and memory_data
_SORT_MAP: dict[MemRegionSort, str | None] = {
    MemRegionSort.IAT: MemoryDataSort.PointerArray,
    MemRegionSort.ILT: MemoryDataSort.PointerArray,
    MemRegionSort.EXPORT_ADDR_TABLE: MemoryDataSort.PointerArray,
    MemRegionSort.EXPORT_NAME_TABLE: MemoryDataSort.PointerArray,
    MemRegionSort.EXPORT_ORDINAL_TABLE: MemoryDataSort.Integer,
    MemRegionSort.EXPORT_DIRECTORY: MemoryDataSort.PEExportDirectory,
    MemRegionSort.IMPORT_DIRECTORY: MemoryDataSort.PEImportDirectory,
    MemRegionSort.IMPORT_HINT_NAME_TABLE: MemoryDataSort.String,
    MemRegionSort.DELAY_IMPORT_DIRECTORY: MemoryDataSort.PEDelayImportDirectory,
    MemRegionSort.STRING_BLOB: MemoryDataSort.String,
    MemRegionSort.POINTER_ARRAY: MemoryDataSort.PointerArray,
    MemRegionSort.STRUCT_ARRAY: MemoryDataSort.Unknown,
    MemRegionSort.DATA: MemoryDataSort.Unknown,
}


def _flatten_regions(regions: list[MemRegion]) -> list[MemRegion]:
    """Flatten DataDirectory regions into their sub-regions."""
    result = []
    for region in regions:
        if isinstance(region, DataDirectory) and region.sub_regions:
            result.extend(region.flat_regions())
        else:
            result.append(region)
    return result


def get_data_regions_from_meta_regions(loader: cle.Loader) -> list[tuple[int, int, str | None]]:
    """
    Extract (addr, size, sort) tuples for all metadata data regions across all loaded objects.

    Flattens DataDirectory sub-regions so each entry maps to a contiguous memory range
    suitable for marking in CFGFast's _seg_list.
    """
    result = []
    for obj in loader.all_objects:
        if not hasattr(obj, "meta_regions") or not obj.meta_regions:
            continue

        flat = _flatten_regions(obj.meta_regions)
        for region in flat:
            sort = _SORT_MAP.get(region.sort, MemoryDataSort.Unknown)
            if region.size > 0:
                result.append((region.vaddr, region.size, sort))

    return result


def get_function_hints_from_meta_regions(loader: cle.Loader) -> list[tuple[int, str | None]]:
    """
    Extract (addr, name) pairs for functions discovered from metadata.

    Uses meta_function_hints populated by backends (e.g., PE export table entries).
    """
    result = []
    for obj in loader.all_objects:
        if hasattr(obj, "meta_function_hints") and obj.meta_function_hints:
            result.extend(obj.meta_function_hints)
    return result


def get_pointer_array_hints(loader: cle.Loader) -> list[tuple[int, int]]:
    """
    Extract pointer array hints and return tuples of (addr, byte count) for each pointer array.
    """
    ptr_array_hints = []
    for obj in loader.all_objects:
        if isinstance(obj, PE):
            ptr_array_hints += get_pointer_array_hints_pe(obj)
    return ptr_array_hints


def get_pointer_array_hints_pe(pe: PE) -> list[tuple[int, int]]:
    """
    Extract pointer array hints from a PE object and return tuples of (addr, byte count) for each pointer array.
    """
    ptr_array_hints = []
    ptr_size = pe.arch.bytes
    mapped_base = pe.mapped_base

    for reloc in pe.relocs:
        if type(reloc) is IMAGE_REL_BASED_ABSOLUTE:
            continue
        ptr_array_hints.append((mapped_base + reloc.relative_addr, ptr_size))

    # merge them
    merged_array_hints = []
    for addr, size in sorted(ptr_array_hints):
        if not merged_array_hints:
            merged_array_hints.append((addr, size))
        else:
            last_addr, last_size = merged_array_hints[-1]
            if last_addr + last_size == addr:
                # merge with the previous one
                merged_array_hints[-1] = (last_addr, last_size + size)
            else:
                merged_array_hints.append((addr, size))

    # filter them
    if pe.arch.name == "X86":
        # we do not want to mark bytes that are within instructions as pointer arrays. as a result, we check if the
        # pointer of each consecutive array hints is *likely* forming an instruction
        for i in range(len(merged_array_hints) - 1):
            ptr_addr, ptr_size = merged_array_hints[i]
            if ptr_addr - 3 >= pe.mapped_base:
                prefix = pe.memory.load(ptr_addr - pe.mapped_base - 3, 3)  # load three bytes before the pointer
                if prefix.startswith(b"\xff\x24"):
                    # jmp dword ptr [addr + eax]
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                if prefix[1:] in {b"\xff\x15", b"\xff\x25"}:
                    # call dword ptr [addr]
                    # jmp dword ptr [addr]
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                if prefix[0] == 0xC7 and prefix[1] in {0x04, 0x45}:
                    # 0x04: mov dword ptr [eax], imm32
                    # 0x45: mov dword ptr [ebp - imm], imm32
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                if prefix[1] == 0xC7:
                    if prefix[2] in {0x01, 0x02, 0x03, 0x06, 0x07}:
                        # 0x01: mov dword ptr [ecx], imm32
                        # 0x02: mov dword ptr [edx], imm32
                        # 0x03: mov dword ptr [ebx], imm32
                        # 0x06: mov dword ptr [esi], imm32
                        # 0x07: mov dword ptr [edi], imm32
                        merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                        continue
                    if prefix[2] in {0x05, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87}:
                        # 0x05: mov dword ptr [addr], imm32
                        # 0x80-0x87: mov dword ptr [addr + reg], imm32
                        if ptr_size > 4:
                            merged_array_hints[i] = ptr_addr + 8, ptr_size - 8
                        else:
                            merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                        continue
                elif prefix[1] == 0x88 and prefix[2] in {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}:
                    # mov byte ptr [addr], {al, cl, dl, bl, ah, ch, dh, bh}
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0x89 and prefix[2] in {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}:
                    # mov [addr], {eax, ecx, edx, ebx, esp, ebp, esi, edi}
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0x89 and 0x80 <= prefix[2] <= 0xBF:
                    # mov [addr + reg], {eax, ecx, edx, ebx, esp, ebp, esi, edi}
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0x39 and prefix[2] in {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}:
                    # cmp [addr], {eax, ecx, edx, ebx, esp, ebp, esi, edi}
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif (prefix[1] == 0x3B and prefix[2] in {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}) or (
                    prefix[1] == 0x80 and prefix[2] in {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
                ):
                    # cmp {eax, ecx, edx, ebx, esp, ebp, esi, edi}, [addr]
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0x81 and prefix[2] == 0xFE:
                    # cmp esi, [addr]
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0x8A and prefix[2] in {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}:
                    # mov {al, cl, dl, bl, ah, ch, dh, bh}, [addr]
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0x8B and prefix[2] in {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}:
                    # mov {eax, ecx, edx, ebx, esp, ebp, esi, edi}, [addr]
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0xFF and prefix[2] == 0x35:
                    # push dword ptr [addr]
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif 0xB8 <= prefix[-1] <= 0xBF:
                    # mov {ecx, ...}, addr
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0x03 and prefix[2] in {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}:
                    # add {eax, ecx, edx, ebx, esp, ebp, esi, edi}, [addr]
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[-1] in {0x05, 0x68, 0xA1, 0xA3}:
                    # 0x05: add eax, imm32
                    # 0x68: push addr
                    # 0xa1: mov eax, addr
                    # 0xa3: mov [addr], eax
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0x81 and 0xC0 <= prefix[2] <= 0xC7:
                    # add {eax, ecx, edx, ebx, esp, ebp, esi, edi}, addr
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[1] == 0x83 and prefix[2] in {0x0D, 0x25, 0x3D}:
                    # 0x0d: or [addr], imm8
                    # 0x25: and [addr], imm8
                    # 0x3d: cmp [addr], imm8
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
                elif prefix[-1] in {0xA0, 0xA2}:
                    # 0xa0: mov al, [addr]
                    # 0xa2: mov [addr], al
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
            if ptr_addr - 7 >= pe.mapped_base:
                prefix = pe.memory.load(ptr_addr - pe.mapped_base - 7, 3)
                if prefix[0] == 0xC7 and prefix[1] in {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87}:
                    # 0x80-0x87: mov dword ptr [addr + reg], imm32
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue
            if ptr_addr - 6 >= pe.mapped_base:
                prefix = pe.memory.load(ptr_addr - pe.mapped_base - 6, 2)
                if prefix[0] == 0xC7 and prefix[1] in {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87}:
                    # 0x80-0x87: mov dword ptr [reg - imm], imm32
                    merged_array_hints[i] = ptr_addr + 4, ptr_size - 4
                    continue

        merged_array_hints = [hint for hint in merged_array_hints if hint[1] > 0]

    return merged_array_hints
