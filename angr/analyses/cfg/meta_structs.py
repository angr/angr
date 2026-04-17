from __future__ import annotations

import logging

import cle
from cle.backends import PE
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

    return merged_array_hints
