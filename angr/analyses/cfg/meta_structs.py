from __future__ import annotations

import logging

import cle
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
