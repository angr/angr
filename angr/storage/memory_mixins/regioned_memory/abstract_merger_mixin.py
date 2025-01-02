from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from claripy.annotation import UninitializedAnnotation

from angr.storage.memory_mixins.memory_mixin import MemoryMixin

l = logging.getLogger(name=__name__)


class AbstractMergerMixin(MemoryMixin):
    """AbstractMergerMixin handles merging initialized values."""

    def _merge_values(self, values: Iterable[tuple[Any, Any]], merged_size: int, **kwargs):
        values = list(values)
        merged_val = values[0][0]

        for tm, _ in values[1:]:
            if tm.has_annotation_type(UninitializedAnnotation):
                continue
            l.info("Merging %s %s...", merged_val, tm)
            merged_val = merged_val.union(tm)
            l.info("... Merged to %s", merged_val)

        if not values[0][0].has_annotation_type(UninitializedAnnotation) and merged_val.identical(values[0][0]):
            return None

        return merged_val
