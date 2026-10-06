from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from angr import claripy
from angr.claripy.annotation import StridedIntervalAnnotation, UninitializedAnnotation
from angr.storage.memory_mixins.memory_mixin import MemoryMixin

l = logging.getLogger(name=__name__)


class AbstractMergerMixin(MemoryMixin):
    """AbstractMergerMixin handles merging initialized values."""

    # splitting a strided interval into bytes loses its value and its name (replace_all cannot find the pieces)
    MERGE_WHOLE_OBJECTS = True

    def _merge_values(self, values: Iterable[tuple[Any, Any]], merged_size: int, is_widening: bool = False, **kwargs):
        values = list(values)
        ours = values[0][0]

        # a never-written default value is dropped in favor of values from other paths. Only a bare BVS qualifies:
        # the annotation propagates through every operation, so derived values must still take part in the merge
        initialized = [v for v, _ in values if not self._is_raw_uninitialized(v)]
        if not initialized:
            return None

        merged_val = initialized[0]
        for tm in initialized[1:]:
            l.info("Merging %s %s...", merged_val, tm)
            merged_val = merged_val.widen(tm) if is_widening else merged_val.union(tm)
            l.info("... Merged to %s", merged_val)

        if not self._is_raw_uninitialized(ours) and claripy.vsa.identical(merged_val, ours):
            return None

        return self._canonicalize(merged_val)

    @staticmethod
    def _is_raw_uninitialized(v) -> bool:
        return v.op == "BVS" and v.has_annotation_type(UninitializedAnnotation)

    @staticmethod
    def _canonicalize(v):
        """
        Collapse a Union/Widen tree into a fresh, uniquely named strided interval. Keeping the tree would let values
        grow without bound across loop iterations, and an unnamed tree cannot be located by replace_all(). A fresh name
        (rather than the value-derived name simplify() picks) keeps equal intervals in different slots distinct.
        """

        simplified = claripy.vsa.simplify(v)
        if simplified.op == "BVV":
            return simplified
        si_anno = simplified.get_annotation(StridedIntervalAnnotation)
        if si_anno is None:
            return v
        extra_annotations = [
            a for a in v.annotations if not isinstance(a, StridedIntervalAnnotation | UninitializedAnnotation)
        ]
        return claripy.BVS("merged", len(v)).annotate(si_anno, *extra_annotations)
