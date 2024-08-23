from __future__ import annotations
from collections.abc import Iterable

from . import MemoryMixin


class LabelMergerMixin(MemoryMixin):
    """
    A memory mixin for merging labels. Labels come from SimLabeledMemoryObject.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _merge_labels(self, labels: Iterable[dict], **kwargs) -> dict | None:
        new_label = {}
        all_keys = set()
        for label in labels:
            all_keys.update(label.keys())
        for key in all_keys:
            v = ...
            for label in labels:
                if v is ...:
                    v = label.get(key)
                elif v != label.get(key):
                    v = None
            new_label[key] = v
        return new_label

    def copy(self, memo=None):
        return super().copy(memo)
