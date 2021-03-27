from typing import Iterable, Tuple, Any, Callable

from . import MemoryMixin


class MultiValueMergerMixin(MemoryMixin):
    def __init__(self, *args, element_limit=5, top_func=None, **kwargs):
        self._element_limit = element_limit
        self._top_func: Callable = top_func

        super().__init__(*args, **kwargs)

    def _merge_values(self, values: Iterable[Tuple[Any,Any]], merged_size: int):
        values_set = set(v for v, _ in values)
        if len(values_set) > self._element_limit:
            merged_val = { self._top_func(merged_size * self.state.arch.byte_width) }
        else:
            merged_val = values_set
        return merged_val

    def copy(self, memo=None):
        copied = super().copy(memo)
        copied._element_limit = self._element_limit
        copied._top_func = self._top_func
        return copied
