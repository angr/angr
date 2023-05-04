from typing import Iterable, Tuple, Any, Callable, Optional

from . import MemoryMixin


class MultiValueMergerMixin(MemoryMixin):
    def __init__(self, *args, element_limit=5, top_func=None, phi_maker=None, **kwargs):
        self._element_limit = element_limit
        self._top_func: Callable = top_func
        self._phi_maker: Optional[Callable] = phi_maker

        super().__init__(*args, **kwargs)

    def _merge_values(self, values: Iterable[Tuple[Any, Any]], merged_size: int, **kwargs):
        values_set = {v for v, _ in values}
        if self._phi_maker is not None:
            phi_var = self._phi_maker(values_set)
            if phi_var is not None:
                return {phi_var}

        # try to merge it in the traditional way
        if len(values_set) > self._element_limit:
            # strip annotations from each value and see how many raw values there are in total
            stripped_values_set = {v._apply_to_annotations(lambda alist: None) for v in values_set}
            if len(stripped_values_set) > 1:
                ret_val = self._top_func(merged_size * self.state.arch.byte_width)
            else:
                ret_val = next(iter(stripped_values_set))
            # migrate annotations
            annotations = []
            for v in values_set:
                annotations += list(v.annotations)
            if annotations:
                ret_val = ret_val.annotate(*annotations)
            merged_val = {ret_val}
        else:
            merged_val = values_set
        return merged_val

    def copy(self, memo=None):
        copied = super().copy(memo)
        copied._element_limit = self._element_limit
        copied._top_func = self._top_func
        copied._phi_maker = self._phi_maker
        return copied
