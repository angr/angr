# pylint:disable=missing-class-docstring
from __future__ import annotations
from typing import Any
from collections.abc import Iterable, Callable

from . import MemoryMixin


class MultiValueMergerMixin(MemoryMixin):
    def __init__(
        self,
        *args,
        element_limit=5,
        annotation_limit=256,
        top_func=None,
        is_top_func=None,
        phi_maker=None,
        merge_into_top=True,
        **kwargs,
    ):
        self._element_limit = element_limit
        self._annotation_limit = annotation_limit
        self._top_func: Callable = top_func
        self._is_top_func: Callable = is_top_func
        self._phi_maker: Callable | None = phi_maker
        self._merge_into_top = merge_into_top

        super().__init__(*args, **kwargs)

    def _merge_values(self, values: Iterable[tuple[Any, Any]], merged_size: int, **kwargs):
        values_set = {v for v, _ in values}
        if self._phi_maker is not None:
            phi_var = self._phi_maker(values_set)
            if phi_var is not None:
                return {phi_var}

        # try to merge it in the traditional way
        has_top = self._merge_into_top and any(self._is_top_func(v) for v in values_set)
        if has_top or len(values_set) > self._element_limit:
            if has_top:
                ret_val = self._top_func(merged_size * self.state.arch.byte_width)
            else:
                # strip annotations from each value and see how many raw values there are in total
                # We have to use cache_key to determine uniqueness here, because if __hash__ collides,
                # python implicitly calls __eq__ to determine if the two objects are actually the same
                # and that just results in a new AST for a BV. Python then tries to convert that AST to a bool
                # which fails with the safeguard in claripy.ast.bool.Bool.__bool__.
                stripped_values_set = {v.clear_annotations().cache_key for v in values_set}
                if len(stripped_values_set) > 1:
                    ret_val = self._top_func(merged_size * self.state.arch.byte_width)
                else:
                    # Get the AST back from the cache_key
                    ret_val = next(iter(stripped_values_set)).ast

            # migrate annotations
            annotations = []
            annotations_set = set()
            for v in values_set:
                for anno in v.annotations:
                    if anno not in annotations_set:
                        annotations.append(anno)
                        annotations_set.add(anno)
            if annotations:
                annotations = sorted(annotations, key=str)
                ret_val = ret_val.annotate(*annotations[: self._annotation_limit])
            merged_val = {ret_val}
        else:
            merged_val = values_set
        return merged_val

    def copy(self, memo=None):
        copied = super().copy(memo)
        copied._element_limit = self._element_limit
        copied._annotation_limit = self._annotation_limit
        copied._top_func = self._top_func
        copied._is_top_func = self._is_top_func
        copied._phi_maker = self._phi_maker
        copied._merge_into_top = self._merge_into_top
        return copied
