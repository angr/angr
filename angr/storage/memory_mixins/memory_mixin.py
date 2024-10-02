from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import claripy

from angr.errors import SimMemoryError
from angr.state_plugins.plugin import SimStatePlugin


class MemoryMixin(SimStatePlugin):
    """
    Base class for memory mixins. In angr, all memory objects are made by
    subclassing one or more MemoryMixins, each adding some functionality to the
    memory object.
    """

    SUPPORTS_CONCRETE_LOAD = False

    def __init__(self, memory_id=None, endness="Iend_BE"):
        super().__init__()
        self.id = memory_id
        self.endness = endness

    def copy(self, memo):  # pylint:disable=unused-argument
        o = type(self).__new__(type(self))
        o.id = self.id
        o.endness = self.endness
        return o

    @property
    def category(self):
        """
        Return the category of this SimMemory instance. It can be one of the three following categories: reg, mem,
        or file.
        """

        if self.id in ("reg", "mem"):
            return self.id

        if self.id.startswith("file"):
            return "file"

        if "_" in self.id:
            return self.id.split("_")[0]

        raise SimMemoryError(f'Unknown SimMemory category for memory_id "{self.id}"')

    @property
    def variable_key_prefix(self):
        s = self.category
        if s == "file":
            return (s, self.id)
        return (s,)

    def find(self, addr, data, max_search, **kwargs):
        pass

    def _add_constraints(self, c, add_constraints=True, condition=None, **kwargs):  # pylint:disable=unused-argument
        if add_constraints:
            to_add = c & condition | ~condition if condition is not None else c
            self.state.add_constraints(to_add)

    def load(self, addr, size=None, **kwargs):
        pass

    def store(self, addr, data, **kwargs):
        pass

    def merge(self, others, merge_conditions, common_ancestor=None) -> bool:
        pass

    def compare(self, other) -> bool:
        pass

    def widen(self, others):
        pass

    def permissions(self, addr, permissions=None, **kwargs):
        pass

    def map_region(self, addr, length, permissions, init_zero=False, **kwargs):
        pass

    def unmap_region(self, addr, length, **kwargs):
        pass

    # Optional interface:
    def concrete_load(self, addr, size, writing=False, **kwargs) -> memoryview:
        """
        Set SUPPORTS_CONCRETE_LOAD to True and implement concrete_load if reading concrete bytes is faster in this
        memory model.

        :param addr:    The address to load from.
        :param size:    Size of the memory read.
        :param writing:
        :return:        A memoryview into the loaded bytes.
        """
        raise NotImplementedError

    def erase(self, addr, size=None, **kwargs) -> None:
        """
        Set [addr:addr+size) to uninitialized. In many cases this will be faster than overwriting those locations with
        new values. This is commonly used during static data flow analysis.

        :param addr:    The address to start erasing.
        :param size:    The number of bytes for erasing.
        :return:        None
        """
        raise NotImplementedError

    def _default_value(  # pylint:disable=too-many-positional-arguments
        self, addr, size, name=None, inspect=True, events=True, key=None, **kwargs
    ):
        """
        Override this method to provide default values for a variety of edge cases and base cases.

        :param addr:    If this value is being filled to provide a default memory value, this will be its address.
                        Otherwise, None.
        :param size:    The size in bytes of the value to return
        :param name:    A descriptive identifier for the value, for if a symbol is created.

        The ``inspect``, ``events``, and ``key`` parameters are for ``state.solver.Unconstrained``, if it is used.
        """

    def _merge_values(self, values: Iterable[tuple[Any, Any]], merged_size: int, **kwargs) -> Any | None:
        """
        Override this method to provide value merging support.

        :param values:          A collection of values with their merge conditions.
        :param merged_size:     The size (in bytes) of the merged value.
        :return:                The merged value, or None to skip merging of the current value.
        """
        raise NotImplementedError

    def _merge_labels(self, labels: Iterable[dict], **kwargs) -> dict | None:
        """
        Override this method to provide label merging support.

        :param labels:          A collection of labels.
        :return:                The merged label, or None to skip merging of the current label.
        """
        raise NotImplementedError

    def replace_all(self, old: claripy.ast.BV, new: claripy.ast.BV):
        raise NotImplementedError

    def _replace_all(self, addrs: Iterable[int], old: claripy.ast.BV, new: claripy.ast.BV):
        raise NotImplementedError

    def copy_contents(self, dst, src, size, condition=None, **kwargs):
        """
        Override this method to provide faster copying of large chunks of data.

        :param dst:     The destination of copying.
        :param src:     The source of copying.
        :param size:    The size of copying.
        :param condition:   The storing condition.
        :param kwargs:      Other parameters.
        :return:        None
        """
        raise NotImplementedError
