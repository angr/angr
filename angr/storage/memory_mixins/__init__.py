from __future__ import annotations

from angr.sim_state import SimState
from .actions_mixin import ActionsMixinHigh, ActionsMixinLow
from .address_concretization_mixin import AddressConcretizationMixin
from .bvv_conversion_mixin import DataNormalizationMixin
from .clouseau_mixin import InspectMixinHigh
from .conditional_store_mixin import ConditionalMixin
from .convenient_mappings_mixin import ConvenientMappingsMixin
from .default_filler_mixin import DefaultFillerMixin, SpecialFillerMixin, ExplicitFillerMixin
from .dirty_addrs_mixin import DirtyAddrsMixin
from .hex_dumper_mixin import HexDumperMixin
from .label_merger_mixin import LabelMergerMixin
from .multi_value_merger_mixin import MultiValueMergerMixin
from .name_resolution_mixin import NameResolutionMixin
from .simplification_mixin import SimplificationMixin
from .simple_interface_mixin import SimpleInterfaceMixin
from .size_resolution_mixin import SizeNormalizationMixin, SizeConcretizationMixin
from .smart_find_mixin import SmartFindMixin
from .symbolic_merger_mixin import SymbolicMergerMixin
from .top_merger_mixin import TopMergerMixin
from .underconstrained_mixin import UnderconstrainedMixin
from .unwrapper_mixin import UnwrapperMixin

from .paged_memory.page_backer_mixins import ClemoryBackerMixin, ConcreteBackerMixin, DictBackerMixin
from .paged_memory.paged_memory_mixin import (
    PagedMemoryMixin,
    ListPagesMixin,
    UltraPagesMixin,
    ListPagesWithLabelsMixin,
    MVListPagesMixin,
    MVListPagesWithLabelsMixin,
)
from .paged_memory.privileged_mixin import PrivilegedPagingMixin
from .paged_memory.stack_allocation_mixin import StackAllocationMixin
from .paged_memory.paged_memory_multivalue_mixin import PagedMemoryMultiValueMixin
from .paged_memory.pages import (
    CooperationBase,
    MemoryObjectMixin,
    ISPOMixin,
    RefcountMixin,
    PermissionsMixin,
    HistoryTrackingMixin,
    PageBase,
    PageType,
    ListPage,
    MVListPage,
    UltraPage,
)

from .slotted_memory import SlottedMemoryMixin
from .regioned_memory import (
    RegionedMemoryMixin,
    RegionCategoryMixin,
    StaticFindMixin,
    AbstractMergerMixin,
    MemoryRegionMetaMixin,
    RegionedAddressConcretizationMixin,
)
from .keyvalue_memory_mixin import KeyValueMemoryMixin
from .javavm_memory_mixin import JavaVmMemoryMixin

# pylint:disable=missing-class-docstring


class DefaultMemory(
    HexDumperMixin,
    SmartFindMixin,
    UnwrapperMixin,
    NameResolutionMixin,
    DataNormalizationMixin,
    SimplificationMixin,
    InspectMixinHigh,
    ActionsMixinHigh,
    UnderconstrainedMixin,
    SizeConcretizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    # InspectMixinLow,
    ActionsMixinLow,
    ConditionalMixin,
    ConvenientMappingsMixin,
    DirtyAddrsMixin,
    # -----
    StackAllocationMixin,
    ConcreteBackerMixin,
    ClemoryBackerMixin,
    DictBackerMixin,
    PrivilegedPagingMixin,
    UltraPagesMixin,
    DefaultFillerMixin,
    SymbolicMergerMixin,
    PagedMemoryMixin,
):
    pass


class DefaultListPagesMemory(
    HexDumperMixin,
    SmartFindMixin,
    UnwrapperMixin,
    NameResolutionMixin,
    DataNormalizationMixin,
    SimplificationMixin,
    ActionsMixinHigh,
    UnderconstrainedMixin,
    SizeConcretizationMixin,
    SizeNormalizationMixin,
    InspectMixinHigh,
    AddressConcretizationMixin,
    # InspectMixinLow,
    ActionsMixinLow,
    ConditionalMixin,
    ConvenientMappingsMixin,
    DirtyAddrsMixin,
    # -----
    StackAllocationMixin,
    ClemoryBackerMixin,
    DictBackerMixin,
    PrivilegedPagingMixin,
    ListPagesMixin,
    DefaultFillerMixin,
    SymbolicMergerMixin,
    PagedMemoryMixin,
):
    pass


class FastMemory(
    NameResolutionMixin,
    SimpleInterfaceMixin,
    SimplificationMixin,
    InspectMixinHigh,
    ConditionalMixin,
    ExplicitFillerMixin,
    DefaultFillerMixin,
    SlottedMemoryMixin,
):
    pass


class AbstractMemory(
    UnwrapperMixin,
    NameResolutionMixin,
    DataNormalizationMixin,
    SimplificationMixin,
    InspectMixinHigh,
    ActionsMixinHigh,
    UnderconstrainedMixin,
    SizeConcretizationMixin,
    SizeNormalizationMixin,
    # InspectMixinLow,
    ActionsMixinLow,
    ConditionalMixin,
    RegionedAddressConcretizationMixin,
    # -----
    RegionedMemoryMixin,
):
    pass


class RegionedMemory(
    RegionCategoryMixin,
    MemoryRegionMetaMixin,
    StaticFindMixin,
    UnwrapperMixin,
    NameResolutionMixin,
    DataNormalizationMixin,
    SimplificationMixin,
    SizeConcretizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    ConvenientMappingsMixin,
    DirtyAddrsMixin,
    # -----
    ClemoryBackerMixin,
    DictBackerMixin,
    UltraPagesMixin,
    DefaultFillerMixin,
    AbstractMergerMixin,
    PagedMemoryMixin,
):
    pass


class LabeledMemory(
    SizeNormalizationMixin,
    ListPagesWithLabelsMixin,
    DefaultFillerMixin,
    TopMergerMixin,
    LabelMergerMixin,
    PagedMemoryMixin,
):
    """
    LabeledMemory is used in static analysis. It allows storing values with labels, such as `Definition`.
    """

    def _default_value(self, addr, size, **kwargs):  # pylint:disable=arguments-differ
        # TODO: Make _default_value() a separate Mixin

        if kwargs.get("name", "").startswith("merge_uc_"):
            # this is a hack. when this condition is satisfied, _default_value() is called inside Listpage.merge() to
            # create temporary values. we simply return a TOP value here.
            return self.state.top(size * self.state.arch.byte_width)

        # we never fill default values for non-existent loads
        kwargs["fill_missing"] = False
        return super()._default_value(addr, size, **kwargs)


class MultiValuedMemory(
    SizeNormalizationMixin,
    MVListPagesMixin,
    DefaultFillerMixin,
    MultiValueMergerMixin,
    PagedMemoryMixin,
    PagedMemoryMultiValueMixin,
):
    def _default_value(self, addr, size, **kwargs):  # pylint:disable=arguments-differ
        # TODO: Make _default_value() a separate Mixin

        if kwargs.get("name", "").startswith("merge_uc_"):
            # this is a hack. when this condition is satisfied, _default_value() is called inside Listpage.merge() to
            # create temporary values. we simply return a TOP value here.
            return self.state.top(size * self.state.arch.byte_width)

        # we never fill default values for non-existent loads
        kwargs["fill_missing"] = False
        return super()._default_value(addr, size, **kwargs)


class KeyValueMemory(
    KeyValueMemoryMixin,
):
    pass


class JavaVmMemory(
    JavaVmMemoryMixin,
):
    pass


SimState.register_default("sym_memory", DefaultMemory)
SimState.register_default("fast_memory", FastMemory)
SimState.register_default("abs_memory", AbstractMemory)
SimState.register_default("keyvalue_memory", KeyValueMemory)
SimState.register_default("javavm_memory", JavaVmMemory)


__all__ = (
    "AbstractMemory",
    "AbstractMergerMixin",
    "ActionsMixinHigh",
    "ActionsMixinLow",
    "AddressConcretizationMixin",
    "ClemoryBackerMixin",
    "ConcreteBackerMixin",
    "ConditionalMixin",
    "ConvenientMappingsMixin",
    "CooperationBase",
    "DataNormalizationMixin",
    "DefaultFillerMixin",
    "DefaultListPagesMemory",
    "DefaultMemory",
    "DictBackerMixin",
    "DirtyAddrsMixin",
    "ExplicitFillerMixin",
    "FastMemory",
    "HexDumperMixin",
    "HistoryTrackingMixin",
    "ISPOMixin",
    "InspectMixinHigh",
    "JavaVmMemory",
    "JavaVmMemoryMixin",
    "KeyValueMemory",
    "KeyValueMemoryMixin",
    "LabelMergerMixin",
    "LabeledMemory",
    "ListPage",
    "ListPagesMixin",
    "ListPagesWithLabelsMixin",
    "MVListPage",
    "MVListPagesMixin",
    "MVListPagesWithLabelsMixin",
    "MemoryObjectMixin",
    "MemoryRegionMetaMixin",
    "MultiValueMergerMixin",
    "MultiValuedMemory",
    "NameResolutionMixin",
    "PageBase",
    "PageType",
    "PagedMemoryMixin",
    "PagedMemoryMultiValueMixin",
    "PermissionsMixin",
    "PrivilegedPagingMixin",
    "RefcountMixin",
    "RegionCategoryMixin",
    "RegionedAddressConcretizationMixin",
    "RegionedMemory",
    "RegionedMemoryMixin",
    "SimpleInterfaceMixin",
    "SimplificationMixin",
    "SizeConcretizationMixin",
    "SizeNormalizationMixin",
    "SlottedMemoryMixin",
    "SmartFindMixin",
    "SpecialFillerMixin",
    "StackAllocationMixin",
    "StaticFindMixin",
    "SymbolicMergerMixin",
    "TopMergerMixin",
    "UltraPage",
    "UltraPagesMixin",
    "UnderconstrainedMixin",
    "UnwrapperMixin",
)
