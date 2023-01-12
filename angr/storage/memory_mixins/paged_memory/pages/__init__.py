import typing

from angr.storage.memory_mixins import MemoryMixin
from .cooperation import CooperationBase, MemoryObjectMixin
from .ispo_mixin import ISPOMixin
from .refcount_mixin import RefcountMixin
from .permissions_mixin import PermissionsMixin
from .history_tracking_mixin import HistoryTrackingMixin


class PageBase(HistoryTrackingMixin, RefcountMixin, CooperationBase, ISPOMixin, PermissionsMixin, MemoryMixin):
    """
    This is a fairly succinct definition of the contract between PagedMemoryMixin and its constituent pages:

    - Pages must implement the MemoryMixin model for loads, stores, copying, merging, etc
    - However, loading/storing may not necessarily use the same data domain as PagedMemoryMixin. In order to do more
      efficient loads/stores across pages, we use the CooperationBase interface which allows the page class to
      determine how to generate and unwrap the objects which are actually stored.
    - To support COW, we use the RefcountMixin and the ISPOMixin (which adds the contract element that ``memory=self``
      be passed to every method call)
    - Pages have permissions associated with them, stored in the PermissionsMixin.

    Read the docstrings for each of the constituent classes to understand the nuances of their functionalities
    """

    pass


PageType = typing.TypeVar("PageType", bound=PageBase)

from .list_page import ListPage
from .mv_list_page import MVListPage
from .ultra_page import UltraPage
