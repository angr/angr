import logging
import weakref
from typing import Union, TYPE_CHECKING

from sortedcontainers import SortedDict

if TYPE_CHECKING:
    from .knowledge_plugins.key_definitions.unknown_size import UnknownSize


l = logging.getLogger(name=__name__)


class StoredObject:

    __slots__ = ('__weakref__', 'start', 'obj', 'size')

    def __init__(self, start, obj, size):
        self.start = start
        self.obj = obj
        self.size: Union['UnknownSize',int] = size

    def __eq__(self, other):
        assert type(other) is StoredObject

        return self.obj == other.obj and self.start == other.start and self.size == other.size

    def __hash__(self):
        return hash((self.start, self.size, self.obj))

    def __repr__(self):
        return "<SO %s@%#x, %s bytes>" % (repr(self.obj), self.start, self.size)

    @property
    def obj_id(self):
        return id(self.obj)


class RegionObject:
    """
    Represents one or more objects occupying one or more bytes in KeyedRegion.
    """

    __slots__ = ('start', 'size', 'stored_objects', '_internal_objects')

    def __init__(self, start, size, objects=None):
        self.start = start
        self.size = size
        self.stored_objects = set() if objects is None else objects

        self._internal_objects = set()
        if self.stored_objects:
            for obj in self.stored_objects:
                self._internal_objects.add(obj.obj)

    def __eq__(self, other):
        return type(other) is RegionObject and self.start == other.start and self.size == other.size and \
               self.stored_objects == other.stored_objects

    def __ne__(self, other):
        return not self == other

    @property
    def is_empty(self):
        return len(self.stored_objects) == 0

    @property
    def end(self):
        return self.start + self.size

    @property
    def internal_objects(self):
        return self._internal_objects

    def includes(self, offset):
        return self.start <= offset < self.start + self.size

    def split(self, split_at):
        assert self.includes(split_at)
        a = RegionObject(self.start, split_at - self.start, self.stored_objects.copy())
        b = RegionObject(split_at, self.start + self.size - split_at, self.stored_objects.copy())

        return a, b

    def add_object(self, obj):
        if obj in self.stored_objects:
            # another StoredObject with the same hash exists, but they may not have the same ID
            # remove the existing StoredObject and replace it with the new one
            self.stored_objects.remove(obj)

        self.stored_objects.add(obj)
        self._internal_objects.add(obj.obj)

    def set_object(self, obj):
        self.stored_objects.clear()
        self._internal_objects.clear()

        self.add_object(obj)

    def copy(self):
        ro = RegionObject(self.start, self.size, objects=self.stored_objects.copy())
        return ro


class KeyedRegion:
    """
    KeyedRegion keeps a mapping between stack offsets and all objects covering that offset. It assumes no variable in
    this region overlap with another variable in this region.

    Registers and function frames can all be viewed as a keyed region.
    """

    __slots__ = ('_storage', '_object_mapping', '_phi_node_contains', '_canonical_size', )

    def __init__(self, tree=None, phi_node_contains=None, canonical_size=8):
        self._storage = SortedDict() if tree is None else tree
        self._object_mapping = weakref.WeakValueDictionary()
        self._phi_node_contains = phi_node_contains
        self._canonical_size: int = canonical_size

    def __getstate__(self):
        return self._storage, dict(self._object_mapping), self._phi_node_contains

    def __setstate__(self, s):
        self._storage, om, self._phi_node_contains = s
        self._object_mapping = weakref.WeakValueDictionary(om)

    def _get_container(self, offset):
        try:
            base_offset = next(self._storage.irange(maximum=offset, reverse=True))
        except StopIteration:
            return offset, None
        else:
            container = self._storage[base_offset]
            if container.includes(offset):
                return base_offset, container
            return offset, None

    def __contains__(self, offset):
        """
        Test if there is at least one variable covering the given offset.

        :param offset:
        :return:
        """

        if type(offset) is not int:
            raise TypeError("KeyedRegion only accepts concrete offsets.")

        return self._get_container(offset)[1] is not None

    def __len__(self):
        return len(self._storage)

    def __iter__(self):
        return iter(self._storage.values())

    def __eq__(self, other):
        if set(self._storage.keys()) != set(other._storage.keys()):
            return False

        for k, v in self._storage.items():
            if v != other._storage[k]:
                return False

        return True

    def copy(self):
        if not self._storage:
            return KeyedRegion(phi_node_contains=self._phi_node_contains, canonical_size=self._canonical_size)

        kr = KeyedRegion(phi_node_contains=self._phi_node_contains, canonical_size=self._canonical_size)
        for key, ro in self._storage.items():
            kr._storage[key] = ro.copy()
        kr._object_mapping = self._object_mapping.copy()
        return kr

    def merge(self, other, replacements=None):
        """
        Merge another KeyedRegion into this KeyedRegion.

        :param KeyedRegion other: The other instance to merge with.
        :return: None
        """

        if self._canonical_size != other._canonical_size:
            raise ValueError("The canonical sizes of two KeyedRegion objects must equal.")

        # TODO: is the current solution not optimal enough?
        for _, item in other._storage.items():  # type: RegionObject
            for so in item.stored_objects:  # type: StoredObject
                if replacements and so.obj in replacements:
                    so = StoredObject(so.start, replacements[so.obj], so.size)
                self._object_mapping[so.obj_id] = so
                self.__store(so, overwrite=False)

        return self

    def merge_to_top(self, other, replacements=None, top=None):
        """
        Merge another KeyedRegion into this KeyedRegion, but mark all variables with different values as TOP.

        :param other:   The other instance to merge with.
        :param replacements:
        :return:        self
        """

        for _, item in other._storage.items():  # type: RegionObject
            for so in item.stored_objects:  # type: StoredObject
                if replacements and so.obj in replacements:
                    so = StoredObject(so.start, replacements[so.obj], so.size)
                self._object_mapping[so.obj_id] = so
                self.__store(so, overwrite=False, merge_to_top=True, top=top)

        return self

    def replace(self, replacements):
        """
        Replace variables with other variables.

        :param dict replacements:   A dict of variable replacements.
        :return:                    self
        """

        for old_var, new_var in replacements.items():
            old_var_id = id(old_var)
            if old_var_id in self._object_mapping:
                # FIXME: we need to check if old_var still exists in the storage
                old_so = self._object_mapping[old_var_id]  # type: StoredObject
                self._store(old_so.start, new_var, old_so.size, overwrite=True)

        return self

    def dbg_repr(self):
        """
        Get a debugging representation of this keyed region.
        :return: A string of debugging output.
        """
        keys = self._storage.keys()
        offset_to_vars = { }

        for key in sorted(keys):
            ro = self._storage[key]
            variables = [ obj.obj for obj in ro.stored_objects ]
            offset_to_vars[key] = variables

        s = [ ]
        for offset, variables in offset_to_vars.items():
            s.append("Offset %#x: %s" % (offset, variables))
        return "\n".join(s)

    def add_variable(self, start, variable):
        """
        Add a variable to this region at the given offset.

        :param int start:
        :param SimVariable variable:
        :return: None
        """

        size = variable.size if variable.size is not None else 1

        self.add_object(start, variable, size)

    def add_object(self, start, obj, object_size):
        """
        Add/Store an object to this region at the given offset.

        :param start:
        :param obj:
        :param int object_size: Size of the object
        :return:
        """

        self._store(start, obj, object_size, overwrite=False)

    def set_variable(self, start, variable):
        """
        Add a variable to this region at the given offset, and remove all other variables that are fully covered by
        this variable.

        :param int start:
        :param SimVariable variable:
        :return: None
        """

        size = variable.size if variable.size is not None else 1

        self.set_object(start, variable, size)

    def set_object(self, start, obj, object_size):
        """
        Add an object to this region at the given offset, and remove all other objects that are fully covered by this
        object.

        :param start:
        :param obj:
        :param object_size:
        :return:
        """

        self._store(start, obj, object_size, overwrite=True)

    def get_base_addr(self, addr):
        """
        Get the base offset (the key we are using to index objects covering the given offset) of a specific offset.

        :param int addr:
        :return:
        :rtype:  int or None
        """

        base_addr, container = self._get_container(addr)
        if container is None:
            return None
        else:
            return base_addr

    def get_variables_by_offset(self, start):
        """
        Find variables covering the given region offset.

        :param int start:
        :return: A set of variables.
        :rtype:  set
        """

        _, container = self._get_container(start)
        if container is None:
            return set()
        else:
            return container.internal_objects

    def get_objects_by_offset(self, start):
        """
        Find objects covering the given region offset.

        :param start:
        :return:
        """

        _, container = self._get_container(start)
        if container is None:
            return set()
        else:
            return container.internal_objects

    def get_all_variables(self):
        """
        Get all variables covering the current region.

        :return:    A set of all variables.
        """
        variables = set()
        for ro in self._storage.values():
            ro: RegionObject
            variables |= ro.internal_objects
        return variables

    #
    # Private methods
    #

    def _canonicalize_size(self, size: Union[int,'UnknownSize']) -> int:

        # delayed import
        from .knowledge_plugins.key_definitions.unknown_size import UnknownSize  # pylint:disable=import-outside-toplevel

        if isinstance(size, UnknownSize):
            return self._canonical_size
        return size

    def _store(self, start, obj, size, overwrite=False):
        """
        Store a variable into the storage.

        :param int start: The beginning address of the variable.
        :param obj: The object to store.
        :param int size: Size of the object to store.
        :param bool overwrite: Whether existing objects should be overwritten or not.
        :return: None
        """

        stored_object = StoredObject(start, obj, size)
        self._object_mapping[stored_object.obj_id] = stored_object
        self.__store(stored_object, overwrite=overwrite)

    def __store(self, stored_object, overwrite=False, merge_to_top=False, top=None):
        """
        Store a variable into the storage.

        :param StoredObject stored_object: The descriptor describing start address and the variable.
        :param bool overwrite:  Whether existing objects should be overwritten or not. True to make a strong update,
                                False to make a weak update.
        :return: None
        """

        start = stored_object.start
        object_size = self._canonicalize_size(stored_object.size)
        end: int = start + object_size

        # region items in the middle
        overlapping_items = list(self._storage.irange(start, end-1))

        # is there a region item that begins before the start and overlaps with this variable?
        floor_key, floor_item = self._get_container(start)
        if floor_item is not None and floor_key not in overlapping_items:
            # insert it into the beginning
            overlapping_items.insert(0, floor_key)

        # scan through the entire list of region items, split existing regions and insert new regions as needed
        to_update = {start: RegionObject(start, object_size, {stored_object})}
        last_end: int = start

        for floor_key in overlapping_items:
            item: RegionObject = self._storage[floor_key]
            item_end: int = item.start + self._canonicalize_size(item.size)
            if item.start < start:
                # we need to break this item into two
                a, b = item.split(start)
                if overwrite:
                    b.set_object(stored_object)
                else:
                    self._add_object_with_check(b, stored_object, merge_to_top=merge_to_top, top=top)
                to_update[a.start] = a
                to_update[b.start] = b
                last_end = b.start + self._canonicalize_size(b.size)
            elif item.start > last_end:
                # there is a gap between the last item and the current item
                # fill in the gap
                new_item = RegionObject(last_end, item.start - last_end, {stored_object})
                to_update[new_item.start] = new_item
                last_end = new_item.end
            elif item_end > end:
                # we need to split this item into two
                a, b = item.split(end)
                if overwrite:
                    a.set_object(stored_object)
                else:
                    self._add_object_with_check(a, stored_object, merge_to_top=merge_to_top, top=top)
                to_update[a.start] = a
                to_update[b.start] = b
                last_end = b.start + self._canonicalize_size(b.size)
            else:
                if overwrite:
                    item.set_object(stored_object)
                else:
                    self._add_object_with_check(item, stored_object, merge_to_top=merge_to_top, top=top)
                to_update[item.start] = item

        self._storage.update(to_update)

    def _is_overlapping(self, start, variable):

        if variable.size is not None:
            # make sure this variable does not overlap with any other variable
            end = start + variable.size
            try:
                prev_offset = next(self._storage.irange(maximum=end-1, reverse=True))
            except StopIteration:
                prev_offset = None

            if prev_offset is not None:
                if start <= prev_offset < end:
                    return True
                prev_item = self._storage[prev_offset][0]
                prev_item_size = prev_item.size if prev_item.size is not None else 1
                if start < prev_offset + prev_item_size < end:
                    return True
        else:
            try:
                prev_offset = next(self._storage.irange(maximum=start, reverse=True))
            except StopIteration:
                prev_offset = None

            if prev_offset is not None:
                prev_item = self._storage[prev_offset][0]
                prev_item_size = prev_item.size if prev_item.size is not None else 1
                if prev_offset <= start < prev_offset + prev_item_size:
                    return True

        return False

    def _add_object_with_check(self, item, stored_object, merge_to_top=False, top=None):
        if len({stored_object.obj} | item.internal_objects) > 1:
            if merge_to_top:
                item.set_object(StoredObject(stored_object.start, top, stored_object.size))
                return

            if self._phi_node_contains is not None:
                # check if `item` is a phi node that contains stored_object.obj
                for so in item.internal_objects:
                    if self._phi_node_contains(so, stored_object.obj):
                        # yes! so we want to skip this object
                        return
                # check if `stored_object.obj` is a phi node that contains item.internal_objects
                if all(self._phi_node_contains(stored_object.obj, o) for o in item.internal_objects):
                    # yes!
                    item.set_object(stored_object)
                    return

        item.add_object(stored_object)
