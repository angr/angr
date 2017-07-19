
import logging

from bintrees import AVLTree


l = logging.getLogger("angr.knowledge.keyed_region")


class StoredObject(object):
    def __init__(self, start, obj, size):
        self.start = start
        self.obj = obj
        self.size = size

    def __eq__(self, other):
        assert type(other) is StoredObject

        return self.obj == other.obj and self.start == other.start and self.size == other.size

    def __hash__(self):
        return hash((self.start, self.obj, self.size))


class RegionObject(object):
    """
    Represents one or more objects occupying one or more bytes in KeyedRegion.
    """
    def __init__(self, start, size, objects=None):
        self.start = start
        self.size = size
        self.stored_objects = set() if objects is None else objects

        self._internal_objects = set()
        if self.stored_objects:
            for obj in self.stored_objects:
                self._internal_objects.add(obj.obj)

    def __eq__(self, other):
        return self.start == other.start and self.size == other.size and self.stored_objects == other.objects

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
        self.stored_objects.add(obj)
        self._internal_objects.add(obj.obj)

    def set_object(self, obj):
        self.stored_objects.clear()
        self._internal_objects.clear()

        self.add_object(obj)

    def copy(self):
        ro = RegionObject(self.start, self.size, objects=self.stored_objects.copy())
        return ro


class KeyedRegion(object):
    """
    KeyedRegion keeps a mapping between stack offsets and all objects covering that offset. It assumes no variable in
    this region overlap with another variable in this region.

    Registers and function frames can all be viewed as a keyed region.
    """
    def __init__(self, tree=None):
        self._storage = AVLTree() if tree is None else tree  # type: AVLTree

    def __contains__(self, offset):
        """
        Test if there is at least one varaible covering the given offset.

        :param offset:
        :return:
        """

        try: base_offset, item = self._storage.floor_item(offset)  #pylint:disable=unused-variable
        except KeyError: return False

        if item.includes(offset):
            return True
        return False

    def __len__(self):
        return len(self._storage)

    def __iter__(self):
        for _, item in self._storage.items():
            yield item

    def __eq__(self, other):
        if set(self._storage.keys()) != set(other._storage.keys()):
            return False

        for k, v in self._storage.iter_items():
            if v != other._storage[k]:
                return False

        return True

    def copy(self):
        if not self._storage:
            return KeyedRegion()

        kr = KeyedRegion()
        for key, ro in self._storage.iter_items():
            kr._storage[key] = ro.copy()
        return kr

    def merge(self, other, make_phi_func=None):
        """
        Merge another KeyedRegion into this KeyedRegion.

        :param KeyedRegion other: The other instance to merge with.
        :return: None
        """

        # TODO: is the current solution not optimal enough?
        for _, item in other._storage.iter_items():  # type: RegionObject
            for stored_object in item.stored_objects:
                self.__store(stored_object, overwrite=False, make_phi_func=make_phi_func)

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
            variables = [ obj.obj for obj in ro.objects ]
            offset_to_vars[key] = variables

        s = [ ]
        for offset, variables in offset_to_vars.iteritems():
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

        try: base_addr, item = self._storage.floor_item(addr)
        except KeyError: return None

        if item.includes(addr):
            return base_addr

        return None

    def get_variables_by_offset(self, start):
        """
        Find variables covering the given region offset.

        :param int start:
        :return: A list of stack variables.
        :rtype:  set
        """

        return self.get_objects_by_offset(start)

    def get_objects_by_offset(self, start):
        """
        Find objects covering the given region offset.

        :param start:
        :return:
        """

        try: base_addr = self._storage.floor_key(start)
        except KeyError: return [ ]

        item = self._storage[base_addr]  # type: RegionObject
        if item.includes(start):
            return item.internal_objects
        return [ ]


    #
    # Private methods
    #

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
        self.__store(stored_object, overwrite=overwrite)

    def __store(self, stored_object, overwrite=False, make_phi_func=None):
        """
        Store a variable into the storage.

        :param StoredObject stored_object: The descriptor describing start address and the variable.
        :param bool overwrite: Whether existing objects should be overwritten or not.
        :return: None
        """

        start = stored_object.start
        object_size = stored_object.size
        end = start + object_size

        # region items in the middle
        overlapping_items = list(self._storage.item_slice(start, end))

        # is there a region item that begins before the start and overlaps with this variable?
        try:
            floor_key, floor_item = self._storage.floor_item(start)  # type: RegionObject
            if floor_item.includes(start):
                item = (floor_key, floor_item)
                if item not in overlapping_items:
                    # insert it into the beginningq
                    overlapping_items.insert(0, (floor_key, floor_item))
        except KeyError:
            # no there isn't
            pass

        # scan through the entire list of region items, split existing regions and insert new regions as needed
        to_update = {start: RegionObject(start, object_size, {stored_object})}
        last_end = start

        for _, item in overlapping_items:  # type: RegionObject
            if item.start < start:
                # we need to break this item into two
                a, b = item.split(start)
                if overwrite:
                    b.set_object(stored_object)
                else:
                    self._add_object_or_make_phi(b, stored_object, make_phi_func=make_phi_func)
                to_update[a.start] = a
                to_update[b.start] = b
                last_end = b.end
            elif item.start > last_end:
                # there is a gap between the last item and the current item
                # fill in the gap
                new_item = RegionObject(last_end, item.start - last_end, {stored_object})
                to_update[new_item.start] = new_item
                last_end = new_item.end
            elif item.end > end:
                # we need to split this item into two
                a, b = item.split(end)
                if overwrite:
                    a.set_object(stored_object)
                else:
                    self._add_object_or_make_phi(a, stored_object, make_phi_func=make_phi_func)
                to_update[a.start] = a
                to_update[b.start] = b
                last_end = b.end
            else:
                if overwrite:
                    item.set_object(stored_object)
                else:
                    self._add_object_or_make_phi(item, stored_object, make_phi_func=make_phi_func)
                to_update[stored_object.start] = item

        self._storage.update(to_update)

    def _is_overlapping(self, start, variable):

        if variable.size is not None:
            # make sure this variable does not overlap with any other variable
            end = start + variable.size
            try:
                prev_offset = self._storage.floor_key(end - 1)
            except KeyError:
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
                prev_offset = self._storage.floor_key(start)
            except KeyError:
                prev_offset = None

            if prev_offset is not None:
                prev_item = self._storage[prev_offset][0]
                prev_item_size = prev_item.size if prev_item.size is not None else 1
                if prev_offset <= start < prev_offset + prev_item_size:
                    return True

        return False

    def _add_object_or_make_phi(self, item, stored_object, make_phi_func=None):  #pylint:disable=no-self-use
        if not make_phi_func or len({stored_object.obj} | item.internal_objects) == 1:
            item.add_object(stored_object)
        else:
            # make a phi node
            item.set_object(StoredObject(stored_object.start,
                                         make_phi_func(stored_object.obj, *item.internal_objects),
                                         stored_object.size,
                                         )
                            )
