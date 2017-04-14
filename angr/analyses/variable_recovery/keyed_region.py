
import logging

from bintrees import AVLTree


l = logging.getLogger('angr.analyses.variable_recovery.keyed_region')


class KeyedRegion(object):
    """
    KeyedRegion keeps a mapping between stack offsets and all variables covering that offset. It assumes no variable in
    this region overlap with another variable in this region.

    Registers and function frames can all be viewed as a keyed region.
    """
    def __init__(self, tree=None):
        self._tree = AVLTree() if tree is None else tree

    def __contains__(self, offset):
        """
        Test if there is at least one varaible covering the given offset.

        :param offset:
        :return:
        """

        try: base_offset = self._tree.floor_key(offset)
        except KeyError: return False

        variables = self._tree[base_offset]

        v = variables[0]
        var_size = 1 if v.size is None else v.size
        if base_offset <= offset < base_offset + var_size:
            return True
        return False

    def __len__(self):
        return len(self._tree)

    def __iter__(self):
        for offset in self._tree.keys():
            for item in self._tree[offset]:
                yield item

    def copy(self):
        if not self._tree:
            return KeyedRegion()
        else:
            return KeyedRegion(tree=self._tree.copy())

    def merge(self, other):
        for offset in set(self._tree.keys()) | set(other._tree.keys()):
            if offset in self._tree:
                if offset in other._tree:
                    for var in other._tree[offset]:
                        self.add_variable(offset, var)
                        # print "adding variable %s during merge" % var
            else:
                self._tree[offset] = other._tree[offset]

    def add_variable(self, offset, variable):
        """
        Add a variable to this region at the given offset.

        :param int offset:
        :param SimVariable variable:
        :return: None
        """

        if offset not in self._tree:
            if self._is_overlapping(offset, variable):
                l.debug('Variable %s overlaps with an existing variable. Skip.', variable)
                return

            self._tree[offset] = [variable]

        else:
            if variable in self._tree[offset]:
                return

            if variable.size != self._tree[offset][0].size:
                l.debug('Adding a new variable to stack with a different size as the previous item. Skip.')
                return

            self._tree[offset].append(variable)

    def set_variable(self, offset, variable):
        """
        Add a variable to this region at the given offset, and remove all other variables that are fully covered by 
        this variable.

        :param int offset:
        :param SimVariable variable:
        :return: None
        """

        if offset not in self._tree:
            # TODO: check for overlaps

            self._tree[offset] = [ variable ]

        else:
            # TODO: check for overlaps

            self._tree[offset] = [ variable ]

    def get_base_offset(self, offset):
        """
        Get the base offset (the key we are using to index variables covering the given offset) of a specific offset.

        :param int offset:
        :return:
        :rtype:  int or None
        """

        try: base_offset = self._tree.floor_key(offset)
        except KeyError: return None

        v = self._tree[base_offset][0]
        var_size = 1 if v.size is None else v.size

        if base_offset <= offset < base_offset + var_size:
            return base_offset
        else:
            return None

    def get_variables_by_offset(self, offset):
        """
        Find variables that cover the given stack offset.

        :param int offset:
        :return: A list of stack variables.
        :rtype:  list
        """

        try: base_offset = self._tree.floor_key(offset)
        except KeyError: return [ ]

        variables = self._tree[base_offset]

        v = variables[0]
        var_size = 1 if v.size is None else v.size

        if base_offset <= offset < base_offset + var_size:
            return variables
        return [ ]


    #
    # Private methods
    #

    def _is_overlapping(self, offset, variable):

        if variable.size is not None:
            # make sure this variable does not overlap with any other variable
            end = offset + variable.size
            try:
                prev_offset = self._tree.floor_key(end - 1)
            except KeyError:
                prev_offset = None

            if prev_offset is not None:
                if offset <= prev_offset < end:
                    return True
                prev_item = self._tree[prev_offset][0]
                prev_item_size = prev_item.size if prev_item.size is not None else 1
                if offset < prev_offset + prev_item_size < end:
                    return True
        else:
            try:
                prev_offset = self._tree.floor_key(offset)
            except KeyError:
                prev_offset = None

            if prev_offset is not None:
                prev_item = self._tree[prev_offset][0]
                prev_item_size = prev_item.size if prev_item.size is not None else 1
                if prev_offset <= offset < prev_offset + prev_item_size:
                    return True

        return False
