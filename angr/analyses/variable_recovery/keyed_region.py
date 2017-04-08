
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

    def copy(self):
        if not self._tree:
            return KeyedRegion()
        else:
            return KeyedRegion(tree=self._tree.copy())

    def add_variable(self, offset, variable):
        """
        Add a variable to this region.

        :param int offset:
        :param SimVariable variable:
        :return: None
        """

        if offset not in self._tree:
            if variable.size is not None:
                # make sure this variable does not overlap with any other variable
                end = offset + variable.size
                try: prev_offset = self._tree.floor_key(end - 1)
                except KeyError: prev_offset = None

                if prev_offset is not None:
                    if offset <= prev_offset < end:
                        l.debug('Variable %s overlaps with an existin variable. Skip.', variable)
                        return
                    prev_item = self._tree[prev_offset][0]
                    prev_item_size = prev_item.size if prev_item.size is not None else 1
                    if offset < prev_offset + prev_item_size < end:
                        l.debug('Variable %s overlaps with an existin variable. Skip.', variable)
                        return
            else:
                try: prev_offset = self._tree.floor_key(offset)
                except KeyError: prev_offset = None

                if prev_offset is not None:
                    prev_item = self._tree[prev_offset][0]
                    prev_item_size = prev_item.size if prev_item.size is not None else 1
                    if prev_offset <= offset < prev_offset + prev_item_size:
                        l.debug('Variable %s overlaps with an existin variable. Skip.', variable)
                        return

            self._tree[offset] = [variable]

        else:
            if variable in self._tree[offset]:
                return

            if variable.size != self._tree[offset][0]:
                l.debug('Adding a new variable to stack with a different size as the previous item. Skip.')
                return

            self._tree[offset].append(variable)

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

