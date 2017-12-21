from collections import defaultdict

from ..errors import AngrError
from .plugin import KnowledgeBasePlugin

import logging
l = logging.getLogger(name=__name__)


class FunctionsPlugin(KnowledgeBasePlugin):
    """
    TODO: Update documentation.
    """

    def __init__(self):
        super(FunctionsPlugin, self).__init__()

        self._addrs = set()
        self._returning = {}
        self._nodes_by_func = {}
        self._funcs_by_node = {}

    def __getitem__(self, item):
        nodes = self._nodes_by_func[item]
        returning = self._returning[item]
        return Function(item, nodes, returning)

    def __iter__(self):
        for addr in self._addrs:
            return self[addr]

    def __contains__(self, item):
        return item in self._addrs

    def __len__(self):
        return len(self._addrs)

    #
    #   ...
    #

    @property
    def addrs(self):
        return self._addrs

    def get_function(self, entry):
        """

        :param entry:
        :return:
        """
        try:
            return self[entry]
        except KeyError:
            return None

    def get_any_function(self, addr):
        """

        :param addr:
        :return:
        """
        try:
            entry = next(iter(self._funcs_by_node[addr]))
            return self.get_function(entry)
        except (KeyError, StopIteration):
            return None

    def get_all_functions(self, addr):
        """

        :param addr:
        :return:
        """
        try:
            entries = self._funcs_by_node[addr]
            return map(self.get_function, entries)
        except KeyError:
            return []

    def register_function(self, entry):
        """

        :param entry:
        :return:
        """
        if entry in self._funcs_by_node:
            overlapped = self._funcs_by_node[entry]
            raise AngrError("Can not register function @ %#x: the address"
                            "is already claimed by function @ %#x" % (entry, overlapped))

        self._addrs.add(entry)
        self._returning[entry] = None
        self._add_nodes(entry, {entry})

    def add_nodes(self, entry, nodes):
        """

        :param entry:
        :param nodes:
        :return:
        """
        if entry not in self._addrs:
            raise AngrError("No function with entry @ %#x", entry)

        for node in set(nodes) - {entry}:
            if node in self._addrs:
                raise AngrError("Node %#x is an entry point and can't be marked"
                                "as local for any other function." % node)

        self._add_nodes(entry, nodes)

    def remove_nodes(self, entry, nodes):
        """

        :param entry:
        :param nodes:
        :return:
        """
        if entry not in self._addrs:
            raise AngrError("No function with entry @ %#x" % entry)

        if entry in nodes:
            raise AngrError("Can not remove node %#x as it is an entry node" % entry)

        self._remove_nodes(entry, nodes)

    def set_returning(self, entry, returning):
        """

        :param entry:
        :param returning:
        :return:
        """
        if entry not in self._addrs:
            raise AngrError("No function with entry @ %#x", entry)
        if self._returning[entry] is not None:
            raise AngrError("Can not change return status for function @ %#x", entry)
        self._returning[entry] = returning

    #
    #   ...
    #

    def _add_nodes(self, entry, nodes):
        for node in nodes:
            self._nodes_by_func.setdefault(entry, set()).add(node)
            self._funcs_by_node.setdefault(node, set()).add(entry)

    def _remove_nodes(self, entry, nodes):
        for node in nodes:
            self._nodes_by_func.setdefault(entry, set()).remove(node)
            self._funcs_by_node.setdefault(node, set()).remove(entry)


class Function(object):

    def __init__(self, entry, nodes, returning):
        self._entry = entry
        self._nodes = nodes
        self._returning = returning

    @property
    def entry(self):
        return self._entry

    @property
    def nodes(self):
        return self._nodes

    @property
    def returning(self):
        return self._returning
