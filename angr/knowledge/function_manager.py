import logging
import collections

import networkx

from .function import Function

l = logging.getLogger(name="angr.knowledge.function_manager")


class FunctionDict(dict):
    """
    FunctionDict is a dict where the keys are function starting addresses and
    map to the associated :class:`Function`.
    """
    def __init__(self, backref, *args, **kwargs):
        self._backref = backref
        super(FunctionDict, self).__init__(*args, **kwargs)

    def __missing__(self, key):
        if isinstance(key, (int, long)):
            addr = key
        else:
            raise ValueError("FunctionDict.__missing__ only supports int as key type")

        t = Function(self._backref, addr)
        self[addr] = t
        return t


class FunctionManager(collections.Mapping):
    """
    This is a function boundaries management tool. It takes in intermediate
    results during CFG generation, and manages a function map of the binary.
    """
    def __init__(self, kb):
        self._kb = kb
        self._function_map = FunctionDict(self)
        self.callgraph = networkx.MultiDiGraph()

        # Registers used for passing arguments around
        self._arg_registers = kb._project.arch.argument_registers

    def copy(self):
        fm = FunctionManager(self._kb)
        fm._function_map = self._function_map.copy()
        fm.callgraph = networkx.MultiDiGraph(self.callgraph)
        fm._arg_registers = self._arg_registers.copy()

        return fm

    def clear(self):
        self._function_map.clear()
        self.callgraph = networkx.MultiDiGraph()

    def _genenare_callmap_sif(self, filepath):
        """
        Generate a sif file from the call map.

        :param filepath:    Path of the sif file
        :return:            None
        """
        with open(filepath, "wb") as f:
            for src, dst in self.callgraph.edges():
                f.write("%#x\tDirectEdge\t%#x\n" % (src, dst))

    def _add_node(self, function_addr, node, syscall=None, size=None):
        if type(node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            node = self._kb._project.factory.snippet(node, max_size=size)
        dst_func = self._function_map[function_addr]
        if syscall in (True, False):
            dst_func.is_syscall = syscall
        dst_func._register_nodes(True, node)

    def _add_call_to(self, function_addr, from_node, to_addr, retn_node, syscall=None):

        if type(from_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if type(retn_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            retn_node = self._kb._project.factory.snippet(retn_node)
        dest_func = self._function_map[to_addr]
        if syscall in (True, False):
            dest_func.is_syscall = syscall

        self._function_map[function_addr]._call_to(from_node, dest_func, retn_node)
        self._function_map[function_addr]._add_call_site(from_node.addr, to_addr, retn_node.addr if retn_node else None)

        # is there any existing edge on the callgraph?
        edge_data = {'type': 'call'}
        if function_addr not in self.callgraph or \
                to_addr not in self.callgraph[function_addr] or \
                edge_data not in self.callgraph[function_addr][to_addr].values():
            self.callgraph.add_edge(function_addr, to_addr, **edge_data)

    def _add_fakeret_to(self, function_addr, from_node, to_node, confirmed=None, syscall=None, to_outside=False,
                        to_function_addr=None):
        if type(from_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        src_func = self._function_map[function_addr]

        if syscall in (True, False):
            src_func.is_syscall = syscall

        src_func._fakeret_to(from_node, to_node, confirmed=confirmed, to_outside=to_outside)

        if to_outside and to_function_addr is not None:
            # mark it on the callgraph
            edge_data = {'type': 'fakeret'}
            if function_addr not in self.callgraph or \
                    to_function_addr not in self.callgraph[function_addr] or \
                    edge_data not in self.callgraph[function_addr][to_function_addr].values():
                self.callgraph.add_edge(function_addr, to_function_addr, **edge_data)

    def _remove_fakeret(self, function_addr, from_node, to_node):
        if type(from_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[function_addr]._remove_fakeret(from_node, to_node)

    def _add_return_from(self, function_addr, from_node, to_node=None): #pylint:disable=unused-argument
        if type(from_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        self._function_map[function_addr]._add_return_site(from_node)

    def _add_transition_to(self, function_addr, from_node, to_node):
        if type(from_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[function_addr]._transit_to(from_node, to_node)

    def _add_outside_transition_to(self, function_addr, from_node, to_node, to_function_addr=None):
        if type(from_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[function_addr]._transit_to(from_node, to_node, outside=True)

        if to_function_addr is not None:
            # mark it on the callgraph
            edge_data = {'type': 'transition'}
            if function_addr not in self.callgraph or \
                    to_function_addr not in self.callgraph[function_addr] or \
                    edge_data not in self.callgraph[function_addr][to_function_addr].values():
                self.callgraph.add_edge(function_addr, to_function_addr, **edge_data)

    def _add_return_from_call(self, function_addr, src_function_addr, to_node):

        # Note that you will never return to a syscall

        if type(to_node) in (int, long):  # pylint: disable=unidiomatic-typecheck
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[function_addr]._return_from_call(
            self._function_map[src_function_addr], to_node)

    #
    # Dict methods
    #

    def __getitem__(self, k):
        if isinstance(k, (int, long)):
            f = self.function(addr=k)
        elif isinstance(k, str):
            f = self.function(name=k)
        else:
            raise ValueError("FunctionManager.__getitem__ deos not support keys of type %s" % type(k))

        if f is None:
            raise KeyError(k)

        return f

    def __setitem__(self, k, v):
        if isinstance(k, (int, long)):
            self._function_map[k] = v
        else:
            raise ValueError("FunctionManager.__setitem__ keys must be an int")

    def __delitem__(self, k):
        if isinstance(k, (int, long)):
            del self._function_map[k]
        else:
            raise ValueError("FunctionManager.__delitem__ only accepts int as key")

    def __len__(self):
        return len(self._function_map)

    def __iter__(self):
        for i in sorted(self._function_map.iterkeys()):
            yield i

    def function(self, addr=None, name=None, create=False, syscall=False):
        """
        Get a function object from the function manager.

        Pass either `addr` or `name` with the appropriate values.
        """
        if addr is not None:
            if addr in self._function_map:
                return self._function_map[addr]
            elif create:
                f = self._function_map[addr]
                if syscall:
                    f.is_syscall=True
                return f
        elif name is not None:
            for func in self._function_map.itervalues():
                if func.name == name:
                    return func

        return None

    def dbg_draw(self, prefix='dbg_function_'):
        for func_addr, func in self._function_map.iteritems():
            filename = "%s%#08x.png" % (prefix, func_addr)
            func.dbg_draw(filename)
