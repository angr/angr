import logging
import networkx
import collections

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
        if isinstance(key, tuple) and len(key) == 2:
            addr, is_syscall = key
        elif isinstance(key, int):
            addr = key
            is_syscall = False
        else:
            raise ValueError("FunctionDict.__missing__ does not support key of type %s" % type(key))

        t = Function(self._backref, addr, syscall=is_syscall)
        self[key] = t
        return t


class FunctionManager(collections.Mapping):
    """
    This is a function boundaries management tool. It takes in intermediate
    results during CFG generation, and manages a function map of the binary.
    """
    def __init__(self, kb):
        self._kb = kb
        self._function_map = FunctionDict(self)
        self.callgraph = networkx.DiGraph()

        # Registers used for passing arguments around
        self._arg_registers = kb._project.arch.argument_registers

    def _genenare_callmap_sif(self, filepath):
        """
        Generate a sif file from the call map.

        :param filepath:    Path of the sif file
        :return:            None
        """
        with open(filepath, "wb") as f:
            for src, dst in self.callgraph.edges():
                f.write("%#x\tDirectEdge\t%#x\n" % (src, dst))

    def _add_node(self, function_addr, node, syscall=False):
        if type(node) in (int, long):
            node = self._kb._project.factory.snippet(node)
        self._function_map[(function_addr, syscall)]._register_nodes(node)

    def _add_call_to(self, function_addr, from_node, to_addr, retn_node, syscall=False):

        # Note that a syscall will never make a call to anything else

        if type(from_node) in (int, long):
            from_node = self._kb._project.factory.snippet(from_node)
        if type(retn_node) in (int, long):
            retn_node = self._kb._project.factory.snippet(retn_node)
        dest_func = self._function_map[(to_addr, syscall)]
        self._function_map[(function_addr, False)]._call_to(from_node, dest_func, retn_node)
        self._function_map[(function_addr, False)]._add_call_site(from_node.addr, to_addr, retn_node.addr if retn_node else None)
        self.callgraph.add_edge((function_addr, False), (to_addr, syscall))

    def _add_fakeret_to(self, function_addr, from_node, to_node, confirmed=None, syscall=False):
        if type(from_node) in (int, long):
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) in (int, long):
            to_node = self._kb._project.factory.snippet(to_node)
        src_func = self._function_map[(function_addr, syscall)]
        src_func._fakeret_to(from_node, to_node, confirmed=confirmed)

    def _remove_fakeret(self, function_addr, from_node, to_node, syscall=False):
        if type(from_node) in (int, long):
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) in (int, long):
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[(function_addr, syscall)]._remove_fakeret(from_node, to_node)

    def _add_return_from(self, function_addr, from_node, to_node=None, syscall=False): #pylint:disable=unused-argument
        if type(from_node) in (int, long):
            from_node = self._kb._project.factory.snippet(from_node)
        self._function_map[(function_addr, syscall)]._add_return_site(from_node)

    def _add_transition_to(self, function_addr, from_node, to_node, syscall=False):
        if type(from_node) in (int, long):
            from_node = self._kb._project.factory.snippet(from_node)
        if type(to_node) in (int, long):
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[(function_addr, syscall)]._transit_to(from_node, to_node)

    def _add_return_from_call(self, function_addr, src_function_addr, to_node, src_func_syscall=False):

        # Note that you will never return to a syscall

        if type(to_node) in (int, long):
            to_node = self._kb._project.factory.snippet(to_node)
        self._function_map[(function_addr, False)]._return_from_call(
            self._function_map[(src_function_addr, src_func_syscall)], to_node)

    #
    # Dict methods
    #

    def __getitem__(self, k):
        if isinstance(k, int):
            f = self.function(addr=k)
        elif isinstance(k, str):
            f = self.function(name=k)
        elif isinstance(k, tuple) and len(k) == 2:
            f = self.function(addr=k[0], syscall=k[1])
        else:
            raise ValueError("FunctionManager.__getitem__ deos not support keys of type %s" % type(k))

        if f is None:
            raise KeyError(k)

        return f

    def __setitem__(self, k, v):
        if isinstance(k, int):
            # By default a non-syscall function is created
            key = (k, False)
            self._function_map[key] = v
        elif isinstance(k, tuple) and len(k) == 2:
            if not isinstance(k[0], int):
                raise ValueError("The first element of a FunctionManager.__setitem__ key must be an int")
            if not isinstance(k[1], bool):
                raise ValueError("The second element of a FunctionManager.__setitem__ key must be a bool")
            self._function_map[k] = v
        else:
            raise ValueError("FunctionManager.__setitem__ keys should be either an int or a 2-tuple")

    def __delitem__(self, k):
        if isinstance(k, tuple) and len(k) == 2:
            del self._function_map[k]
        elif isinstance(k, int):
            del self._function_map[(k, False)]
        else:
            raise ValueError("FunctionManager.__delitem__ does not support keys of type %s" % type(k))

    def __len__(self):
        return len(self._function_map)

    def __iter__(self):
        for i in sorted(self._function_map.keys()):
            yield i

    def function(self, addr=None, name=None, create=False, syscall=False):
        """
        Get a function object from the function manager.

        Pass either `addr` or `name` with the appropriate values.
        """
        if addr is not None:
            if (addr, syscall) in self._function_map or create:
                return self._function_map[(addr, syscall)]
        elif name is not None:
            for func in self._function_map.itervalues():
                if func.name == name:
                    return func

        return None

    def dbg_draw(self, prefix='dbg_function_'):
        for (func_addr, is_syscall), func in self._function_map.iteritems():
            filename = "%s%#08x_%s.png" % (prefix, func_addr, "syscall" if is_syscall else "normal")
            func.dbg_draw(filename)

from .function import Function
