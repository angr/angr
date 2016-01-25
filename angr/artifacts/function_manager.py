import logging
import networkx
import collections

l = logging.getLogger(name="angr.artifacts.function_manager")

class FunctionManager(collections.MutableMapping):
    '''
    This is a function boundaries management tool. It takes in intermediate
    results during CFG generation, and manages a function map of the binary.
    '''
    def __init__(self, artifact):
        self._artifact = artifact
        # A map that uses function starting address as the key, and maps
        # to a function class
        self._function_map = {}
        self.callgraph = networkx.DiGraph()

    def _genenare_callmap_sif(self, filepath):
        '''
        Generate a sif file from the call map

        :param filepath: Path of the sif file
        :return: None
        '''
        with open(filepath, "wb") as f:
            for src, dst in self.callgraph.edges():
                f.write("0x%x\tDirectEdge\t0x%x\n" % (src, dst))

    def _create_function_if_not_exist(self, function_addr):
        if function_addr not in self._function_map:
            self._function_map[function_addr] = Function(self, function_addr)
            self._function_map[function_addr].add_block(function_addr)

    def add_call_to(self, function_addr, from_addr, to_addr, retn_addr, syscall=False):
        self._create_function_if_not_exist(function_addr)
        self._create_function_if_not_exist(to_addr)
        self._function_map[function_addr].call_to(from_addr, to_addr, retn_addr, syscall=syscall)
        self._function_map[function_addr].add_call_site(from_addr, to_addr, retn_addr)
        self.callgraph.add_edge(function_addr, to_addr)

    def add_return_from(self, function_addr, from_addr, to_addr=None): #pylint:disable=unused-argument
        self._create_function_if_not_exist(function_addr)
        self._function_map[function_addr].add_return_site(from_addr)

    def add_transition_to(self, function_addr, from_addr, to_addr):
        self._create_function_if_not_exist(function_addr)
        self._function_map[function_addr].transit_to(from_addr, to_addr)

    def add_return_from_call(self, function_addr, src_function_addr, to_addr):
        self._create_function_if_not_exist(function_addr)
        self._function_map[function_addr].return_from_call(src_function_addr, to_addr)

    #
    # Dict methods
    #

    def __getitem__(self, k):
        f = self.function(name=k) if isinstance(k, str) else self.function(addr=k)
        if f is None:
            raise KeyError(k)
        return f

    def __setitem__(self, k, v):
        if not isinstance(k, int):
            raise ValueError("FunctionManager.__setitem__ keys should be addresses")
        self._function_map[k] = v

    def __delitem__(self, k):
        del self._function_map[k]

    def __len__(self):
        return len(tuple(self.__iter__()))

    def __iter__(self):
        for i in sorted(self._function_map.keys()):
            yield i

    def function(self, addr=None, name=None, create_if_not_exist=False):
        if addr:
            if addr in self._function_map:
                return self._function_map[addr]
            elif create_if_not_exist:
                self._create_function_if_not_exist(addr)
                return self._function_map[addr]
        elif name:
            funcs = [ i for i in self._function_map.values() if i.name == name ]
            if funcs:
                return funcs[0]
            else:
                return None
        else:
            return None

    def dbg_draw(self):
        for func_addr, func in self._function_map.items():
            filename = "dbg_function_0x%08x.png" % func_addr
            func.dbg_draw(filename)

from .function import Function
