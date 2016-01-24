import logging
import networkx

l = logging.getLogger(name="angr.artifacts.function manager")

class FunctionManager(object):
    '''
    This is a function boundaries management tool. It takes in intermediate
    results during CFG generation, and manages a function map of the binary.
    '''
    def __init__(self, project, cfg):
        self.project = project
        self._cfg = cfg
        # A map that uses function starting address as the key, and maps
        # to a function class
        self._function_map = {}
        self.interfunction_graph = networkx.DiGraph()

        # Registers used for passing arguments around
        self.arg_registers = project.arch.argument_registers

    def _create_function_if_not_exist(self, function_addr):
        if function_addr not in self._function_map:
            self._function_map[function_addr] = Function(self, function_addr)
            self._function_map[function_addr].add_block(function_addr)

    def call_to(self, function_addr, from_addr, to_addr, retn_addr, syscall=False):
        self._create_function_if_not_exist(function_addr)
        self._create_function_if_not_exist(to_addr)
        self._function_map[function_addr].call_to(from_addr, to_addr, retn_addr, syscall=syscall)
        self._function_map[function_addr].add_call_site(from_addr, to_addr, retn_addr)
        self.interfunction_graph.add_edge(function_addr, to_addr)

    def return_from(self, function_addr, from_addr, to_addr=None): #pylint:disable=unused-argument
        self._create_function_if_not_exist(function_addr)
        self._function_map[function_addr].add_return_site(from_addr)

    def transit_to(self, function_addr, from_addr, to_addr):
        self._create_function_if_not_exist(function_addr)
        self._function_map[function_addr].transit_to(from_addr, to_addr)

    def return_from_call(self, function_addr, src_function_addr, to_addr):
        self._create_function_if_not_exist(function_addr)
        self._function_map[function_addr].return_from_call(src_function_addr, to_addr)

    @property
    def functions(self):
        return self._function_map

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

    def repr_functions(self):
        s = [ ]
        for addr, f in self.functions.iteritems():
            s.append((addr, repr(f)))
        s = sorted(s, key=lambda x: x[0])

        return "\n".join([ x for _, x in s ])

    def dbg_print(self):
        result = ''
        for func_addr, func in self._function_map.items():
            f_str = "Function %#x\n%s\n" % (func_addr, func.dbg_print())
            result += f_str
        return result

    def dbg_draw(self):
        for func_addr, func in self._function_map.items():
            filename = "dbg_function_0x%08x.png" % func_addr
            func.dbg_draw(filename)

from .function import Function
