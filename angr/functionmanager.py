from collections import defaultdict

import networkx
import matplotlib.pyplot as pyplot

class Function(object):
    def __init__(self, name=None):
        self._transition_graph = networkx.DiGraph()
        self._ret_sites = set()
        self._call_sites = {}
        self._retn_addr_to_call_site = {}
        self._name = None

    def transit_to(self, from_addr, to_addr):
        self._transition_graph.add_edge(from_addr, to_addr)

    def add_block(self, addr):
        self._transition_graph.add_node(addr)

    def add_return_site(self, return_site_addr):
        self._ret_sites.add(return_site_addr)

    def add_call_site(self, call_addr, retn_addr):
        self._call_sites[call_addr] = retn_addr
        self._retn_addr_to_call_site[retn_addr] = call_addr

    def dbg_print(self):
        result = ''
        basic_blocks = []
        for n in self._transition_graph.nodes():
            basic_blocks.append("0x%08x" % n)
        result = "[" + ', '.join(basic_blocks) + ']'
        return result

    def dbg_draw(self, filename):
        '''
        Draw the graph and save it to a PNG file
        '''
        tmp_graph = networkx.DiGraph()
        for edge in self._transition_graph.edges():
            node_a = "0x%08x" % edge[0]
            node_b = "0x%08x" % edge[1]
            if node_b in self._ret_sites:
                node_b += "[Ret]"
            if node_a in self._call_sites:
                node_a += "[Call]"
            tmp_graph.add_edge(node_a, node_b)
        pos = networkx.graphviz_layout(tmp_graph, prog='neato')
        networkx.draw(tmp_graph, pos)
        pyplot.savefig(filename)

class FunctionManager(object):
    '''
    This is a function boundaries management tool. It takes in intermediate
    results during CFG generation, and manages a function map of the binary.
    '''
    def __init__(self, project, binary):
        self._project = project
        self._binary = binary
        # A map that uses function starting address as the key, and maps
        # to a function class
        self._function_map = defaultdict(Function)

    def call_to(self, function_addr, from_addr, to_addr, retn_addr):
        self._function_map[function_addr].add_call_site(from_addr, retn_addr)

    def return_from(self, function_addr, from_addr, to_addr):
        self._function_map[function_addr].add_return_site(from_addr)

    def transit_to(self, function_addr, from_addr, to_addr):
        self._function_map[function_addr].transit_to(from_addr, to_addr)

    def dbg_print(self):
        result = ''
        for func_addr, func in self._function_map.items():
            f_str = "Function 0x%08x\n%s\n" % (func_addr, func.dbg_print())
            result += f_str
        return result
