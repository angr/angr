import sys
import pickle

import networkx

import idalink

def _buildCFG(ida, graph, func_addr):
    addrs = [func_addr]

    while addrs:
        addr = addrs.pop()
        refs = ida.idautils.CodeRefsFrom(addr, 1)
        for r in refs:
            if r not in graph:
                addrs.append(r)
            if not graph.has_edge(addr, r):
                graph.add_edge(addr, r)

def BuildCFG(ida):
    '''
    Context-sensitivity level is 1
    '''
    graph = networkx.DiGraph()

    for func_addr in ida.idautils.Functions():
        print "Function %x" % func_addr
        _buildCFG(ida, graph, func_addr)

    print "Graph has %d nodes and %d edges." % (len(graph.nodes()), len(graph.edges()))

    return graph

def usage():
    print "Usage: %s idaprog /path/to/binary/file /path/to/edge/dump" % (sys.argv[0])

def main():
    if len(sys.argv) != 4:
        usage()

    idaprog = sys.argv[1]
    binary_path = sys.argv[2]
    edge_dump = sys.argv[3]

    ida = idalink.IDALink(binary_path, idaprog)

    graph = BuildCFG(ida)

    # Dump it
    pickle.dump(graph, open(edge_dump, "wb"))

if __name__ == "__main__":
    main()
