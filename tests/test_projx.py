import angr
import projx as px

p = angr.Project('/usr/bin/sudo', load_options={'auto_load_libs': False})


cfg = p.analyses.CFGFast()

for node in cfg._graph.nodes():
    cfg._graph.add_node(node, node=node, address=node.addr, size=node.size, is_syscall=node.is_syscall, name=node.name,
                        function_address=node.function_address, looping_times=node.looping_times)

G = cfg._graph
"""
G = px.utils.test_graph()
"""
projection = px.Projection(G, node_type_attr='is_syscall', edge_type_attr='jumpkind')

g = projection.execute('MATCH (m:asdflkjasdf)-[jmp:Ijk_Boring]-(n)')

print g.nodes(data=True)
print g.edges(data=True)


