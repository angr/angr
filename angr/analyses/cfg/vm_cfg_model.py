from __future__ import annotations

import networkx

from angr.knowledge_plugins.cfg.cfg_model import CFGModel


class VMCFGModel(CFGModel):
    """
    A CFGModel whose graph is a plain networkx.DiGraph of CFGNode objects.

    The VM-deobfuscation analyses (CFGVMDeobfuscation, CFGConcreteExecution,
    EmulatedStackPointerTracker, Symbolizer, PropagatorEmulated, VMDeobfuscation) rewrite the CFG
    directly with networkx idioms -- subgraphs, connected components, DFS orders, wholesale node and
    edge surgery -- and hand the graph to networkx algorithms. angr's SpillingCFG keeps CFGNodes out
    of its networkx graph (it stores block keys and loads nodes on demand), so it cannot stand in for
    a DiGraph. This model keeps the plain graph those analyses expect and maintains the block-ID
    index itself.
    """

    __slots__ = ("_vm_nodes",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._vm_nodes: dict = {}
        self.graph = networkx.DiGraph()

    @classmethod
    def from_model(cls, model: CFGModel) -> VMCFGModel:
        """
        Replace a model freshly handed out by CFGManager with a VMCFGModel registered under the same
        identifier.
        """
        if isinstance(model, VMCFGModel):
            return model
        new = cls(
            model.ident,
            cfg_manager=model._cfg_manager,
            is_arm=model.is_arm,
            addr_type=model.addr_type,
        )
        if model._cfg_manager is not None:
            model._cfg_manager[model.ident] = new
        return new

    #
    # Node bookkeeping, keyed by BlockID rather than by block key
    #

    @property
    def _nodes(self):
        return self._vm_nodes

    def add_node(self, block_id, node) -> None:
        self._vm_nodes[block_id] = node
        self.graph.add_node(node)

    def remove_node(self, block_id, node) -> None:
        self._vm_nodes.pop(block_id, None)
        if node in self.graph:
            self.graph.remove_node(node)

    def get_node(self, block_id):
        return self._vm_nodes.get(block_id)

    def has_node_id(self, block_id) -> bool:
        return block_id in self._vm_nodes

    def nodes_by_addr(self, addr):
        yield from self._nodes_by_addr.get(addr, [])

    def has_node_addr(self, addr) -> bool:
        return bool(self._nodes_by_addr.get(addr))

    def get_any_node(self, addr, is_syscall=None, anyaddr=False, force_fastpath=False):
        candidates = self._nodes_by_addr.get(addr, None)
        if candidates:
            for node in candidates:
                if is_syscall is None or node.is_syscall == is_syscall:
                    return node

        if force_fastpath or not anyaddr:
            return None

        for node in self.graph.nodes():
            if node.size is None:
                continue
            if not (node.addr <= addr < node.addr + node.size):
                continue
            if is_syscall is None or node.is_syscall == is_syscall:
                return node
        return None

    def get_all_nodes(self, addr, is_syscall=None, anyaddr=False):
        results = []
        for node in self.graph.nodes():
            if anyaddr and node.size is not None:
                matched = node.addr <= addr < node.addr + node.size
            else:
                matched = node.addr == addr
            if matched and (is_syscall is None or node.is_syscall == is_syscall):
                results.append(node)
        return results

    #
    # Pickling: CFGModel.__getstate__ only walks its own __slots__, so collect them across the MRO
    #

    def __getstate__(self):
        slots = []
        for klass in type(self).__mro__:
            slots.extend(getattr(klass, "__slots__", ()))
        return {name: getattr(self, name) for name in slots if name not in {"__weakref__", "_cfg_manager"}}
