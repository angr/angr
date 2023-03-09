class Loop:
    def __init__(self, entry, entry_edges, break_edges, continue_edges, body_nodes, graph, subloops):
        self.entry = entry
        self.entry_edges = entry_edges
        self.break_edges = break_edges
        self.continue_edges = continue_edges
        self.body_nodes = body_nodes
        self.graph = graph
        self.subloops = subloops

        self.has_calls = any(map(lambda loop: loop.has_calls, subloops))

        if not self.has_calls:
            for _, _, data in self.graph.edges(data=True):
                if "type" in data and data["type"] == "fake_return":
                    # this is a function call.
                    self.has_calls = True
                    break

    def __repr__(self):
        s = "<Loop @ %s, %d blocks>" % (self.entry.addr, len(self.body_nodes))
        return s
