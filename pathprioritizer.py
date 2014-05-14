import networkx

class PathPrioritizer(object):
    def __init__(self, cfg, target):
        self._cfg = cfg
        self._target = target
        self._shortest_path_length_dict = {}

        self._construct()

    def _construct(self):
        g = self._cfg.get_graph()
        bbl_dict = self._cfg.get_bbl_dict()
        assert(self._target in g)
        assert(bbl_dict is not None)

        # Reverse the bbl_dict
        bbl_key_map = {}
        for k, v in bbl_dict:
            bbl_key_map[v] = k

        # Do a BFS from target, and save the length of shortest path to each
        # basic block
        shortest_path_length = networkx.single_source_shortest_path_length( \
                                                            g, self._target)
        for k, v in shortest_path_length:
            bbl_key = bbl_key_map[k]
            self._shortest_path_length_dict[bbl_key] = v
