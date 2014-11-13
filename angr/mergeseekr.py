from .analyses import cdg

class MergeSeekr(object):
    def __init__(self, cfg_, cdg_):
        self._cfg = cfg_
        self._cdg = cdg_

        self._path_merge_points = {}

        self._construct()

    def _construct(self):
        '''
        A merge point (or transition point, as is termed in Veritesting paper)
        should be an immediate post-dominator of a certain range of nodes.
        We can get the post-dominator information from CDG.
        '''
        post_doms = self._cdg.get_post_dominators()
        # Get all nodes in CFG that has two out degrees (means a branch)
        branching_nodes = self._cfg.get_branching_nodes()
        for node in branching_nodes:
            successors = self._cfg.get_successors(node)
            if node not in post_doms:
                continue
            post_dom = post_doms[node]
            if not isinstance(post_dom, cdg.TempNode):
                # DFS until the post dominator, and label all nodes on the way
                for succ in successors:
                    self._path_merge_points[succ.addr] = post_dom.addr

    def get_path_merge_points(self):
        return self._path_merge_points
