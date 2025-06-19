from . import ExplorationTechnique

import logging
l = logging.getLogger('angr.exploration_techniques.cfgexplorer')


class CFGExplorer(ExplorationTechnique):
    """
    This technique will make step stop at the next block in the CFG
    """

    def __init__(self, cfg):
        super(CFGExplorer, self).__init__()

        self.cfg = cfg
        if not self.cfg.normalized:
            self.cfg.normalize()

    def step_path(self, path):
        """ this steps paths forwards, try to step up to the boundaries of a cfg block,
        avoid stepping in the middle of a block later """
        cfg_node = self.cfg.get_any_node(addr=path.addr)

        if cfg_node is None:
            return None

        successors = path.step(size=cfg_node.size)
        return successors, path.unconstrained_successors, path.unsat_successors, [], []
