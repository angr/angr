from functools import reduce

from ..plugin import KnowledgeBasePlugin
from .cfg_model import CFGModel


class CFGManager(KnowledgeBasePlugin):

    def __init__(self, kb):

        super().__init__()

        self._kb = kb
        self.cfgs = { }

    def __repr__(self):
        return "<CFGManager with %d CFGs>" % len(self.cfgs)

    def __contains__(self, ident):
        return ident in self.cfgs

    def __getitem__(self, ident) -> CFGModel:
        if ident not in self.cfgs:
            self.cfgs[ident] = CFGModel(ident, cfg_manager=self)
        return self.cfgs[ident]

    def __setitem__(self, ident, model):
        self.cfgs[ident] = model

    def new_model(self, prefix):

        if prefix not in self.cfgs:
            return self[prefix]

        # find a unique ident
        i = 0
        while True:
            ident = prefix + "_%d" % i
            if ident not in self.cfgs:
                break
            i += 1
        return self[ident]

    def copy(self):
        cm = CFGManager(self._kb)
        cm.cfgs = dict(map(
            lambda x: (x[0], x[1].copy()),
            self.cfgs.items()
        ))
        return cm

    def get_most_accurate(self):
        """
        :return: The most accurate CFG present in the CFGManager, or None if it does not hold any.
        """
        less_accurate_to_most_accurate = ['CFGFast', 'CFGEmulated']

        # Try to get the most accurate first, then default to the next, ... all the way down to `None`.
        # Equivalent to `self.cfgs.get(<LAST>, self.cfgs.get(<SECOND LAST>, ... self.cfgs.get(<FIRST>, None)))`.
        return reduce(
            lambda acc, cfg: self.cfgs.get(cfg, acc),
            less_accurate_to_most_accurate,
            None
        )

    #
    # Pickling
    #

    def __getstate__(self):
        return {
            '_kb': self._kb,
            'cfgs': self.cfgs,
        }

    def __setstate__(self, state):
        self._kb = state['_kb']
        self.cfgs = state['cfgs']


KnowledgeBasePlugin.register_default("cfgs", CFGManager)
