from collections import defaultdict

from archinfo.arch_arm import is_arm_arch

from ..plugin import KnowledgeBasePlugin
from .cfg_model import CFGModel


class CFGManager(KnowledgeBasePlugin):
    """
    This is the CFG manager, it manages CFGs
    """

    def __init__(self, kb):
        super().__init__(kb=kb)

        self.cfgs = {}

    def __repr__(self):
        return "<CFGManager with %d CFGs>" % len(self.cfgs)

    def __contains__(self, ident):
        return ident in self.cfgs

    def __getitem__(self, ident) -> CFGModel:
        if ident not in self.cfgs:
            if self._kb is not None and self._kb._project is not None:
                is_arm = is_arm_arch(self._kb._project.arch)
            else:
                is_arm = False
            self.cfgs[ident] = CFGModel(ident, cfg_manager=self, is_arm=is_arm)
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
        cm.cfgs = dict(map(lambda x: (x[0], x[1].copy()), self.cfgs.items()))
        return cm

    def get_most_accurate(self) -> CFGModel | None:
        """
        :return: The most accurate CFG present in the CFGManager, or None if it does not hold any.
        """
        less_accurate_to_most_accurate = ["CFGFast", "CFGEmulated"]

        sorted_cfgs_by_prefix = defaultdict(list)
        for key, cfg_model in self.cfgs.items():
            for prefix in less_accurate_to_most_accurate:
                if key.startswith(prefix):
                    the_prefix = prefix
                    break
            else:
                # not found
                continue

            sorted_cfgs_by_prefix[the_prefix].append((key, cfg_model))

        for key in reversed(less_accurate_to_most_accurate):
            if key in sorted_cfgs_by_prefix:
                lst = sorted(sorted_cfgs_by_prefix[key], key=lambda item: item[0])
                return lst[-1][-1]
        return None

    #
    # Pickling
    #

    def __getstate__(self):
        return {
            "_kb": self._kb,
            "cfgs": self.cfgs,
        }

    def __setstate__(self, state):
        self._kb = state["_kb"]
        self.cfgs = state["cfgs"]


KnowledgeBasePlugin.register_default("cfgs", CFGManager)
