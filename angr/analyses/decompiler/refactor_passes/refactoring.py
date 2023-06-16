from typing import List, Tuple, Any

from ..optimization_passes.optimization_pass import SequenceOptimizationPass, OptimizationPassStage
from ..structurer_node_path import NodePath


class Refactoring(SequenceOptimizationPass):
    """
    Supports the execution of refactoring code constructs as instructed by users.
    """

    NAME = "Refactor code construct"
    DESCRIPTION = __doc__.strip()
    ARCHES = None
    PLATFORMS = None
    STAGE: int = OptimizationPassStage.AFTER_STRUCTURING

    def __init__(self, func, seq=None, refactor_vector=None, **kwargs):
        super().__init__(func, seq=seq, **kwargs)
        self._refactor_vector: List[Tuple[NodePath, Any]] = refactor_vector

        if self._refactor_vector:
            self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        seq = self.seq
        last_idx = None
        for idx, (path, refactor_config) in enumerate(self._refactor_vector):
            # locate the node
            parent_node, the_node = path.locate_node(seq)
            if the_node is None:
                r = False
            else:
                # node located. initialize a refactor pass using the configuration
                ref_type, kwargs = refactor_config
                if kwargs is None:
                    kwargs = {}
                refactor_pass = ref_type(the_node, **kwargs)
                if refactor_pass.out_node is not None:
                    r = path.replace_node(the_node, refactor_pass.out_node, root_node=seq, parent_node=parent_node)
                else:
                    r = False
            if not r:
                # abort immediately since future refactor vectors may not be valid
                last_idx = idx
                break

        if last_idx is not None:
            # remove the invalid refactoring step
            for i in range(len(self._refactor_vector) - last_idx):
                self._refactor_vector.pop(-1)

        self.out_seq = seq
