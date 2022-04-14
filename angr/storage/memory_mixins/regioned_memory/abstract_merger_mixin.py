import logging
from typing import Iterable, Tuple, Any

from .. import MemoryMixin

l = logging.getLogger(name=__name__)


class AbstractMergerMixin(MemoryMixin):

    def _merge_values(self, values: Iterable[Tuple[Any,Any]], merged_size: int, **kwargs):

        # if self.category == 'reg' and self.state.arch.register_endness == 'Iend_LE':
        #     should_reverse = True
        # elif self.state.arch.memory_endness == 'Iend_LE':
        #     should_reverse = True
        # else:
        #     should_reverse = False

        values = list(values)
        merged_val = values[0][0]

        # if should_reverse: merged_val = merged_val.reversed

        for tm, _ in values[1:]:
            # if should_reverse: tm = tm.reversed

            if self._is_uninitialized(tm):
                continue
            l.info("Merging %s %s...", merged_val, tm)
            merged_val = merged_val.union(tm)
            l.info("... Merged to %s", merged_val)

        # if should_reverse:
        #     merged_val = merged_val.reversed

        if not values[0][0].uninitialized and self.state.solver.backends.vsa.identical(merged_val, values[0][0]):
            return None

        return merged_val

    @staticmethod
    def _is_uninitialized(a):
        return getattr(a._model_vsa, 'uninitialized', False)
