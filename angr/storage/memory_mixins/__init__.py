from ...state_plugins.plugin import SimStatePlugin
from ...errors import SimMemoryError

"""
Feature list!

- Base features
  - endness
  - size
  - conditional store/load with fallback
- Need to be able to instrument loads/stores
- Need to be able to capture the result of address concretization
- Need to be able to capture the result of page management?
  - this one is special - it needs to change values/sizes and needs to happen after concretization
  
Mixin list:
- Name resolution [base phase]
- SAO unwrap [base phase]
- BVV conversion [base phase]
- SimInspect [base phase + mut phase]
- SimActions [base phase + mut phase]
- Address concretization [mut phase?]
- Page splitting/address space wrap
- Permission checking/segfault errors [mut phase]
- Storage
"""

class MemoryMixin(SimStatePlugin):
    def __init__(self, ident=None, endness='Iend_BE'):
        super().__init__()
        self.id = ident
        self.endness = endness

    @property
    def category(self):
        """
        Return the category of this SimMemory instance. It can be one of the three following categories: reg, mem,
        or file.
        """

        if self.id in ('reg', 'mem'):
            return self.id

        elif self.id.startswith('file'):
            return 'file'

        else:
            raise SimMemoryError('Unknown SimMemory category for memory_id "%s"' % self.id)


    def load(self, addr, **kwargs):
        pass

    def store(self, addr, data, **kwargs):
        pass

    def find(self, addr, data, **kwargs):
        pass

    def _add_constraints(self, c, add_constraints=True, condition=None, **kwargs):
        if add_constraints:
            if condition is not None:
                to_add = (c & condition) | ~condition
            else:
                to_add = c
            self.state.add_constraints(to_add)

    def _default_value(self, addr, size, name='mem', inspect=True, events=True, key=None, **kwargs):
        """
        Override this method to provide default values for a variety of edge cases and base cases.

        :param addr:    If this value is being filled to provide a default memory value, this will be its address.
                        Otherwise, None.
        :param size:    The size in bytes of the value to return
        :param name:    A descriptive identifier for the value, for if a symbol is created.

        The ``inspect``, ``events``, and ``key`` parameters are for ``state.solver.Unconstrained``, if it is used.
        """
        pass

from .actions_mixin import ActionsMixinHigh, ActionsMixinLow
