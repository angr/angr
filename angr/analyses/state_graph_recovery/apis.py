
# This file defines APIs for altering a state graph inside a binary. Some patches are defined by Patcherex.
#
#
# Do not import this file anywhere in angr by default since that would add a dependency from angr to Patcherex. Instead,
# import this file when needed::
#
#   from angr.analyses.state_graph_recovery import apis
#

from typing import Optional, Iterable

from patcherex.patches import AddCodePatch, InsertCodePatch, AddLabelPatch
from patcherex.patches import Patch

from .abstract_state import AbstractState


class AddStatePatch(Patch):
    """
    Add a new state and its corresponding logic (implemented as assembly code for now) to the state graph inside the
    binary.

    This patch is implemented as a combination of lower-level Patcherex patches.

    :ivar pred_states:  Predecessor states of this new abstract state.
    :ivar succ_states:  Successor states of this new abstract state.
    :ivar asm_code:     The assembly code that implements the logic of this new abstract state.
    """
    def __init__(self, pred_states: Iterable[AbstractState], succ_states: Optional[Iterable[AbstractState]]=None,
                 asm_code: Optional[str]=None, name: Optional[str]=None):

        super().__init__(name)

        self.pred_states = pred_states
        self.succ_states = succ_states
        self.asm_code = asm_code

    def __repr__(self):
        return "AddStatePatch"


class EditDataPatch(Patch):
    """
    Edit an existing constant value in the binary. Note that this constant value to be edited may or may not be in a
    data section. In other words, you may use
    """


class EditInstrPatch(Patch):
    """
    TODO
    """
