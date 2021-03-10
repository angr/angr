
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


#
# Patches
#


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
    Edit an existing constant value in the binary. Note that the constant value to be edited may or may not be in a
    data section. In other words, you may use EditDataPatch to directly edit bytes anywhere in the binary.

    If old_data is specified, it will be used to check against existing data before applying this patch. The patch will
    not be applied if existing data does not match old_data.

    Example: Changing the 4-byte chunk at 0x83200 from 04 00 00 00 to 13 37 00 00

        0x83200    04 00 00 00

        p = EditDataPatch(0x83200, b"\x13\x37\x00\x00", old_data=b"\x04\x00\x00\x00")

    After applying this patch::

        0x83200    13 37 00 00
    """
    def __init__(self, addr: int, data: bytes, old_data: Optional[bytes]=None, name: Optional[str]=None):
        super().__init__(name)
        self.addr = addr
        self.data = data
        self.old_data = old_data


class EditInstrPatch(Patch):
    """
    Edit an existing instruction in the binary. Note that this patch is not always applicable.

    For now, the following edits are supported.

    - Changing comparison operators: (signed to unsigned, unsigned to signed, less than to greater than, less than or
      equal to to greater than or equal to, etc.)
    - Nopping instructions.
    """
    def __init__(self, addr: int, new_instr: str, name: Optional[str]=None):
        super().__init__(name)
        self.addr = addr
        self.new_instr = new_instr


#
# Root cause diagnosis
#


class CauseBase:
    """
    This is the base class for all possible root causes.
    """
    pass


class DataItemCause(CauseBase):
    """
    Describes root causes that only involve a single data item in the original binary.

    For example, in the following piece of program,

    int a = 20000;  // line 1
    sleep(a):  // line 2

    The root cause of "sleeping for *20,000* seconds" is the integer 20,000 that is involved at line 1. For
    architectures like ARM and MIPS, large integers are almost always directly loaded from memory. In these scenarios,
    it can be captured by a DataItemCause instance.
    """
    def __init__(self, addr: int, data_type: str, data_size: int):
        self.addr = addr
        self.data_type = data_type
        self.data_size = data_size


class InstrOperandCause(CauseBase):
    """
    Describes root causes that only involve an instruction operand.

    For example, in the following piece of program,

    int a = 2; // line 1
    sleep(a); // line 2

    The root cause of "sleeping for *2* seconds" is the integer 2 that is involved at line 1. If this integer is
    directly used in an instruction, the cause can be captured by an InstrOperandCause instance.
    """
    def __init__(self, addr: int, operand_idx: int, old_value: int):
        self.addr = addr
        self.operand_idx = operand_idx
        self.old_value = old_value


class InstrOpcodeCause(CauseBase):
    """
    Describes root causes that only involve an instruction opcode or operator.

    For example, in the following piece of program,

    int a = b + 2; // line 1
    sleep(a); // line 2

    The root cause of "sleeping for *b + 2* seconds" involves the add operator. If this addition operation is
    implemented as an instruction, such as _add r0, r0, 2_, then InstrOpcodeCause will be able to capture it.
    """
    def __init__(self, addr: int, operator: str, old_value: str):
        self.addr = addr
        self.operator = operator
        self.old_value = old_value
