
# This file defines APIs for altering a state graph inside a binary. Some patches are defined by Patcherex.
#
#
# Do not import this file anywhere in angr by default since that would add a dependency from angr to Patcherex. Instead,
# import this file when needed::
#
#   from angr.analyses.state_graph_recovery import apis
#

import struct
from typing import List, Optional, Iterable, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    import angr

_l = logging.getLogger(name=__name__)

try:
    from patcherex.patches import AddCodePatch, InsertCodePatch, AddLabelPatch
    from patcherex.patches import Patch
    from patcherex.backends.detourbackend import DetourBackend
except ImportError:
    _l.warning("Cannot import Patcherex. You will not be able to apply patches.")

    # dummy patch base class
    class Patch:
        def __init__(self, name):
            self.name = name

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
    def __init__(self, addr: int, data_type: str, data_size: int, name: Optional[str]=None):
        self.addr = addr
        self.data_type = data_type
        self.data_size = data_size
        self.name = name

    def __repr__(self):
        return f"<DataItemCause: {self.data_type}@{self.addr:#x}[{self.data_size} bytes]%s>" % (
            self.name if self.name else "")

    def __eq__(self, other):
        if not isinstance(other, DataItemCause):
            return False
        return self.addr == other.addr and \
            self.data_type == other.data_type and \
            self.data_size == other.data_size and \
            self.name == other.name

    def __hash__(self):
        return hash((self.addr, self.data_type, self.data_size, self.name))

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

    def __repr__(self):
        return f"<InstrOperandCause {self.addr:#x} operand {self.operand_idx}:{self.old_value}>"

    def __eq__(self, other):
        if not isinstance(other, InstrOperandCause):
            return False
        return self.addr == other.addr and self.operand_idx == other.operand_idx and self.old_value == other.old_value

    def __hash__(self):
        return hash((self.addr, self.operand_idx, self.old_value))


class InstrOpcodeCause(CauseBase):
    """
    Describes root causes that only involve an instruction opcode or operator.

    For example, in the following piece of program,

    int a = b + 2; // line 1
    sleep(a); // line 2

    The root cause of "sleeping for *b + 2* seconds" involves the add operator. If this addition operation is
    implemented as an instruction, such as _add r0, r0, 2_, then InstrOpcodeCause will be able to capture it.
    """
    def __init__(self, addr: int, operator):
        self.addr = addr
        self.operator = operator

    def __repr__(self):
        return f"<InstrOpcodeCause {self.addr:#x} opcode {self.operator}>"

    def __eq__(self, other):
        if not isinstance(other, InstrOpcodeCause):
            return False
        return self.addr == other.addr and self.operator == other.operator

    def __hash__(self):
        return hash((self.addr, self.operator))

#
# Interaction
#

def generate_patch(arch, causes: List[CauseBase]) -> Optional[Patch]:
    # patches
    idx = input("[?] Which root cause do you want to mitigate? (%d - %d) " % (0, len(causes) - 1))
    try:
        idx = int(idx)
    except (ValueError, TypeError):
        print("[-] Invalid ID. Continue.")
        return
    if 0 <= idx < len(causes):
        cause = causes[idx]
        # Generate patch based on user input and cause type
        if isinstance(cause, DataItemCause):
            new_value = input("[?] New value:")
            endness_prefix = "<" if arch.memory_endness == "Iend_LE" else ">"

            # encode the value as required
            if cause.data_type == "int":
                new_data = struct.pack(f"{endness_prefix}I", int(new_value))
            elif cause.data_type == "float":
                new_data = struct.pack(f"{endness_prefix}f", float(new_value))
            elif cause.data_type == "double":
                new_data = struct.pack(f"{endness_prefix}d", float(new_value))
            else:
                raise RuntimeError(f"Unsupported data type {cause.data_type}")

            patch = EditDataPatch(cause.addr, new_data)
            return patch

    return None


def apply_patch_on_state(patch: Patch, state: 'angr.SimState'):
    if isinstance(patch, EditDataPatch):
        state.memory.store(patch.addr, patch.data, endness='Iend_BE')
    else:
        raise NotImplementedError("Do not support other types of patches yet.")


def apply_patch(patch: Patch, file_path: str, output_path: str, proj: 'angr.Project', start_addr: int) -> None:
    if isinstance(patch, EditDataPatch):
        # create a patch that uses ptrace to overwrite the target address in memory
        prolog = """
import sys
import ptrace.debugger

def get_library_base(pid: int, library_name: str):
    with open(f"/proc/{pid}/maps", "r") as f:
        lines = f.read().split("\\n")
        for line in lines:
            if library_name in line:
                items = line.split(" ")
                base_addr = items[0][:items[0].index("-")]
                base_addr = int(base_addr, 16)
                return base_addr
    return None


pid = int(sys.argv[1])
library_name = "/tmp/"

lib_base_addr = get_library_base(pid, library_name)
debugger = ptrace.debugger.PtraceDebugger()
process = debugger.addProcess(pid, False)
"""
        epilog = """
process.detach()
        """
        overwrite_one_byte = "process.writeBytes(lib_base_addr + %#x, b\"\\x%02x\")"

        py_code = prolog + "\n"
        for pos, byt in enumerate(patch.data):
            py_code += overwrite_one_byte % (
                patch.addr - proj.loader.main_object.mapped_base + pos,
                byt,
            )
            py_code += "\n"
        py_code += epilog + "\n"

        with open(output_path, "w") as f:
            f.write(py_code)

        return

        # create a patch to overwrite the address with the data we want
        backend = DetourBackend(file_path)
        # TODO: Support ASLR
        if proj.arch.name == "AMD64":
            prolog = "push rdi"
            overwrite_one_byte = """
            mov rdi, %#x
            mov BYTE [rdi], %#x
            """
            epilog = "pop rdi"
        else:
            raise RuntimeError("Unsupported architecture %s." % proj.arch.name)

        asm_code = prolog + "\n"
        base_addr = 0x400000  # FIXME: Adjust this address based on the base address of the executable on PLC devices
        for pos, byt in enumerate(patch.data):
            asm_code += overwrite_one_byte % (
                base_addr + patch.addr - proj.loader.main_object.mapped_base + pos,
                byt,
            )
            asm_code += "\n"
        asm_code += epilog
        new_patch = InsertCodePatch(start_addr, asm_code)
        backend.apply_patches([new_patch])
        backend.save(output_path)

        return

        # convert memory address to file offset
        section = proj.loader.find_section_containing(patch.addr)
        if section is None:
            # TODO: Support section-less binaries
            raise RuntimeError(f"Cannot find the section containing the address {patch.addr:#x}")

        fileaddr = section.offset + (patch.addr - section.vaddr)

        if not 0 <= fileaddr < len(raw_binary):
            raise RuntimeError(f"Calculated fileaddr {fileaddr} is out of bound.")

        # apply the patch
        binary = raw_binary[:fileaddr] + patch.data + raw_binary[fileaddr + len(patch.data):]
        return binary

    return None
