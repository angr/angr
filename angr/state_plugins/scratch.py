import logging

import claripy

from .plugin import SimStatePlugin


l = logging.getLogger(name=__name__)


class SimStateScratch(SimStatePlugin):
    """
    Implements the scratch state plugin.
    """

    def __init__(self, scratch=None):
        super().__init__()

        # info on the current run
        self.irsb = None
        self.bbl_addr = None
        self.stmt_idx = None
        self.last_ins_addr = None
        self.ins_addr = None
        self.sim_procedure = None
        self.bbl_addr_list = None
        self.stack_pointer_list = None
        self.executed_pages_set = None

        # information on exits *from* this state
        self.jumpkind = None
        self.guard = claripy.true
        self.target = None
        self.source = None
        self.exit_stmt_idx = None
        self.exit_ins_addr = None
        self.executed_block_count = 0  # the number of blocks that was executed here
        self.executed_syscall_count = 0  # the number of system calls that was executed here
        self.executed_instruction_count = -1  # the number of instructions that was executed
        self.avoidable = True

        # information on VEX temps of this IRSB
        self.temps = []
        self.tyenv = None

        # dirtied addresses, for dealing with self-modifying code
        self.dirty_addrs = set()
        self.num_insns = 0

        # pcode IR-relative jumps
        self.statement_offset = 0

        if scratch is not None:
            self.temps = list(scratch.temps)
            self.tyenv = scratch.tyenv
            self.jumpkind = scratch.jumpkind
            self.guard = scratch.guard
            self.target = scratch.target
            self.source = scratch.source
            self.exit_stmt_idx = scratch.exit_stmt_idx
            self.exit_ins_addr = scratch.exit_ins_addr
            self.executed_block_count = scratch.executed_block_count
            self.executed_syscall_count = scratch.executed_syscall_count
            self.executed_instruction_count = scratch.executed_instruction_count
            self.executed_pages_set = scratch.executed_pages_set

            self.irsb = scratch.irsb
            self.bbl_addr = scratch.bbl_addr
            self.stmt_idx = scratch.stmt_idx
            self.last_ins_addr = scratch.last_ins_addr
            self.ins_addr = scratch.ins_addr
            self.sim_procedure = scratch.sim_procedure
            self.bbl_addr_list = scratch.bbl_addr_list
            self.stack_pointer_list = scratch.stack_pointer_list

            self.statement_offset = scratch.statement_offset

        # priveleges
        self._priv_stack = [False]

    @property
    def priv(self):
        return self._priv_stack[-1]

    def push_priv(self, priv):
        self._priv_stack.append(priv)

    def pop_priv(self):
        self._priv_stack.pop()
        if len(self._priv_stack) == 0:
            raise SimValueError("Priv stack is empty")

    def set_tyenv(self, tyenv):
        self.tyenv = tyenv
        self.temps = [None] * len(tyenv.types)

    def tmp_expr(self, tmp):
        """
        Returns the Claripy expression of a VEX temp value.

        :param tmp: the number of the tmp
        :param simplify: simplify the tmp before returning it
        :returns: a Claripy expression of the tmp
        """
        self.state._inspect("tmp_read", BP_BEFORE, tmp_read_num=tmp)
        try:
            v = self.temps[tmp]
            if v is None:
                raise SimMissingTempError(
                    "VEX temp variable %d does not exist. This is usually the result of an " "incorrect slicing." % tmp
                )
        except IndexError:
            raise SimMissingTempError("Accessing a temp that is illegal in this tyenv")
        self.state._inspect("tmp_read", BP_AFTER, tmp_read_expr=v)
        return v

    # pylint:disable=unused-argument
    def store_tmp(self, tmp, content, reg_deps=None, tmp_deps=None, deps=None, **kwargs):
        """
        Stores a Claripy expression in a VEX temp value.
        If in symbolic mode, this involves adding a constraint for the tmp's symbolic variable.

        :param tmp: the number of the tmp
        :param content: a Claripy expression of the content
        :param reg_deps: the register dependencies of the content
        :param tmp_deps: the temporary value dependencies of the content
        """
        self.state._inspect("tmp_write", BP_BEFORE, tmp_write_num=tmp, tmp_write_expr=content)
        tmp = self.state._inspect_getattr("tmp_write_num", tmp)
        content = self.state._inspect_getattr("tmp_write_expr", content)

        if o.SYMBOLIC_TEMPS not in self.state.options:
            # Non-symbolic
            self.temps[tmp] = content
        else:
            # Symbolic
            self.state.add_constraints(self.temps[tmp] == content)

        # get the size, and record the write
        if o.TRACK_TMP_ACTIONS in self.state.options:
            data_ao = SimActionObject(content, reg_deps=reg_deps, tmp_deps=tmp_deps, deps=deps, state=self.state)
            r = SimActionData(
                self.state, SimActionData.TMP, SimActionData.WRITE, tmp=tmp, data=data_ao, size=content.length
            )
            self.state.history.add_action(r)

        self.state._inspect("tmp_write", BP_AFTER)

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        return SimStateScratch(scratch=self)

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=unused-argument
        return False

    def widen(self, others):  # pylint: disable=unused-argument
        return False

    def clear(self):
        s = self.state
        j = self.jumpkind
        self.__init__()
        self.state = s
        self.jumpkind = j  # preserve jumpkind - "what is the previous jumpkind" is an important question sometimes


# pylint:disable=wrong-import-position
from .sim_action import SimActionObject, SimActionData
from ..errors import SimValueError, SimMissingTempError
from .. import sim_options as o
from .inspect import BP_AFTER, BP_BEFORE

from ..sim_state import SimState

SimState.register_default("scratch", SimStateScratch)
