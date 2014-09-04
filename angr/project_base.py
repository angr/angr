#!/usr/bin/env python

import simuvex
import logging
import claripy
import pdb
# pylint: disable=W0201
# pylint: disable=W0703

l = logging.getLogger("angr.project")


class ProjectBase(object):
    """ This class is the base of the Project class.
        It contains all the low level stuff, such as calls to CFG generation
        and getting the inital state.
    """

    def initial_exit(self, mode=None, options=None):
        """Creates a SimExit to the entry point."""
        return self.exit_to(self.entry, mode=mode, options=options)

    def initial_state(self, initial_prefix=None, options=None, mode=None):
        """Creates an initial state, with stack and everything."""
        if mode is None and options is None:
            mode = self.default_analysis_mode

        return self.arch.make_state(claripy.claripy, memory_backer=self.ld.memory,
                                    mode=mode, options=options,
                                    initial_prefix=initial_prefix)

    def exit_to(self, addr, state=None, mode=None, options=None, jumpkind=None,
                initial_prefix=None):
        """Creates a SimExit to the specified address."""
        if state is None:
            state = self.initial_state(mode=mode, options=options,
                                       initial_prefix=initial_prefix)
        return simuvex.SimExit(addr=addr, state=state, jumpkind=jumpkind)

    def block(self, addr, max_size=None, num_inst=None, traceflags=0, thumb=False):
        """
        Returns a pyvex block starting at address addr

        Optional params:

        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param traceflags: traceflags to be passed to VEX. Default: 0
        @thumb: bool: this block is in thumb mode (ARM)
        """
        return self.vexer.block(addr, max_size=max_size, num_inst=num_inst,
                                traceflags=traceflags, thumb=thumb)

    def is_thumb_addr(self, addr):
        """ Don't call this for anything else than the entry point, unless you
        are using the IDA fallback (force_ida = True), or have generated a cfg.
        CLE doesn't know about thumb mode.
        """
        if self.arch.name != 'ARM':
            return False

        if self._cfg is not None:
            return self._cfg.is_thumb_addr(addr)

        # What binary is that ?
        obj = self.binary_by_addr(addr)
        if obj is None:
            raise AngrMemoryError("Cannot check for thumb mode at 0x%x" % addr)

        return obj.is_thumb(addr)

    def is_thumb_state(self, where):
        """  Runtime thumb mode detection.
            Given a SimRun @where, this tells us whether it is in Thumb mode
        """

        if self.arch.name != 'ARM':
            return False

        state = where.state
        addr = where.concretize()
        # If the address is the entry point, the state won't know if it's thumb
        # or not, let's ask CLE
        if addr == self.entry:
            thumb = self.is_thumb_addr(addr)
        else:
            thumb = state.reg_expr("thumb").eval().value == 1

        # While we're at it, it can be interesting to check for
        # inconsistencies with IDA in case we're in IDA fallback mode...
        if (self.except_thumb_mismatch == True and self.force_ida == True):
            idathumb = self.is_thumb_addr(addr)
            if idathumb != thumb:
                raise Exception("IDA and VEX don't agree on thumb state @%x" %
                                where.concretize())
        return thumb == 1

    def sim_block(self, where, max_size=None, num_inst=None,
                  stmt_whitelist=None, last_stmt=None):
        """
        Returns a simuvex block starting at SimExit 'where'

        Optional params:

        @param where: the exit to start the analysis at
        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param state: the initial state. Fully unconstrained if None

        """
        thumb = self.is_thumb_state(where)
        irsb = self.block(where.concretize(), max_size, num_inst, thumb=thumb)
        return simuvex.SimIRSB(where.state, irsb, addr=where.concretize(),
                               whitelist=stmt_whitelist, last_stmt=last_stmt)

    def sim_run(self, where, max_size=400, num_inst=None, stmt_whitelist=None,
                last_stmt=None):
        """
        Returns a simuvex SimRun object (supporting refs() and
        exits()), automatically choosing whether to create a SimIRSB or
        a SimProcedure.

        Parameters:
        @param where : the exit to analyze
        @param max_size : the maximum size of the block, in bytes
        @param num_inst : the maximum number of instructions
        @param state : the initial state. Fully unconstrained if None
        """

        if where.is_error:
            raise AngrExitError("Provided exit of jumpkind %s is in an error "
                                "state." % where.jumpkind)

        addr = where.concretize()
        state = where.state

        if addr % state.arch.instruction_alignment != 0:
            if self.is_thumb_state(where) and addr % 2 == 1:
                pass
            #where.set_expr_exit(where.target-1, where.source, where.state, where.guard)
            else:
                raise AngrExitError("Address 0x%x does not align to alignment %d "
                                    "for architecture %s." % (addr,
                                    state.arch.instruction_alignment,
                                    state.arch.name))

        if where.is_syscall:
            l.debug("Invoking system call handler (originally at 0x%x)", addr)
            return simuvex.SimProcedures['syscalls']['handler'](state, addr=addr)
        if self.is_sim_procedure(addr):
            sim_proc_class, kwargs = self.sim_procedures[addr]
            l.debug("Creating SimProcedure %s (originally at 0x%x)",
                    sim_proc_class.__name__, addr)
            return sim_proc_class(state, addr=addr, **kwargs)
        else:
            l.debug("Creating SimIRSB at 0x%x", addr)
            return self.sim_block(where, max_size=max_size, num_inst=num_inst,
                                  stmt_whitelist=stmt_whitelist,
                                  last_stmt=last_stmt)

    def binary_by_addr(self, addr):
        """ This returns the binary containing address @addr"""
        return self.ld.addr_belongs_to_object(addr)

    def construct_cfg(self, avoid_runs=None):
        """ Constructs a control flow graph """
        avoid_runs = [ ] if avoid_runs is None else avoid_runs
        c = CFG()
        c.construct(self.main_binary, self, avoid_runs=avoid_runs)
        self.__cfg = c
        return c

    def construct_cdg(self, avoid_runs=None):
        if self._cfg is None: self.construct_cfg(avoid_runs=avoid_runs)

        c = CDG(self.main_binary, self, self._cfg)
        c.construct()
        self._cdg = c
        return c

    def construct_ddg(self, avoid_runs=None):
        if self._cfg is None: self.construct_cfg(avoid_runs=avoid_runs)

        d = DDG(self, self._cfg, self.entry)
        d.construct()
        self._ddg = d
        return d

    def slice_to(self, addr, start_addr=None, stmt=None, avoid_runs=None):
        if self._cfg is None: self.construct_cfg(avoid_runs=avoid_runs)
        if self._cdg is None: self.construct_cdg(avoid_runs=avoid_runs)
        if self._ddg is None: self.construct_ddg(avoid_runs=avoid_runs)

        s = SliceInfo(self.main_binary, self, self._cfg, self._cdg, self._ddg)
        target_irsb = self._cfg.get_any_irsb(addr)
        target_stmt = -1 if stmt is None else stmt
        s.construct(target_irsb, target_stmt)
        return s.annotated_cfg(addr, start_point=start_addr, target_stmt=stmt)


    def survey(self, surveyor_name, *args, **kwargs):
        s = surveyors.all_surveyors[surveyor_name](self, *args, **kwargs)
        self.surveyors.append(s)
        return s


#from .memory_dict import MemoryDict
from .errors import AngrMemoryError, AngrExitError
#from .vexer import VEXer
from .cfg import CFG
from .cdg import CDG
from .ddg import DDG
from . import surveyors
from .sliceinfo import SliceInfo
#from .project_cle import Project_cle
