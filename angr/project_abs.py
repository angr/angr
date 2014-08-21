#!/usr/bin/env python

import simuvex
import logging
import angr
import claripy
import md5
import struct
# pylint: disable=W0201
# pylint: disable=W0703

l = logging.getLogger("angr.project")


class AbsProject(object):
    """ This class contains all the stuff in common between Project_cle and
    project_ida """

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

    def block(self, addr, max_size=None, num_inst=None, traceflags=0):
        """
        Returns a pyvex block starting at address addr

        Optional params:

        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param traceflags: traceflags to be passed to VEX. Default: 0
        """
        return self.vexer.block(addr, max_size=max_size, num_inst=num_inst,
                                traceflags=traceflags, thumb=self.is_thumb(addr))

    def is_thumb(self, addr):
        if self.arch.name != 'ARM':
            return False
        if self.binary_by_addr(addr) is None:
            raise AngrMemoryError("No IDA to check thumb mode at 0x%x." % addr)
        return self.binary_by_addr(addr).ida.idc.GetReg(addr, "T") == 1


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
        irsb = self.block(where.concretize(), max_size, num_inst)
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
            if self.is_thumb(addr) and addr % 2 == 1:
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

    def add_custom_sim_procedure(self, address, sim_proc, kwargs):
        '''
        Link a SimProcedure class to a specified address.
        '''
        if address in self.sim_procedures:
            l.warning("Address 0x%08x is already in SimProcedure dict.", address)
            return
        if kwargs is None: kwargs = {}
        self.sim_procedures[address] = (sim_proc, kwargs)

    def is_sim_procedure(self, hashed_addr):
        return hashed_addr in self.sim_procedures

    def get_pseudo_addr_for_sim_procedure(self, s_proc):
        for addr, tpl in self.sim_procedures.items():
            simproc_class, _ = tpl
            if isinstance(s_proc, simproc_class):
                return addr
        return None

    def set_sim_procedure(self, binary, lib, func_name, sim_proc, kwargs):
        """
         This method differs from Project_ida's one with same name

         Generate a hashed address for this function, which is used for
         indexing the abstract function later.
         This is so hackish, but thanks to the fucking constraints, we have no
         better way to handle this
        """
        m = md5.md5()
        m.update(lib + "_" + func_name)

        # TODO: update addr length according to different system arch
        hashed_bytes = m.digest()[:self.arch.bits/8]
        pseudo_addr = (struct.unpack(self.arch.struct_fmt, hashed_bytes)[0] / 4) * 4

        # Put it in our dict
        if kwargs is None: kwargs = {}
        if (pseudo_addr in self.sim_procedures) and \
                            (self.sim_procedures[pseudo_addr][0] != sim_proc):
            l.warning("Address 0x%08x is already in SimProcedure dict.", pseudo_addr)
            return

        self.sim_procedures[pseudo_addr] = (sim_proc, kwargs)
        l.debug("\t -> setting SimProcedure with pseudo_addr 0x%x...", pseudo_addr)

        if self.force_ida == True:
            binary.resolve_import_dirty(func_name, pseudo_addr)
        else:
            self.update_jmpslot_with_simprocedure(func_name, pseudo_addr, binary)

    def construct_cfg(self, avoid_runs=None):
        """ Constructs a control flow graph """
        avoid_runs = [ ] if avoid_runs is None else avoid_runs
        c = CFG()
        c.construct(self.main_binary, self, avoid_runs=avoid_runs)
        return c

    def survey(self, surveyor_name, *args, **kwargs):
        s = surveyors.all_surveyors[surveyor_name](self, *args, **kwargs)
        self.surveyors.append(s)
        return s


#from .binary import Binary
#from .memory_dict import MemoryDict
from .errors import AngrMemoryError, AngrExitError
#from .vexer import VEXer
from .cfg import CFG
from . import surveyors
#from .project_cle import Project_cle
#from .project_ida import Project_ida
