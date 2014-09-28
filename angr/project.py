#!/usr/bin/env python

# pylint: disable=W0201
# pylint: disable=W0703

import os
import simuvex    # pylint: disable=F0401
import cle
import logging
import md5
import struct
from cle.idabin import IdaBin

l = logging.getLogger("angr.project")


class Project(object):    # pylint: disable=R0904,
    """ This is the main class of the Angr module
        The code in this file focuses on the usage of SimProcedures.
        Low level functions of Project are defined in ProjectBase.
    """

    def __init__(self, filename,
                 use_sim_procedures=True,
                 default_analysis_mode=None,
                 exclude_sim_procedure=lambda x: False,
                 exclude_sim_procedures=(),
                 arch=None,
                 load_options=None,
                 except_thumb_mismatch=False,
                 parallel=False):
        """
        This constructs a Project_cle object.

        Arguments:
            @filename: path to the main executable object to analyse
            @arch: optional target architecture (auto-detected otherwise)
            @exclude_sim_procedures: a list of functions to *not* wrap with
            sim_procedures

            @load_options: a dict of {binary1: {option1:val1, option2:val2 etc.}}
            e.g., {'/bin/ls':{backend:'ida', skip_libs='ld.so.2', load_libs=False}}

            See CLE's documentation for valid options.

            NOTE:
                @arch is optional, and overrides Cle's guess
                """

        if not os.path.exists(filename) or not os.path.isfile(filename):
            raise Exception("Not a valid binary file: %s" % repr(filename))

        if not default_analysis_mode:
            default_analysis_mode = 'static'

        self.irsb_cache = {}
        self.binaries = {}
        self.surveyors = []
        self.dirname = os.path.dirname(filename)
        self.filename = os.path.basename(filename)
        self.default_analysis_mode = default_analysis_mode if default_analysis_mode is not None else 'symbolic'
        self._exclude_sim_procedure = exclude_sim_procedure
        self._exclude_sim_procedures = exclude_sim_procedures
        self.exclude_all_sim_procedures = exclude_sim_procedures
        self.except_thumb_mismatch=except_thumb_mismatch
        self._parallel = parallel
        load_options = { } if load_options is None else load_options

        self._cfg = None
        self._cdg = None
        self._ddg = None

        # this is the claripy object
        # FIXME:
        # We use VSA!
        # backend_vsa = claripy.backends.BackendVSA()
        # backend_concrete = claripy.backends.BackendConcrete()
        # claripy_ = claripy.init_standalone(model_backends=[backend_concrete, backend_vsa])
        # backend_concrete.set_claripy_object(claripy_)
        # backend_vsa.set_claripy_object(claripy_)

        # This is a map from IAT addr to (SimProcedure class name, kwargs_
        self.sim_procedures = {}

        l.info("Loading binary %s", self.filename)
        l.debug("... from directory: %s", self.dirname)

        # Ld guesses the architecture, loads the binary, its dependencies and
        # performs relocations.
        #ld = cle.Ld(filename, force_ida=force_ida, load_libs=load_libs, skip_libs=skip_libs)
        if filename not in load_options:
            load_options[filename] = {}

        ld = cle.Ld(load_options)
        self.ld = ld
        self.main_binary = ld.main_bin

        if arch in simuvex.Architectures:
            self.arch = simuvex.Architectures[arch](ld.main_bin.get_vex_ir_endness())
        elif isinstance(arch, simuvex.SimArch):
            self.arch = arch
        elif arch is None:
            self.arch = simuvex.Architectures[ld.main_bin.simarch](ld.main_bin.get_vex_ir_endness())
        else:
            raise ValueError("Invalid arch specification.")

        self.min_addr = ld.min_addr()
        self.max_addr = ld.max_addr()
        self.entry = ld.main_bin.entry_point

        if use_sim_procedures == True:
            self.use_sim_procedures()

            # We need to resync memory as simprocedures have been set at the
            # level of each IDA's instance
            if self.ld.ida_main == True:
                self.ld.ida_sync_mem()

        self.vexer = VEXer(ld.memory, self.arch, use_cache=self.arch.cache_irsb)

    def exclude_sim_procedure(self, f):
        return (f in self._exclude_sim_procedures) or self._exclude_sim_procedure(f)

    def __find_sim_libraries(self):
        """ Look for libaries that we can replace with their simuvex
        simprocedures counterpart
        This function returns the list of libraries that were found in simuvex
        """
        simlibs = []

        libs = [os.path.basename(o) for o in self.ld.dependencies.keys()]
        for lib_name in libs:
            # Hack that should go somewhere else:
            if lib_name == 'libc.so.0':
                lib_name = 'libc.so.6'

            if lib_name not in simuvex.procedures.SimProcedures:
                l.debug("There are no simprocedures for library %s :(", lib_name)
            else:
                simlibs.append(lib_name)

        return simlibs

    def use_sim_procedures(self):
        """ Use simprocedures where we can """

        libs = self.__find_sim_libraries()

        unresolved = []

        for i in self.main_binary.imports.keys():
            unresolved.append(i)

        l.debug("[Resolved [R] SimProcedures]")
        for i in self.main_binary.imports.keys():
            if self.exclude_sim_procedure(i):
                l.debug("%s: SimProcedure EXCLUDED", i)
                continue

            for lib in libs:
                simfun = simuvex.procedures.SimProcedures[lib]
                if i not in simfun.keys():
                    continue
                l.debug("[R] %s:", i)
                l.debug("\t -> matching SimProcedure in %s :)", lib)
                self.set_sim_procedure(self.main_binary, lib, i, simfun[i], None)
                unresolved.remove(i)

        # What's left in imp is unresolved.
        l.debug("[Unresolved [U] SimProcedures]: using ReturnUnconstrained instead")

        for i in unresolved:
            l.debug("[U] %s", i)
            self.set_sim_procedure(self.main_binary, "stubs", i,
                                   simuvex.SimProcedures["stubs"]["ReturnUnconstrained"],
                                   None)

    def update_jmpslot_with_simprocedure(self, func_name, pseudo_addr, binary):
        """ Update a jump slot (GOT address referred to by a PLT slot) with the
        address of a simprocedure """
        self.ld.override_got_entry(func_name, pseudo_addr, binary)

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

        # TODO: move this away from Project
        # Is @binary using the IDA backend ?
        if isinstance(binary, IdaBin):
            binary.resolve_import_with(func_name, pseudo_addr)
            #binary.resolve_import_dirty(func_name, pseudo_addr)
        else:
            self.update_jmpslot_with_simprocedure(func_name, pseudo_addr, binary)

    def initial_exit(self, mode=None, options=None):
        """Creates a SimExit to the entry point."""
        return self.exit_to(self.entry, mode=mode, options=options)

    def initial_state(self, initial_prefix=None, options=None, add_options=None, remove_options=None, mode=None):
        """Creates an initial state, with stack and everything."""
        if mode is None and options is None:
            mode = self.default_analysis_mode

        memory_backer = self.ld.memory
        if add_options is not None and simuvex.o.ABSTRACT_MEMORY in add_options:
            # Adjust the memory backer when using abstract memory
            if memory_backer is not None:
                memory_backer = {'global': memory_backer}

        if self._parallel:
            add_options = (set() if add_options is None else add_options) | { simuvex.o.PARALLEL_SOLVES }

        state = self.arch.make_state(memory_backer=memory_backer,
                                    mode=mode, options=options,
                                    initial_prefix=initial_prefix,
                                    add_options=add_options, remove_options=remove_options)

        state.abiv = None
        if self.main_binary.ppc64_initial_rtoc is not None:
            state.store_reg('rtoc', self.main_binary.ppc64_initial_rtoc)
            state.abiv = 'ppc64_1'
        return state

    def exit_to(self, addr, state=None, mode=None, options=None, jumpkind=None,
                initial_prefix=None):
        """Creates a SimExit to the specified address."""
        if state is None:
            state = self.initial_state(mode=mode, options=options,
                                       initial_prefix=initial_prefix)
            if self.arch.name == 'ARM':
                try:
                    thumb = self.is_thumb_addr(addr)
                except Exception:
                    l.warning("Creating new exit in ARM binary of unknown thumbness!")
                    l.warning("Guessing thumbness based on alignment")
                    thumb = addr % 2 == 1
                finally:
                    state.store_reg('thumb', 1 if thumb else 0)

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
        are using the IDA fallback for the binary loaded at addr (which you can
        check with ld.is_ida_mapped(addr)), or have generated a cfg.
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
            thumb = state.se.any_int(state.reg_expr("thumb")) == 1

        # While we're at it, it can be interesting to check for
        # inconsistencies with IDA in case we're in IDA fallback mode...
        if self.except_thumb_mismatch == True and self.ld.is_ida_mapped(addr) == True:
            idathumb = self.is_thumb_addr(addr)
            if idathumb != thumb:
                l.warning("IDA and VEX don't agree on thumb state @%x", where.concretize())

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
        return simuvex.SimIRSB(where.state, irsb, addr=where.concretize(), whitelist=stmt_whitelist, last_stmt=last_stmt) #pylint:disable=unexpected-keyword-arg

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

    def construct_cfg(self, avoid_runs=None, simple=False, context_sensitivity_level=2):
        """ Constructs a control flow graph """
        avoid_runs = [ ] if avoid_runs is None else avoid_runs
        c = CFG(project=self, context_sensitivity_level=context_sensitivity_level)
        c.construct(self.main_binary, avoid_runs=avoid_runs, simple=simple)
        self._cfg = c
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


from .errors import AngrMemoryError, AngrExitError
from .vexer import VEXer
from .cfg import CFG
from .cdg import CDG
from .ddg import DDG
from . import surveyors
from .sliceinfo import SliceInfo
