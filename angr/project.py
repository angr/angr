#!/usr/bin/env python

# pylint: disable=W0703

import os
import md5
import types
import struct
import logging

import cle
import simuvex

l = logging.getLogger("angr.project")

projects = { }
def fake_project_unpickler(name):
    if name not in projects:
        raise AngrError("Project %s has not been opened." % name)
    return projects[name]
fake_project_unpickler.__safe_for_unpickling__ = True

def deprecated(f):
    def deprecated_wrapper(*args, **kwargs):
        print "ERROR: FUNCTION %s IS DEPRECATED. PLEASE UPDATE YOUR CODE." % f
        return f(*args, **kwargs)
    return deprecated_wrapper

class Project(object):
    """
    This is the main class of the Angr module. It is meant to contain a set of
    binaries and the relationships between them, and perform analyses on them.
    """

    def __init__(self, filename,
                 use_sim_procedures=True,
                 default_analysis_mode=None,
                 exclude_sim_procedure=None,
                 exclude_sim_procedures=(),
                 arch=None,
                 load_options=None,
                 except_thumb_mismatch=False,
                 parallel=False, ignore_functions=None,
                 argv=None, envp=None, symbolic_argc=None):
        """
        This constructs a Project object.

        Arguments:
            @filename: path to the main executable object to analyse
            @arch: optional target architecture (auto-detected otherwise)
            in the form of a simuvex.SimState or a string
            @exclude_sim_procedures: a list of functions to *not* wrap with
            simprocedures
            @exclude_sim_procedure: a function that, when passed a function
            name, returns whether or not to wrap it with a simprocedure

            @load_options: a dict of {binary1: {option1:val1, option2:val2 etc.}}
            e.g., {'/bin/ls':{backend:'ida', skip_libs='ld.so.2', auto_load_libs=False}}

            See CLE's documentation for valid options.
        """

        if isinstance(exclude_sim_procedure, types.LambdaType):
            l.warning("Passing a lambda type as the exclude_sim_procedure argument to Project causes the resulting object to be un-serializable.")

        if not os.path.exists(filename) or not os.path.isfile(filename):
            raise Exception("Not a valid binary file: %s" % repr(filename))

        if not default_analysis_mode:
            default_analysis_mode = 'symbolic'

        self.irsb_cache = {}
        self.binaries = {}
        self.dirname = os.path.dirname(filename)
        self.basename = os.path.basename(filename)
        self.filename = filename
        projects[filename] = self

        self.default_analysis_mode = default_analysis_mode if default_analysis_mode is not None else 'symbolic'
        self._exclude_sim_procedure = exclude_sim_procedure
        self._exclude_sim_procedures = exclude_sim_procedures
        self.exclude_all_sim_procedures = exclude_sim_procedures
        self.except_thumb_mismatch=except_thumb_mismatch
        self._parallel = parallel
        self.load_options = { } if load_options is None else load_options

        # List of functions we don't want to step into (and want
        # ReturnUnconstrained() instead)
        self.ignore_functions = [] if ignore_functions is None else ignore_functions

        self._cfg = None
        self._vfg = None
        self._cdg = None
        self._analysis_results = { }
        self.results = AnalysisResults(self)

        self.analyses = Analyses(self, self._analysis_results)
        self.surveyors = Surveyors(self, surveyors.all_surveyors)

        # This is a map from IAT addr to (SimProcedure class name, kwargs_)
        self.sim_procedures = {}

        l.info("Loading binary %s", self.filename)
        l.debug("... from directory: %s", self.dirname)

        # ld is angr's loader, provided by cle
        self.ld = cle.Ld(filename, self.load_options)
        self.main_binary = self.ld.main_bin

        if arch in simuvex.Architectures:
            self.arch = simuvex.Architectures[arch](self.ld.main_bin.get_vex_ir_endness())
        elif isinstance(arch, simuvex.SimArch):
            self.arch = arch
        elif arch is None:
            self.arch = simuvex.Architectures[self.ld.main_bin.simarch](self.ld.main_bin.get_vex_ir_endness())
        else:
            raise ValueError("Invalid arch specification.")

        self.min_addr = self.ld.min_addr()
        self.max_addr = self.ld.max_addr()
        self.entry = self.ld.main_bin.entry_point

        if use_sim_procedures == True:
            self.use_sim_procedures()

            # We need to resync memory as simprocedures have been set at the
            # level of each IDA's instance
            if self.ld.ida_main == True:
                self.ld.ida_sync_mem()

        self.vexer = VEXer(self.ld.memory, self.arch, use_cache=self.arch.cache_irsb)
        self.capper = Capper(self.ld.memory, self.arch, use_cache=True)

        # command line arguments, environment variables, etc
        self.argv = argv if argv is not None else ['./' + self.basename]
        self.envp = envp if envp is not None else {}
        self.symbolic_argc = symbolic_argc

    #
    # Pickling
    #

    def __getstate__(self):
        try:
            vexer, capper, ld, main_bin = self.vexer, self.capper, self.ld, self.main_binary
            self.vexer, self.capper, self.ld, self.main_binary = None, None, None, None
            return dict(self.__dict__)
        finally:
            self.vexer, self.capper, self.ld, self.main_binary = vexer, capper, ld, main_bin

    def __setstate__(self, s):
        self.__dict__.update(s)
        self.ld = cle.Ld(self.filename, self.load_options)
        self.main_binary = self.ld.main_bin
        self.vexer = VEXer(self.ld.memory, self.arch, use_cache=self.arch.cache_irsb)
        self.capper = Capper(self.ld.memory, self.arch, use_cache=True)

    #
    # Project stuff
    #

    def exclude_sim_procedure(self, f):
        return (f in self._exclude_sim_procedures) or (self._exclude_sim_procedure is not None and self._exclude_sim_procedure(f))

    def __find_sim_libraries(self):
        """ Look for libaries that we can replace with their simuvex
        simprocedures counterpart
        This function returns the list of libraries that were found in simuvex
        """
        simlibs = []

        auto_libs = [os.path.basename(o) for o in self.ld.dependencies.keys()]
        custom_libs = [os.path.basename(o) for o in self.ld._custom_dependencies.keys()]

        libs = set(auto_libs + custom_libs + self.ld._get_static_deps(self.main_binary))

        for lib_name in libs:
            # Hack that should go somewhere else:
            if lib_name == 'libc.so.0':
                lib_name = 'libc.so.6'

            if lib_name == 'ld-uClibc.so.0':
                lib_name = 'ld-uClibc.so.6'

            if lib_name not in simuvex.procedures.SimProcedures:
                l.debug("There are no simprocedures for library %s :(", lib_name)
            else:
                simlibs.append(lib_name)

        return simlibs

    def use_sim_procedures(self):
        """ Use simprocedures where we can """

        libs = self.__find_sim_libraries()
        unresolved = []

        functions = self.main_binary.imports

        for i in functions:
            unresolved.append(i)

        l.debug("[Resolved [R] SimProcedures]")
        for i in functions:
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
            # Where we cannot use SimProcedures, we step into the function's
            # code (if you don't want this behavior, use 'auto_load_libs':False
            # in load_options)
            if i in self.main_binary.resolved_imports and i not in self.ignore_functions:
                continue
            l.debug("[U] %s", i)
            self.set_sim_procedure(self.main_binary, "stubs", i,
                                   simuvex.SimProcedures["stubs"]["ReturnUnconstrained"],
                                   {'resolves':i})

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

        # Special case for __libc_start_main - it needs to call exit() at the end of execution
        # TODO: Is there any more elegant way of doing this?
        if func_name == '__libc_start_main':
            if 'exit_addr' not in kwargs:
                m = md5.md5()
                m.update('__libc_start_main:exit')
                hashed_bytes_ = m.digest()[ : self.arch.bits / 8]
                pseudo_addr_ = (struct.unpack(self.arch.struct_fmt, hashed_bytes_)[0] / 4) * 4
                self.sim_procedures[pseudo_addr_] = (simuvex.procedures.SimProcedures['libc.so.6']['exit'], {})
                kwargs['exit_addr'] = pseudo_addr_

        self.sim_procedures[pseudo_addr] = (sim_proc, kwargs)
        l.debug("\t -> setting SimProcedure with pseudo_addr 0x%x...", pseudo_addr)

        # TODO: move this away from Project
        # Is @binary using the IDA backend ?
        if isinstance(binary, cle.IdaBin):
            binary.resolve_import_with(func_name, pseudo_addr)
            #binary.resolve_import_dirty(func_name, pseudo_addr)
        else:
            self.update_jmpslot_with_simprocedure(func_name, pseudo_addr, binary)

    def initial_exit(self, mode=None, options=None):
        """Creates a SimExit to the entry point."""
        return self.exit_to(self.entry, mode=mode, options=options)

    def initial_state(self, initial_prefix=None, options=None, add_options=None, remove_options=None, mode=None, argv=None, envp=None, sargc=None):
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

        # Command line arguments and environment variables
        args = argv if argv is not None else self.argv
        envs = envp if envp is not None else self.envp

        state = self.arch.make_state(memory_backer=memory_backer,
                                    mode=mode, options=options,
                                    initial_prefix=initial_prefix,
                                    add_options=add_options, remove_options=remove_options)

        if (args is not None) and (envs is not None):
            sp = state.sp_expr()
            envs = ["%s=%s"%(x[0], x[1]) for x in envs.iteritems()]
            if sargc:
                argc = state.se.Unconstrained("argc", state.arch.bits)
            else:
                argc = state.BVV(len(args), state.arch.bits)

            envl = state.BVV(len(envs), state.arch.bits)
            strtab = state.make_string_table([args, envs], [argc, envl], sp)

            # store argc argv envp in posix stuff
            state['posix'].argv = strtab
            state['posix'].argc = argc
            state['posix'].environ = strtab + ((len(args) + 1) * (state.arch.bits / 8))

            # put argc on stack and fixup the stack pointer
            newsp = strtab - (state.arch.bits / 8)
            state.store_mem(newsp, argc, endness=state.arch.memory_endness)
            state.store_reg(state.arch.sp_offset, newsp, endness=state.arch.register_endness)

        state.abiv = None
        if self.main_binary.ppc64_initial_rtoc is not None:
            state.store_reg('rtoc', self.main_binary.ppc64_initial_rtoc, endness=state.arch.register_endness)
            state.abiv = 'ppc64_1'
        # MIPS initialization
        if self.arch.name == 'MIPS32':
            state.store_reg('ra', 0)
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
        check with ld.addr_is_ida_mapped(addr)), or have generated a cfg.
        CLE doesn't know about thumb mode.

        Given an address @addr, returns whether that address is in THUMB mode.

        This is a tricky problem due to the fact that any address can be
        THUMB or not depending on the runtime context, so do not call this
        function unless one of the following are true:
        - The address is the entry point
        - You are using the IDA fallback
        - You have run a CFG analysis already
        """
        if self.arch.name != 'ARM':
            return False

        if self.analyzed('CFG'):
            return self.analyses.CFG().is_thumb_addr(addr)

        # What binary is that ?
        obj = self.binary_by_addr(addr)
        if obj is None:
            raise AngrMemoryError("Cannot check for thumb mode at 0x%x" % addr)

        return obj.is_thumb(addr)

    def is_thumb_state(self, where):
        """
        Runtime thumb mode detection.
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
        if self.except_thumb_mismatch == True and self.ld.addr_is_ida_mapped(addr) == True:
            idathumb = self.is_thumb_addr(addr)
            if idathumb != thumb:
                l.warning("IDA and VEX don't agree on thumb state @%x", where.concretize())

        return thumb == 1

    def sim_block(self, where, max_size=None, num_inst=None,
                  stmt_whitelist=None, last_stmt=None):
        """
        Returns a simuvex block starting at SimExit @where

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
            r = simuvex.SimProcedures['syscalls']['handler'](state, addr=addr)
        elif self.is_sim_procedure(addr):
            sim_proc_class, kwargs = self.sim_procedures[addr]
            l.debug("Creating SimProcedure %s (originally at 0x%x)",
                    sim_proc_class.__name__, addr)
            r = sim_proc_class(state, addr=addr, sim_kwargs=kwargs)
            l.debug("... %s created", r)
        else:
            l.debug("Creating SimIRSB at 0x%x", addr)
            r = self.sim_block(where, max_size=max_size, num_inst=num_inst,
                                  stmt_whitelist=stmt_whitelist,
                                  last_stmt=last_stmt)

        return r

    def binary_by_addr(self, addr):
        """ This returns the binary containing address @addr"""
        return self.ld.addr_belongs_to_object(addr)

    #
    # Deprecated analysis styles
    #

    @deprecated
    def slice_to(self, addr, stmt_idx=None, start_addr=None, cfg_only=True):
        """
        Create a program slice from @start_addr to @addr
        Note that @add must be a valid IRSB in the CFG
        """

        cfg = self.analyze('CFG')
        cdg = self.analyze('CDG')

        s = SliceInfo(self.main_binary, self, cfg, cdg, None)
        target_irsb = self._cfg.get_any_irsb(addr)

        if target_irsb is None:
            raise AngrExitError("The CFG doesn't contain any IRSB starting at "
                                "0x%x" % addr)


        target_stmt = -1 if stmt_idx is None else stmt_idx
        s.construct(target_irsb, target_stmt, control_flow_slice=cfg_only)
        return s.annotated_cfg(addr, start_point=start_addr, target_stmt=target_stmt)

    @deprecated
    def survey(self, surveyor_name, *args, **kwargs):
        return self.surveyors.__dict__[surveyor_name](*args, **kwargs)

    #
    # Non-deprecated analyses
    #

    def analyzed(self, name, *args, **kwargs):
        key = (name, args, tuple(sorted(kwargs.items())))
        return key in self._analysis_results

    @deprecated
    def analyze(self, name, *args, **kwargs):
        """
        Runs an analysis of the given name, providing the given args and kwargs to it.
        If this analysis (with these options) has already been run, it simply returns
        the previously-run analysis.

        @param name: the name of the analysis
        @param args: arguments to pass to the analysis
        @param kwargs: keyword arguments to pass to the analysis
        @returns the analysis results (an instance of a subclass of the Analysis object)
        """
        return self.analyses.__dict__[name](*args, **kwargs)

from .errors import AngrMemoryError, AngrExitError, AngrError, AngrAnalysisError
from .vexer import VEXer
from .capper import Capper
from . import surveyors
from .sliceinfo import SliceInfo
from .analysis import AnalysisResults, Analyses
from .surveyor import Surveyors


