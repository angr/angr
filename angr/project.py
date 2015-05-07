#!/usr/bin/env python

# pylint: disable=W0703

import os
import md5
import types
import struct
import logging
import weakref

import cle
import simuvex
import archinfo

l = logging.getLogger("angr.project")

projects = weakref.WeakValueDictionary()
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

VEX_IRSB_MAX_SIZE = 400

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
                 arch=None, simos=None,
                 load_options=None,
                 parallel=False, ignore_functions=None, force_abstraction=None,
                 argv=None, envp=None, symbolic_argc=None):
        """
        This constructs a Project object.

        Arguments:
            @filename: path to the main executable object to analyse
            @arch: optional target architecture (auto-detected otherwise)
            in the form of an archinfo.Arch or a string
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
        self._use_sim_procedures = use_sim_procedures
        self._parallel = parallel
        self.load_options = { } if load_options is None else load_options

        # List of functions we don't want to step into (and want
        # ReturnUnconstrained() instead)
        self.ignore_functions = [] if ignore_functions is None else ignore_functions
        self.force_abstraction = [] if force_abstraction is None else force_abstraction
        
        self._cfg = None
        self._vfg = None
        self._cdg = None
        self._analysis_results = { }
        self.results = AnalysisResults(self)

        self.analyses = Analyses(self, self._analysis_results)
        self.surveyors = Surveyors(self)

        # This is a map from IAT addr to (SimProcedure class name, kwargs_)
        self.sim_procedures = {}

        l.info("Loading binary %s", self.filename)
        l.debug("... from directory: %s", self.dirname)

        # ld is angr's loader, provided by cle
        self.ld = cle.Ld(filename, **self.load_options)
        self.main_binary = self.ld.main_bin

        if isinstance(arch, str):
            self.arch = archinfo.arch_from_id(arch) # may raise ArchError, let the user see this
        elif isinstance(arch, archinfo.Arch):
            self.arch = arch
        elif arch is None:
            self.arch = self.ld.main_bin.arch
        else:
            raise ValueError("Invalid arch specification.")

        self.min_addr = self.ld.min_addr()
        self.max_addr = self.ld.max_addr()
        self.entry = self.ld.main_bin.entry

        self.use_sim_procedures()

        # command line arguments, environment variables, etc
        self.argv = argv
        self.envp = envp
        self.symbolic_argc = symbolic_argc

        if isinstance(simos, SimOS) and simos.arch == self.arch:
            self.simos = simos #pylint:disable=invalid-name
        elif simos is None:
            self.simos = SimLinux(self.arch, self)
        else:
            raise ValueError("Invalid OS specification or non-matching architecture.")

        self.simos.configure_project(self)

        self.vexer = VEXer(self.ld.memory, self.arch, use_cache=self.arch.cache_irsb)
        self.capper = Capper(self.ld.memory, self.arch, use_cache=True)
        self.state_generator = StateGenerator(self)
        self.path_generator = PathGenerator(self)

    #
    # Pickling
    #

    def __getstate__(self):
        try:
            vexer, capper, ld, main_bin, state_generator = self.vexer, self.capper, self.ld, self.main_binary, self.state_generator
            self.vexer, self.capper, self.ld, self.main_binary, self.state_generator = None, None, None, None, None
            return dict(self.__dict__)
        finally:
            self.vexer, self.capper, self.ld, self.main_binary, self.state_generator = vexer, capper, ld, main_bin, state_generator

    def __setstate__(self, s):
        self.__dict__.update(s)
        self.ld = cle.Ld(self.filename, self.load_options)
        self.main_binary = self.ld.main_bin
        self.vexer = VEXer(self.ld.memory, self.arch, use_cache=self.arch.cache_irsb)
        self.capper = Capper(self.ld.memory, self.arch, use_cache=True)
        self.state_generator = StateGenerator(self)

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

        for lib_name in self.ld.requested_objects:
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

        for obj in self.ld.all_objects:
            unresolved = []
            for reloc in obj.imports.itervalues():
                func = reloc.symbol                
                sh_lib = func.resolvedby.owner_obj.binary if func.resolvedby else None
                if sh_lib:
                    sh_lib = sh_lib.split('/')[-1]
                if self.exclude_sim_procedure(func.name):
                    # l.debug("%s: SimProcedure EXCLUDED", i)
                    continue
                elif func.name in self.ignore_functions:
                    unresolved.append(func)
                    continue
                elif self._use_sim_procedures:
                    for lib in libs:
                        simfun = simuvex.procedures.SimProcedures[lib]
                        if func.name in simfun:
                            l.info("[R] %s:", func.name)
                            l.debug("\t -> matching SimProcedure in %s :)", lib)
                            self.set_sim_procedure(obj, lib, func.name, simfun[func.name], None)
                            break
                    else: # we could not find a simprocedure for this function
                        if not func.resolved or sh_lib in self.force_abstraction: # the loader couldn't find one either
                            unresolved.append(func)                               # or the lib must be abstracted
                # in the case that simprocedures are off and an object in the PLT goes
                # unresolved, we still want to replace it with a retunconstrained.
                elif not func.resolved and func.name in obj.jmprel:
                    unresolved.append(func)

            for func in unresolved:
                l.info("[U] %s", func.name)
                self.set_sim_procedure(obj, "stubs", func.name,
                       simuvex.SimProcedures["stubs"]["ReturnUnconstrained"],
                       {'resolves': func.name}
                )

        # We need to resync memory as simprocedures have been set at the
        # level of each IDA's instance
        if isinstance(self.ld.main_bin, cle.IdaBin):
            self.ld.ida_sync_mem()
     
    def update_jmpslot_with_simprocedure(self, func_name, pseudo_addr, binary):
        """ Update a jump slot (GOT address referred to by a PLT slot) with the
        address of a simprocedure """
        self.ld.override_got_entry(func_name, pseudo_addr, binary)

    def add_custom_sim_procedure(self, address, sim_proc, kwargs=None):
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

        hashed_bytes = m.digest()[:self.arch.bytes]
        pseudo_addr = struct.unpack(self.arch.struct_fmt(), hashed_bytes)[0]
        pseudo_addr -= pseudo_addr % 4

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
                hashed_bytes_ = m.digest()[ : self.arch.bytes]
                pseudo_addr_ = struct.unpack(self.arch.struct_fmt(), hashed_bytes_)[0]
                pseudo_addr_ = pseudo_addr_ % 4
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

    @deprecated
    def initial_exit(self, mode=None, options=None):
        """Creates a SimExit to the entry point."""
        return self.exit_to(addr=self.entry, mode=mode, options=options)

    @deprecated
    def initial_state(self, mode=None, add_options=None, args=None, env=None, **kwargs):
        '''
        Creates an initial state, with stack and everything.

        All arguments are passed directly through to StateGenerator.entry_point,
        allowing for a couple of more reasonable defaults.

        @param mode - Optional, defaults to project.default_analysis_mode
        @param add_options - gets PARALLEL_SOLVES added to it if project._parallel is true
        @param args - Optional, defaults to project.argv
        @param env - Optional, defaults to project.envp
        '''

        # Have some reasonable defaults
        if mode is None:
            mode = self.default_analysis_mode
        if add_options is None:
            add_options = set()
        if self._parallel:
            add_options |= { simuvex.o.PARALLEL_SOLVES }
        if args is None:
            args = self.argv
        if env is None:
            env = self.envp

        return self.state_generator.entry_point(mode=mode, add_options=add_options, args=args, env=env, **kwargs)

    @deprecated
    def exit_to(self, addr=None, state=None, mode=None, options=None, initial_prefix=None):
        '''
        Creates a Path with the given state as initial state.

        :param addr:
        :param state:
        :param mode:
        :param options:
        :param jumpkind:
        :param initial_prefix:
        :return: A Path instance
        '''
        return self.path_generator.blank_path(address=addr, mode=mode, options=options,
                        initial_prefix=initial_prefix, state=state)

    def block(self, addr, max_size=None, num_inst=None, traceflags=0, thumb=False, backup_state=None, opt_level=None):
        """
        Returns a pyvex block starting at address addr

        Optional params:

        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param traceflags: traceflags to be passed to VEX. Default: 0
        @param thumb: whether this block is in thumb mode (ARM)
        @param opt_level: the optimization level {0,1,2} to use on the IR
        """
        if max_size is not None and max_size != VEX_IRSB_MAX_SIZE: num_inst = -1
        return self.vexer.block(addr, max_size=max_size, num_inst=num_inst,
                                traceflags=traceflags, thumb=thumb, backup_state=backup_state, opt_level=opt_level)

    def sim_block(self, state, max_size=None, num_inst=None,
                  stmt_whitelist=None, last_stmt=None, addr=None):
        """
        Returns a simuvex block starting at SimExit @where

        Optional params:

        @param where: the exit to start the analysis at
        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param state: the initial state. Fully unconstrained if None

        """
        if addr is None:
            addr = state.se.any_int(state.regs.ip)

        thumb = False
        if addr % state.arch.instruction_alignment != 0:
            if state.thumb:
                thumb = True
            else:
                raise AngrExitError("Address 0x%x does not align to alignment %d "
                                    "for architecture %s." % (addr,
                                    state.arch.instruction_alignment,
                                    state.arch.name))

        opt_level = 1 if simuvex.o.OPTIMIZE_IR in state.options else 0

        irsb = self.block(addr, max_size, num_inst, thumb=thumb, backup_state=state, opt_level=opt_level)
        return simuvex.SimIRSB(state, irsb, addr=addr, whitelist=stmt_whitelist, last_stmt=last_stmt)

    def sim_run(self, state, max_size=VEX_IRSB_MAX_SIZE, num_inst=None, stmt_whitelist=None,
                last_stmt=None, jumpkind="Ijk_Boring"):
        """
        Returns a simuvex SimRun object (supporting refs() and
        exits()), automatically choosing whether to create a SimIRSB or
        a SimProcedure.

        Parameters:
        @param state : the state to analyze
        @param max_size : the maximum size of the block, in bytes
        @param num_inst : the maximum number of instructions
        @param state : the initial state. Fully unconstrained if None
        """

        addr = state.se.any_int(state.regs.ip)

        if jumpkind.startswith("Ijk_Sys"):
            l.debug("Invoking system call handler (originally at 0x%x)", addr)
            return simuvex.SimProcedures['syscalls']['handler'](state, addr=addr)

        if jumpkind in ("Ijk_EmFail", "Ijk_NoDecode", "Ijk_MapFail") or "Ijk_Sig" in jumpkind:
            l.debug("Invoking system call handler (originally at 0x%x)", addr)
            r = simuvex.SimProcedures['syscalls']['handler'](state, addr=addr)
        elif self.is_sim_procedure(addr):
            sim_proc_class, kwargs = self.sim_procedures[addr]
            l.debug("Creating SimProcedure %s (originally at 0x%x)",
                    sim_proc_class.__name__, addr)
            state._inspect('call', simuvex.BP_BEFORE, function_name=sim_proc_class.__name__)
            r = sim_proc_class(state, addr=addr, sim_kwargs=kwargs)
            state._inspect('call', simuvex.BP_AFTER, function_name=sim_proc_class.__name__)
            l.debug("... %s created", r)
        else:
            l.debug("Creating SimIRSB at 0x%x", addr)
            r = self.sim_block(state, max_size=max_size, num_inst=num_inst,
                                  stmt_whitelist=stmt_whitelist,
                                  last_stmt=last_stmt, addr=addr)

        return r

    def binary_by_addr(self, addr):
        """ This returns the binary containing address @addr"""
        return self.ld.addr_belongs_to_object(addr)

    #
    # Non-deprecated analyses
    #

    def analyzed(self, name, *args, **kwargs):
        key = (name, args, tuple(sorted(kwargs.items())))
        return key in self._analysis_results

    #
    # Path Groups
    #

    def path_group(self, paths=None, **kwargs):
        if paths is None:
            paths = [ self.path_generator.entry_point() ]
        return PathGroup(self, active_paths=paths, **kwargs)

from .errors import AngrExitError, AngrError
from .vexer import VEXer
from .capper import Capper
from .analysis import AnalysisResults, Analyses
from .surveyor import Surveyors
from .states import StateGenerator
from .paths import PathGenerator
from .simos import SimOS, SimLinux
from .path_group import PathGroup
