#!/usr/bin/env python

# pylint: disable=W0703

import os
import types
import logging
import weakref

import cle
import simuvex
import archinfo

from .extern_obj import AngrExternObject

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

class Project(object):
    """
    This is the main class of the Angr module. It is meant to contain a set of
    binaries and the relationships between them, and perform analyses on them.
    """

    def __init__(self, filename,
                 default_analysis_mode=None,
                 ignore_functions=None,
                 use_sim_procedures=True,
                 exclude_sim_procedure=None,
                 exclude_sim_procedures=(),
                 arch=None, simos=None,
                 load_options=None,
                 parallel=False):
        """
        This constructs a Project object.

        Arguments:
         @param filename
             the path to the main executable object to analyze
         @param default_analysis_mode
             the mode of analysis to use by default. Defaults to 'symbolic'.
         @param ignore_functions
             a list of function names that, when imported from shared libraries,
             should never be stepped into in analysis (calls will return an
             unconstrained value)
         @param use_sim_procedure
             whether to replace resolved dependencies for which simprocedures
             are available with said simprocedures
         @param exclude_sim_procedure
             a function that, when passed a function name, returns whether
             or not to wrap it with a simprocedure
         @param exclude_sim_procedures
             a list of functions to *not* wrap with simprocedures
         @param arch
             optional target architecture (auto-detected otherwise)
             in the form of an archinfo.Arch or a string
         @param simos
             a SimOS class to use for this project
         @param load_options
             a dict of keyword arguments to the CLE loader. See CLE's docs.
             e.g., { 'auto_load_libs': False,
                     'skip_libs': 'ld.so.2',
                     'lib_opts': {
                       'libc.so.6': {
                         'custom_base_addr': 0x55555400
                       }
                     }
                   }
         @param parallel
             whether to use parallel processing analyzing this binary
        """

        if isinstance(exclude_sim_procedure, types.LambdaType):
            l.warning("Passing a lambda type as the exclude_sim_procedure argument to Project causes the resulting object to be un-serializable.")

        if not os.path.exists(filename) or not os.path.isfile(filename):
            raise Exception("Not a valid binary file: %s" % repr(filename))

        if not default_analysis_mode:
            default_analysis_mode = 'symbolic'

        self.irsb_cache = {}
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
        self._cfg = None
        self._vfg = None
        self._cdg = None
        self._analysis_results = { }
        self.results = AnalysisResults(self)

        self.analyses = Analyses(self, self._analysis_results)
        self.surveyors = Surveyors(self)

        # This is a map from IAT addr to (SimProcedure class, kwargs_)
        self.sim_procedures = {}

        l.info("Loading binary %s", self.filename)
        l.debug("... from directory: %s", self.dirname)

        # ld is angr's loader, provided by cle
        self.ld = cle.Loader(filename, **self.load_options)
        self.main_binary = self.ld.main_bin
        self.extern_obj = AngrExternObject()
        self.ld.add_object(self.extern_obj)

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

        if isinstance(simos, type) and issubclass(simos, SimOS):
            self.simos = simos(self.arch, self) #pylint:disable=invalid-name
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
        self.ld = cle.Loader(self.filename, self.load_options)
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
                if func.name in self.ignore_functions:
                    unresolved.append(func)
                    continue
                elif self.exclude_sim_procedure(func.name):
                    continue

                elif self._use_sim_procedures:
                    for lib in libs:
                        simfun = simuvex.procedures.SimProcedures[lib]
                        if func.name in simfun:
                            l.info("[R] %s:", func.name)
                            l.debug("\t -> matching SimProcedure in %s :)", lib)
                            self.set_sim_procedure(obj, func.name, simfun[func.name], None)
                            break
                    else: # we could not find a simprocedure for this function
                        if not func.resolved:   # the loader couldn't find one either
                            unresolved.append(func)
                # in the case that simprocedures are off and an object in the PLT goes
                # unresolved, we still want to replace it with a retunconstrained.
                elif not func.resolved and func.name in obj.jmprel:
                    unresolved.append(func)

            for func in unresolved:
                l.info("[U] %s", func.name)
                self.set_sim_procedure(obj, func.name,
                       simuvex.SimProcedures["stubs"]["ReturnUnconstrained"],
                       {'resolves': func.name}
                )

        # We need to resync memory as simprocedures have been set at the
        # level of each IDA's instance
        if isinstance(self.ld.main_bin, cle.IdaBin):
            self.ld.ida_sync_mem()

    def hook(self, addr, func, length=0, kwargs=None):
        """
         Hook a section of code with a custom function.

         @param addr        The address to hook
         @param func        A python function or SimProcedure class that will perform an action when
                            execution reaches the hooked address
         @param length      How many bytes you'd like to skip over with your hook. Can be zero.
         @param kwargs      A dictionary of keyword arguments to be passed to your function or
                            your SimProcedure's run function.

         If func is a function, it takes a SimState and the given kwargs. It can return nothing
         (None), in which case it will generate a single exit to the instruction at addr+length,
         or it can return an array of successor states.

         If func is a SimProcedure, it will be run instead of a SimBlock at that address.

         If length is zero, the block at the hooked address will be executed immediately
         after the hook function.
        """

        if addr in self.sim_procedures:
            l.warning("Address is already hooked [hook(%#x, %s)]", addr, func)
            return

        if kwargs is None: kwargs = {}

        if isinstance(func, type):
            proc = func
        elif hasattr(func, '__call__'):
            proc = simuvex.procedures.stubs.UserHook.UserHook
            kwargs = {'user_func': func, 'user_kwargs': kwargs, 'default_return_addr': addr+length}
        else:
            raise AngrError("%s is not a valid object to execute in a hook", func)

        self.sim_procedures[addr] = (proc, kwargs)

    def is_hooked(self, addr):
        return addr in self.sim_procedures

    def unhook(self, addr):
        if addr not in self.sim_procedures:
            l.warning("Address %#x not hooked", addr)
            return

        del self.sim_procedures[addr]

    def set_sim_procedure(self, binary, func_name, sim_proc, kwargs=None):
        """
         Use a simprocedure to resolve a dependency in a binary.

         @param binary      The CLE binary whose dependency is to be resolve
         @param func_name   The name of the dependency to resolve
         @param sim_proc    The class of the SimProcedure to use
         @param kwargs      An optional dictionary of arguments to be passed
                            to the simprocedure's run() method.
        """
        if kwargs is None: kwargs = {}
        ident = sim_proc.__module__ + '.' + sim_proc.__name__
        pseudo_addr = self.extern_obj.get_pseudo_addr(ident)
        binary.set_got_entry(func_name, pseudo_addr)

        if not self.is_hooked(pseudo_addr):     # Do not add duplicate simprocedures
            self.hook(pseudo_addr, sim_proc, kwargs=kwargs)
            l.debug("\t -> setting SimProcedure with pseudo_addr 0x%x...", pseudo_addr)

            # Special case for __libc_start_main - it needs to call exit() at the end of execution
            # TODO: Fix this by implementing call sequences in SimProcedure
            if func_name == '__libc_start_main':
                if 'exit_addr' not in kwargs:
                    exit_pseudo_addr = self.extern_obj.get_pseudo_addr('__libc_start_main:exit')
                    self.hook(exit_pseudo_addr, simuvex.procedures.SimProcedures['libc.so.6']['exit'])
                    kwargs['exit_addr'] = exit_pseudo_addr

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
        return self.vexer.block(addr, max_size=max_size, num_inst=num_inst,
                                traceflags=traceflags, thumb=thumb, backup_state=backup_state, opt_level=opt_level)

    def sim_block(self, state, max_size=None, num_inst=None,
                  stmt_whitelist=None, last_stmt=None, addr=None):
        """
         Returns a SimIRSB object with execution based on state

         Optional params:
         @param max_size         the maximum size of the block, in bytes
         @param num_inst         the maximum number of instructions
         @param stmt_whitelist   a list of stmt indexes to which to confine execution
         @param last_stmt        a statement index at which to stop execution
         @param addr             the address at which to start the block
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
        for stmt in irsb.statements:
            if stmt.tag != 'Ist_IMark' or stmt.addr == addr:
                continue
            if self.is_hooked(stmt.addr):
                max_bytes = stmt.addr - addr
                irsb = self.block(addr, max_bytes, thumb=thumb, backup_state=state, opt_level=opt_level)
                break
        return simuvex.SimIRSB(state, irsb, addr=addr, whitelist=stmt_whitelist, last_stmt=last_stmt)

    def sim_run(self, state, max_size=None, num_inst=None, stmt_whitelist=None,
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
        elif self.is_hooked(addr) and jumpkind != 'Ijk_NoHook':
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
