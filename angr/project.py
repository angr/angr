#!/usr/bin/env python

# pylint: disable=W0703

import os
import types
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

class Project(object):
    """
    This is the main class of the Angr module. It is meant to contain a set of
    binaries and the relationships between them, and perform analyses on them.
    """

    def __init__(self, thing,
                 default_analysis_mode=None,
                 ignore_functions=None,
                 use_sim_procedures=True,
                 exclude_sim_procedures_func=None,
                 exclude_sim_procedures_list=(),
                 arch=None, simos=None,
                 load_options=None,
                 parallel=False,
                 support_selfmodifying_code=False):
        """
        This constructs a Project object.

        Arguments:
         @param thing
             the path to the main executable object to analyze, or a CLE Loader object
         @param default_analysis_mode
             the mode of analysis to use by default. Defaults to 'symbolic'.
         @param ignore_functions
             a list of function names that, when imported from shared libraries,
             should never be stepped into in analysis (calls will return an
             unconstrained value)
         @param use_sim_procedure
             whether to replace resolved dependencies for which simprocedures
             are available with said simprocedures
         @param exclude_sim_procedures_func
             a function that, when passed a function name, returns whether
             or not to wrap it with a simprocedure
         @param exclude_sim_procedures_list
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
         @param support_selfmodifying_code
             Whether we support self-modifying code. When enabled, Project.sim_block() will try to read code from the
             given state, not only from the initial memory regions.
        """

        # Step 1: Load the binary
        if isinstance(thing, cle.Loader):
            self.loader = thing
            self.filename = self.loader._main_binary_path
        elif not isinstance(thing, (unicode, str)) or not os.path.exists(thing) or not os.path.isfile(thing):
            raise Exception("Not a valid binary file: %s" % repr(thing))
        else:
            # use angr's loader, provided by cle
            l.info("Loading binary %s", thing)
            self.filename = thing
            if load_options is None: load_options = {}
            self.loader = cle.Loader(self.filename, **load_options)

        # Step 2: determine its CPU architecture, ideally falling back to CLE's guess
        if isinstance(arch, str):
            self.arch = archinfo.arch_from_id(arch) # may raise ArchError, let the user see this
        elif isinstance(arch, archinfo.Arch):
            self.arch = arch
        elif arch is None:
            self.arch = self.loader.main_bin.arch
        else:
            raise ValueError("Invalid arch specification.")

        # Step 3: Set some defaults and set the public and private properties
        if not default_analysis_mode:
            default_analysis_mode = 'symbolic'
        if not ignore_functions:
            ignore_functions = []

        if isinstance(exclude_sim_procedures_func, types.LambdaType):
            l.warning("Passing a lambda type as the exclude_sim_procedures_func argument to Project causes the resulting object to be un-serializable.")

        self._sim_procedures = {}
        self._default_analysis_mode = default_analysis_mode
        self._exclude_sim_procedures_func = exclude_sim_procedures_func
        self._exclude_sim_procedures_list = exclude_sim_procedures_list
        self._should_use_sim_procedures = use_sim_procedures
        self._parallel = parallel
        self._support_selfmodifying_code = support_selfmodifying_code
        self._ignore_functions = ignore_functions
        self._extern_obj = AngrExternObject()
        self.loader.add_object(self._extern_obj)

        self._cfg = None
        self._vfg = None
        self._cdg = None

        self.entry = self.loader.main_bin.entry
        self.factory = AngrObjectFactory(self)
        self.analyses = Analyses(self)
        self.surveyors = Surveyors(self)

        projects[self.filename] = self

        # Step 4: Register simprocedures as appropriate for library functions
        self._use_sim_procedures()

        # Step 5: determine the host OS and perform additional initialization
        # in the SimOS constructor
        if isinstance(simos, type) and issubclass(simos, SimOS):
            self._simos = simos(self) #pylint:disable=invalid-name
        elif simos is None:
            self._simos = os_mapping[self.loader.main_bin.os](self)
        else:
            raise ValueError("Invalid OS specification or non-matching architecture.")

    #
    # Public methods
    #

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

        if self.is_hooked(addr):
            l.warning("Address is already hooked [hook(%#x, %s, %s()]", addr, func, kwargs.get('funcname'))
            return

        if kwargs is None: kwargs = {}

        if isinstance(func, type):
            proc = func
        elif hasattr(func, '__call__'):
            proc = simuvex.procedures.stubs.UserHook.UserHook
            kwargs = {'user_func': func, 'user_kwargs': kwargs, 'default_return_addr': addr+length}
        else:
            raise AngrError("%s is not a valid object to execute in a hook", func)

        self._sim_procedures[addr] = (proc, kwargs)

    def is_hooked(self, addr):
        return addr in self._sim_procedures

    def unhook(self, addr):
        if not self.is_hooked(addr):
            l.warning("Address %#x not hooked", addr)
            return

        del self._sim_procedures[addr]

    #
    # Pickling
    #

    def __getstate__(self):
        try:
            factory, analyses, surveyors = self.factory, self.analyses, self.surveyors
            self.factory, self.analyses, self.surveyors = None, None, None
            return dict(self.__dict__)
        finally:
            self.factory, self.analyses, self.surveyors = factory, analyses, surveyors

    def __setstate__(self, s):
        self.__dict__.update(s)
        self.factory = AngrObjectFactory(self)
        self.analyses = Analyses(self)
        self.surveyors = Surveyors(self)

    #
    # Private project stuff for simprocedures
    #

    def _should_exclude_sim_procedure(self, f):
        return (f in self._exclude_sim_procedures_list) or \
               ( self._exclude_sim_procedures_func is not None and \
                 self._exclude_sim_procedures_func(f)
               )

    def _find_sim_libraries(self):
        """ Look for libaries that we can replace with their simuvex
        simprocedures counterpart
        This function returns the list of libraries that were found in simuvex
        """
        simlibs = []

        for lib_name in self.loader.requested_objects:
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

    def _use_sim_procedures(self):
        """ Use simprocedures where we can """
        libs = self._find_sim_libraries()
        for obj in self.loader.all_objects:
            unresolved = []
            for reloc in obj.imports.itervalues():
                func = reloc.symbol
                if not func.is_function:
                    continue
                elif func.name in self._ignore_functions:
                    unresolved.append(func)
                    continue
                elif self._should_exclude_sim_procedure(func.name):
                    continue

                elif self._should_use_sim_procedures:
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
                # Don't touch weakly bound symbols, they are allowed to go unresolved
                if func.is_weak:
                    continue
                l.info("[U] %s", func.name)
                procedure = simuvex.SimProcedures['stubs']['NoReturnUnconstrained']
                if func.name not in procedure.use_cases:
                    procedure = simuvex.SimProcedures['stubs']['ReturnUnconstrained']
                self.set_sim_procedure(obj, func.name, procedure, {'resolves': func.name})

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
        if 'resolves' in kwargs:
            ident += '.' + kwargs['resolves']
        pseudo_addr = self._extern_obj.get_pseudo_addr(ident)
        binary.set_got_entry(func_name, pseudo_addr)

        if not self.is_hooked(pseudo_addr):     # Do not add duplicate simprocedures
            self.hook(pseudo_addr, sim_proc, kwargs=kwargs)
            l.debug("\t -> setting SimProcedure with pseudo_addr 0x%x...", pseudo_addr)

from .errors import AngrError
from .factory import AngrObjectFactory
from .simos import SimOS, os_mapping
from .extern_obj import AngrExternObject
from .analysis import Analyses
from .surveyor import Surveyors
