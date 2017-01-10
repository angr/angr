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
    This is the main class of the angr module. It is meant to contain a set of binaries and the relationships between
    them, and perform analyses on them.

    :ivar analyses: The available analyses.
    :type analyses: angr.analysis.Analyses
    :ivar entry:    The program entrypoint.
    :ivar factory:  Provides access to important analysis elements such as path groups and symbolic execution results.
    :type factory:  AngrObjectFactory
    :ivar filename: The filename of the executable.
    :ivar loader:   The program loader.
    :type loader:   cle.Loader
    :ivar surveyor: The available surveyors.
    :type surveyor: angr.surveyor.Surveyors
    """

    def __init__(self, thing,
                 default_analysis_mode=None,
                 ignore_functions=None,
                 use_sim_procedures=True,
                 exclude_sim_procedures_func=None,
                 exclude_sim_procedures_list=(),
                 arch=None, simos=None,
                 load_options=None,
                 translation_cache=True,
                 support_selfmodifying_code=False):
        """
        :param thing:                       The path to the main executable object to analyze, or a CLE Loader object.

        The following parameters are optional.

        :param default_analysis_mode:       The mode of analysis to use by default. Defaults to 'symbolic'.
        :param ignore_functions:            A list of function names that, when imported from shared libraries, should
                                            never be stepped into in analysis (calls will return an unconstrained value).
        :param use_sim_procedure:           Whether to replace resolved dependencies for which simprocedures are
                                            available with said simprocedures.
        :param exclude_sim_procedures_func: A function that, when passed a function name, returns whether or not to wrap
                                            it with a simprocedure.
        :param exclude_sim_procedures_list: A list of functions to *not* wrap with simprocedures.
        :param arch:                        The target architecture (auto-detected otherwise).
        :param simos:                       a SimOS class to use for this project.
        :param load_options:                a dict of keyword arguments to the CLE loader. See CLE's docs.
        :param translation_cache:           If True, cache translated basic blocks rather than re-translating them.
        :param support_selfmodifying_code:  Whether we support self-modifying code. When enabled, Project.sim_block()
                                            will try to read code from the current state instead of the original memory
                                            regions.
        :type  support_selfmodifying_code:  bool

        A sample `load_options` value could be:
        ::

            { 'auto_load_libs': False,
              'skip_libs': 'ld.so.2',
              'lib_opts': {
                'libc.so.6': {
                'custom_base_addr': 0x55555400
                }
              }
            }
        """

        # Step 1: Load the binary
        if load_options is None: load_options = {}

        if isinstance(thing, cle.Loader):
            self.loader = thing
            self.filename = self.loader._main_binary_path
        elif hasattr(thing, 'read') and hasattr(thing, 'seek'):
            l.info("Loading binary from stream")
            self.filename = None
            self.loader = cle.Loader(thing, **load_options)
        elif not isinstance(thing, (unicode, str)) or not os.path.exists(thing) or not os.path.isfile(thing):
            raise Exception("Not a valid binary file: %s" % repr(thing))
        else:
            # use angr's loader, provided by cle
            l.info("Loading binary %s", thing)
            self.filename = thing
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
        self._support_selfmodifying_code = support_selfmodifying_code
        self._ignore_functions = ignore_functions
        self._extern_obj = AngrExternObject(self.arch)
        self._extern_obj.provides = 'angr externs'
        self.loader.add_object(self._extern_obj)
        self._syscall_obj = AngrExternObject(self.arch)
        self._syscall_obj.provides = 'angr syscalls'
        self.loader.add_object(self._syscall_obj)

        if self._support_selfmodifying_code:

            if translation_cache is True:
                translation_cache = False
                l.warning("Disabling IRSB translation cache because support for self-modifying code is enabled.")


        vex_engine = simuvex.SimEngineVEX(
                stop_points=self._sim_procedures,
                use_cache=translation_cache,
                support_selfmodifying_code=support_selfmodifying_code)
        procedure_engine = SimEngineHook(self)
        failure_engine = SimEngineFailure(self)
        syscall_engine = SimEngineSyscall(self)
        unicorn_engine = simuvex.SimEngineUnicorn(self._sim_procedures)

        self.entry = self.loader.main_bin.entry
        self.factory = AngrObjectFactory(
                self,
                vex_engine,
                procedure_engine,
                [failure_engine, syscall_engine, procedure_engine, unicorn_engine, vex_engine])
        self.analyses = Analyses(self)
        self.surveyors = Surveyors(self)
        self.kb = KnowledgeBase(self, self.loader.main_bin)

        if self.filename is not None:
            projects[self.filename] = self

        # Step 5: determine the host OS and perform additional initialization
        # in the SimOS constructor
        if isinstance(simos, type) and issubclass(simos, SimOS):
            self._simos = simos(self) #pylint:disable=invalid-name
        elif simos is None:
            self._simos = os_mapping[self.loader.main_bin.os](self)
        else:
            raise ValueError("Invalid OS specification or non-matching architecture.")

        # Step 4: Register simprocedures as appropriate for library functions
        self._use_sim_procedures()
        self._simos.configure_project()

    def _use_sim_procedures(self):
        """
        This is all the automatic simprocedure related initialization work
        It's too big to just get pasted into the initializer.
        """

        # Step 1: Get the appropriate libraries of SimProcedures from simuvex
        libs = []
        for lib_name in self.loader.requested_objects:
            if isinstance(self.loader.main_bin, cle.backends.pe.PE):
                # File names are case-insensitive on Windows. Make them all lowercase
                lib_name = lib_name.lower()

            # Hack that should go somewhere else:
            if lib_name in [ 'libc.so.0', 'libc.so' ]:
                lib_name = 'libc.so.6'
            if lib_name == 'ld-uClibc.so.0':
                lib_name = 'ld-uClibc.so.6'

            if lib_name not in simuvex.procedures.SimProcedures:
                l.debug("There are no simprocedures for library %s :(", lib_name)
            else:
                libs.append(lib_name)

        # Step 2: Categorize every "import" symbol in each object.
        # If it's IGNORED, mark it for stubbing
        # If it's blacklisted, don't process it
        # If it matches a simprocedure we have, replace it
        already_resolved = set()
        for obj in self.loader.all_objects:
            unresolved = []
            for reloc in obj.imports.itervalues():
                func = reloc.symbol
                if func.name in already_resolved:
                    continue
                if not func.is_function:
                    continue
                elif func.name in self._ignore_functions:
                    unresolved.append(func)
                    continue
                elif self._should_exclude_sim_procedure(func.name):
                    continue

                elif self._should_use_sim_procedures:
                    for lib in libs:
                        simfuncs = simuvex.procedures.SimProcedures[lib]
                        if func.name in simfuncs:
                            l.info("Providing %s from %s with SimProcedure", func.name, lib)
                            self.hook_symbol(func.name, simfuncs[func.name])
                            already_resolved.add(func.name)
                            break
                    else: # we could not find a simprocedure for this function
                        if not func.resolved:   # the loader couldn't find one either
                            unresolved.append(func)
                # in the case that simprocedures are off and an object in the PLT goes
                # unresolved, we still want to replace it with a retunconstrained.
                elif not func.resolved and func.name in obj.jmprel:
                    unresolved.append(func)

            # Step 3: Stub out unresolved symbols
            # This is in the form of a SimProcedure that either doesn't return
            # or returns an unconstrained value
            for func in unresolved:
                # Don't touch weakly bound symbols, they are allowed to go unresolved
                if func.is_weak:
                    continue
                l.info("[U] %s", func.name)
                procedure = simuvex.SimProcedures['stubs']['NoReturnUnconstrained']
                if func.name not in procedure.use_cases:
                    procedure = simuvex.SimProcedures['stubs']['ReturnUnconstrained']
                self.hook_symbol(func.name, Hook(procedure, resolves=func.name))
                already_resolved.add(func.name)

    def _should_exclude_sim_procedure(self, f):
        """
        Has symbol name `f` been marked for exclusion by any of the user
        parameters?
        """
        return (f in self._exclude_sim_procedures_list) or \
               ( self._exclude_sim_procedures_func is not None and \
                 self._exclude_sim_procedures_func(f)
               )

    #
    # Public methods
    # They're all related to hooking!
    #

    def hook(self, addr, hook, length=0, kwargs=None):
        """
        Hook a section of code with a custom function. This is used internally to provide symbolic
        summaries of library functions, and can be used to instrument execution or to modify
        control flow.

        :param addr:        The address to hook.
        :param hook:        A :class:`angr.project.Hook` describing a procedure to run at the
                            given address. You may also pass in a SimProcedure class or a function
                            directly and it will be wrapped in a Hook object for you.
        :param length:      If you provide a function for the hook, this is the number of bytes
                            that will be skipped by executing the hook by default.
        :param kwargs:      If you provide a SimProcedure for the hook, these are the keyword
                            arguments that will be passed to the procedure's `run` method
                            eventually.
        """
        l.debug('hooking %#x with %s', addr, hook)

        if self.is_hooked(addr):
            l.warning("Address is already hooked [hook(%#x, %s)]", addr, hook)
            return

        if not isinstance(hook, Hook):
            if kwargs is None: kwargs = {}

            if isinstance(hook, type) and issubclass(hook, simuvex.s_procedure.SimProcedure):
                hook = Hook(hook, **kwargs)
            elif callable(hook):
                hook = Hook(simuvex.procedures.stubs.UserHook.UserHook,
                            user_func=hook,
                            length=length)
            else:
                raise AngrError("%s is not a valid object to execute in a hook", hook)

        self._sim_procedures[addr] = hook

        # set up a continuation if necessary
        cont = hook.make_continuation()
        if cont is not None:
            cont_addr = self._extern_obj.anon_allocation()
            self.hook(cont_addr, cont)
            hook.set_continuation_addr(cont_addr)
            cont.set_continuation_addr(cont_addr)

    def is_hooked(self, addr):
        """
        Returns True if `addr` is hooked.

        :param addr: An address.
        :returns:    True if addr is hooked, False otherwise.
        """
        return addr in self._sim_procedures

    def is_symbol_hooked(self, symbol_name):
        """
        Check if a symbol is already hooked.

        :param str symbol_name: Name of the symbol.
        :return: True if the symbol can be resolved and is hooked, False otherwise.
        :rtype: bool
        """

        ident = self._symbol_name_to_ident(symbol_name)

        # TODO: this method does not follow the SimOS.prepare_function_symbol() path. We should fix it later.

        if not self._extern_obj.contains_identifier(ident):
            return False

        return True

    def hooked_symbol_addr(self, symbol_name):
        """
        Check if a symbol is hooked or not, and if it is hooked, return the address of the symbol.

        :param str symbol_name: Name of the symbol.
        :return: Address of the symbol if it is hooked, None otherwise.
        :rtype: int or None
        """

        if not self.is_symbol_hooked(symbol_name):
            return None

        ident = self._symbol_name_to_ident(symbol_name)

        return self._extern_obj.get_pseudo_addr_for_symbol(ident)

    def unhook(self, addr):
        """
        Remove a hook.

        :param addr:    The address of the hook.
        """
        if not self.is_hooked(addr):
            l.warning("Address %#x not hooked", addr)
            return

        del self._sim_procedures[addr]

    def hooked_by(self, addr):
        """
        Returns the current hook for `addr`.

        :param addr: An address.

        :returns:    None if the address is not hooked.
        """

        if not self.is_hooked(addr):
            l.warning("Address %#x is not hooked", addr)
            return None

        return self._sim_procedures[addr]

    def hook_symbol(self, symbol_name, obj, kwargs=None):
        """
        Resolve a dependency in a binary. Uses the "externs object" (project._extern_obj) to
        allocate an address for a new symbol in the binary, and then tells the loader to reperform
        the relocation process, taking into account the new symbol.

        :param symbol_name: The name of the dependency to resolve.
        :param obj:         The thing with which to satisfy the dependency. May be a python integer
                            or anything that may be passed to `project.hook()`.
        :param length:      If you provide a function for the hook, this is the number of bytes
                            that will be skipped by executing the hook by default.
        :param kwargs:      If you provide a SimProcedure for the hook, these are the keyword
                            arguments that will be passed to the procedure's `run` method
                            eventually.
        :returns:           The address of the new symbol.
        :rtype:             int
        """
        if kwargs is None: kwargs = {}
        ident = self._symbol_name_to_ident(symbol_name, kwargs)

        if not isinstance(obj, (int, long)):
            pseudo_addr = self._simos.prepare_function_symbol(ident)
            pseudo_vaddr = pseudo_addr - self._extern_obj.rebase_addr

            if self.is_hooked(pseudo_addr):
                l.warning("Re-hooking symbol " + symbol_name)
                self.unhook(pseudo_addr)

            self.hook(pseudo_addr, obj, kwargs=kwargs)
        else:
            # This is pretty intensely sketchy
            pseudo_addr = obj
            pseudo_vaddr = obj - self._extern_obj.rebase_addr

        self.loader.provide_symbol(self._extern_obj, symbol_name, pseudo_vaddr)

        return pseudo_addr

    #
    # Private methods related to hooking
    #

    @staticmethod
    def _symbol_name_to_ident(symbol_name, kwargs=None):
        """
        Convert a symbol name to an identifier that are used by hooking.

        :param str symbol_name: Name of the symbol.
        :param dict kwargs: Any additional keyword arguments.
        :return: An identifier.
        :rtype: str
        """
        ident = 'symbol hook: ' + symbol_name
        if kwargs and 'resolves' in kwargs:
            ident += '.' + kwargs['resolves']

        return ident

    #
    # Pickling
    #

    def __getstate__(self):
        try:
            analyses, surveyors = self.analyses, self.surveyors
            self.analyses, self.surveyors = None, None
            return dict(self.__dict__)
        finally:
            self.analyses, self.surveyors = analyses, surveyors

    def __setstate__(self, s):
        self.__dict__.update(s)
        self.analyses = Analyses(self)
        self.surveyors = Surveyors(self)


class Hook(object):
    """
    An object describing an action to be taken at a given address instead of executing binary code.
    An instance of this class may be passed to `angr.Project.hook` along with the address at which
    to hook.

    More specifically, a hook is a wrapper for a SimProcedure, a simuvex object that contains a lot
    of logic for how to mutate a state in common ways. The SimProcedure base class is subclassed
    to produce a SimProcedure that may be used for hooking. If the SimProcedure class is too heavy
    for your use case, there is a class method `wrap` on this class that can be used to wrap a
    simple function into a SimProcedure, and then further into a `Hook` directly.

    This class is a bit of a hack to deal with the fact that SimProcedures need to hold state but
    having them do so makes them not thread-safe.
    """
    def __init__(self, procedure, **kwargs):
        """
        :param procedure:   The class of the procedure to use
        :param kwargs:      Any additional keyword arguments will be eventually passed to the
                            `run` method of the procedure on its execution, via the `sim_kwargs`
                            SimProcedure constructor parameter.
        """
        self.procedure = procedure
        self.kwargs = kwargs
        self.is_continuation = False
        self._continuation_addr = None

    def instantiate(self, *args, **kwargs):
        kwargs['sim_kwargs'] = self.kwargs
        kwargs['is_continuation'] = self.is_continuation
        kwargs['continuation_addr'] = self._continuation_addr
        return self.procedure(*args, **kwargs)
    instantiate.__doc__ = simuvex.s_procedure.SimProcedure.__init__.__doc__

    def __repr__(self):
        try:
            resolves_str = ' (resolves %s)' % self.kwargs['resolves']
        except KeyError:
            resolves_str = ''

        if len(self.kwargs) == 0:
            args_str = ''
        elif len(self.kwargs) == 1:
            args_str = ' (1 arg)'
        else:
            args_str = ' (%d args)' % len(self.kwargs)

        cont_str = ' (continuation)' if self.is_continuation else ''

        return '<Hook for %s%s%s%s>' % (self.name, resolves_str, args_str, cont_str)

    def make_continuation(self):
        if self.is_continuation or not self.procedure.IS_FUNCTION or self._continuation_addr is not None:
            return None
        hook = Hook(self.procedure, **self.kwargs)
        hook.is_continuation = True
        return hook

    def set_continuation_addr(self, addr):
        self._continuation_addr = addr

    @property
    def name(self):
        return self.procedure.__name__

    @classmethod
    def wrap(cls, length=0):
        """
        Call this function to return a decorator you can use to turn a function into a Hook. This
        specific kind of hook is called a "User Hook".

        For example:

        >>> @Hook.wrap(length=5)
        >>> def set_rax(state):
        >>>     state.regs.rax = 1
        >>>
        >>> project.hook(0x1234, set_rax)

        The function may modify the state in any way it sees fit. In order to produce successors
        from a user hook, you have two options.

            1. Return nothing. In this case, execution will resume at `length` bytes after the hook
               address.
            2. Return a list of successor states. Each of the states should have the following
               attributes set:

                - `state.scratch.guard`: a symbolic boolean describing the condition necessary for
                  this successor to be taken. A shortcut to the symbolic `True` value is
                  `state.se.true`.
                - `state.scratch.jumpkind`: The type of the jump to be taken, as a VEX enum string.
                  This will usually be `Ijk_Boring`, which signifies an ordinary jump or branch.
        """
        def inner(function):
            return Hook(simuvex.procedures.stubs.UserHook.UserHook,
                        user_func=function,
                        length=length)
        return inner

from .errors import AngrError
from .factory import AngrObjectFactory
from .simos import SimOS, os_mapping
from .extern_obj import AngrExternObject
from .analysis import Analyses
from .surveyor import Surveyors
from .knowledge_base import KnowledgeBase
from .engines import SimEngineFailure, SimEngineSyscall, SimEngineHook
