import logging
import os
import types
import weakref
from collections import defaultdict

import archinfo
import cle
from cle.address_translator import AT

l = logging.getLogger("angr.project")

# This holds the default execution engine for a given CLE loader backend.
# All the builtins right now use SimEngineVEX.  This may not hold for long.


def global_default(): return {'any': SimEngineVEX}
default_engines = defaultdict(global_default)


def register_default_engine(loader_backend, engine, arch='any'):
    """
    Register the default execution engine to be used with a given CLE backend.
    Usually this is the SimEngineVEX, but if you're operating on something that isn't
    going to be lifted to VEX, you'll need to make sure the desired engine is registered here.

    :param loader_backend: The loader backend (a type)
    :param type engine: The engine to use for the loader backend (a type)
    :param arch: The architecture to associate with this engine. Optional.
    :return:
    """
    if not isinstance(loader_backend, type):
        raise TypeError("loader_backend must be a type")
    if not isinstance(engine, type):
        raise TypeError("engine must be a type")
    default_engines[loader_backend][arch] = engine


def get_default_engine(loader_backend, arch='any'):
    """
    Get some sort of sane default for a given loader and/or arch.
    Can be set with register_default_engine()
    :param loader_backend:
    :param arch:
    :return:
    """
    matches = default_engines[loader_backend]
    for k,v in matches.items():
        if k == arch or k == 'any':
            return v
    return None

projects = weakref.WeakValueDictionary()


def fake_project_unpickler(name):
    if name not in projects:
        raise AngrError("Project %s has not been opened." % name)
    return projects[name]
fake_project_unpickler.__safe_for_unpickling__ = True


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
                 support_selfmodifying_code=False,
                 **kwargs):
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
        :param translation_cache:           If True, cache translated basic blocks rather than re-translating them.
        :param support_selfmodifying_code:  Whether we support self-modifying code. When enabled, Project.sim_block()
                                            will try to read code from the current state instead of the original memory
                                            regions.
        :type  support_selfmodifying_code:  bool

        Any additional keyword arguments passed will be passed onto ``cle.Loader``.
        """

        # Step 1: Load the binary
        if load_options is None: load_options = {}
        load_options.update(kwargs)

        if isinstance(thing, cle.Loader):
            if load_options:
                l.warning("You provided CLE options to angr but you also provided a completed cle.Loader object!")
            self.loader = thing
            self.filename = self.loader.main_object.binary
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
            self.arch = archinfo.arch_from_id(arch)  # may raise ArchError, let the user see this
        elif isinstance(arch, archinfo.Arch):
            self.arch = arch
        elif arch is None:
            self.arch = self.loader.main_object.arch
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
        self._executing = False # this is a flag for the convenience API, exec() and terminate_execution() below

        if self._support_selfmodifying_code:
            if translation_cache is True:
                translation_cache = False
                l.warning("Disabling IRSB translation cache because support for self-modifying code is enabled.")

        # Look up the default engine.
        engine_cls = get_default_engine(type(self.loader.main_object))
        if not engine_cls:
            raise AngrError("No engine associated with loader %s" % str(type(self.loader.main_object)))
        engine = engine_cls(
                stop_points=self._sim_procedures,
                use_cache=translation_cache,
                support_selfmodifying_code=support_selfmodifying_code)
        procedure_engine = SimEngineHook(self)
        failure_engine = SimEngineFailure(self)
        syscall_engine = SimEngineSyscall(self)
        unicorn_engine = SimEngineUnicorn(self._sim_procedures)

        self.entry = self.loader.main_object.entry
        self.factory = AngrObjectFactory(
                self,
                engine,
                procedure_engine,
                [failure_engine, syscall_engine, procedure_engine, unicorn_engine, engine])
        self.analyses = Analyses(self)
        self.surveyors = Surveyors(self)
        self.kb = KnowledgeBase(self, self.loader.main_object)

        if self.filename is not None:
            projects[self.filename] = self

        # Step 4: determine the guest OS
        if isinstance(simos, type) and issubclass(simos, SimOS):
            self._simos = simos(self) #pylint:disable=invalid-name
        elif simos is None:
            self._simos = os_mapping[self.loader.main_object.os](self)
        else:
            raise ValueError("Invalid OS specification or non-matching architecture.")

        # Step 5: Register simprocedures as appropriate for library functions
        for obj in self.loader.initial_load_objects:
            self._register_object(obj)

        # Step 6: Run OS-specific configuration
        self._simos.configure_project()

    def _register_object(self, obj):
        """
        This scans through an objects imports and hooks them with simprocedures from our library whenever possible
        """

        # Step 1: get the set of libraries we are allowed to use to resolve unresolved symbols
        missing_libs = []
        for lib_name in self.loader.missing_dependencies:
            try:
                missing_libs.append(SIM_LIBRARIES[lib_name])
            except KeyError:
                l.info("There are no simprocedures for missing library %s :(", lib_name)

        # Step 2: Categorize every "import" symbol in each object.
        # If it's IGNORED, mark it for stubbing
        # If it's blacklisted, don't process it
        # If it matches a simprocedure we have, replace it
        for reloc in obj.imports.itervalues():
            # Step 2.1: Quick filter on symbols we really don't care about
            func = reloc.symbol
            if func is None:
                continue
            if not func.is_function:
                continue
            if not reloc.resolved:
                l.debug("Ignoring unresolved import '%s' from %s ...?", func.name, reloc.owner_obj)
                continue
            if self.is_hooked(reloc.symbol.resolvedby.rebased_addr):
                l.debug("Already hooked %s (%s)", func.name, reloc.owner_obj)
                continue

            # Step 2.2: If this function has been resolved by a static dependency,
            # check if we actually can and want to replace it with a SimProcedure.
            # We opt out of this step if it is blacklisted by ignore_functions, which
            # will cause it to be replaced by ReturnUnconstrained later.
            if func.resolved and func.resolvedby.owner_obj is not self.loader.extern_object and \
                    func.name not in self._ignore_functions:
                if self._check_user_blacklists(func.name):
                    continue
                owner_name = func.resolvedby.owner_obj.provides
                if isinstance(self.loader.main_object, cle.backends.pe.PE):
                    owner_name = owner_name.lower()
                if owner_name not in SIM_LIBRARIES:
                    continue
                sim_lib = SIM_LIBRARIES[owner_name]
                if not sim_lib.has_implementation(func.name):
                    continue
                l.info("Using builtin SimProcedure for %s from %s", func.name, sim_lib.name)
                self.hook_symbol(func.name, sim_lib.get(func.name, self.arch))

            # Step 2.3: If 2.2 didn't work, check if the symbol wants to be resolved
            # by a library we already know something about. Resolve it appropriately.
            # Note that _check_user_blacklists also includes _ignore_functions.
            # An important consideration is that even if we're stubbing a function out,
            # we still want to try as hard as we can to figure out where it comes from
            # so we can get the calling convention as close to right as possible.
            elif reloc.resolvewith is not None and reloc.resolvewith in SIM_LIBRARIES:
                sim_lib = SIM_LIBRARIES[reloc.resolvewith]
                if self._check_user_blacklists(func.name):
                    if not func.is_weak:
                        l.info("Using stub SimProcedure for unresolved %s from %s", func.name, sim_lib.name)
                        self.hook_symbol(func.name, sim_lib.get_stub(func.name, self.arch))
                else:
                    l.info("Using builtin SimProcedure for unresolved %s from %s", func.name, sim_lib.name)
                    self.hook_symbol(func.name, sim_lib.get(func.name, self.arch))

            # Step 2.4: If 2.3 didn't work (the symbol didn't request a provider we know of), try
            # looking through each of the SimLibraries we're using to resolve unresolved
            # functions. If any of them know anything specifically about this function,
            # resolve it with that. As a final fallback, just ask any old SimLibrary
            # to resolve it.
            elif missing_libs:
                for sim_lib in missing_libs:
                    if sim_lib.has_metadata(func.name):
                        if self._check_user_blacklists(func.name):
                            if not func.is_weak:
                                l.info("Using stub SimProcedure for unresolved %s from %s", func.name, sim_lib.name)
                                self.hook_symbol(func.name, sim_lib.get_stub(func.name, self.arch))
                        else:
                            l.info("Using builtin SimProcedure for unresolved %s from %s", func.name, sim_lib.name)
                            self.hook_symbol(func.name, sim_lib.get(func.name, self.arch))
                        break
                else:
                    if not func.is_weak:
                        l.info("Using stub SimProcedure for unresolved %s", func.name)
                        self.hook_symbol(func.name, missing_libs[0].get(func.name, self.arch))

            # Step 2.5: If 2.4 didn't work (we have NO SimLibraries to work with), just
            # use the vanilla ReturnUnconstrained, assuming that this isn't a weak func
            elif not func.is_weak:
                l.info("Using stub SimProcedure for unresolved %s", func.name)
                self.hook_symbol(func.name, SIM_PROCEDURES['stubs']['ReturnUnconstrained']())

    def _check_user_blacklists(self, f):
        """
        Has symbol name `f` been marked for exclusion by any of the user
        parameters?
        """
        return not self._should_use_sim_procedures or \
            f in self._exclude_sim_procedures_list or \
            f in self._ignore_functions or \
            (self._exclude_sim_procedures_func is not None and self._exclude_sim_procedures_func(f))

    #
    # Public methods
    # They're all related to hooking!
    #

    def hook(self, addr, hook=None, length=0, kwargs=None):
        """
        Hook a section of code with a custom function. This is used internally to provide symbolic
        summaries of library functions, and can be used to instrument execution or to modify
        control flow.

        When hook is not specified, it returns a function decorator that allows easy hooking.
        Usage:
        # Assuming proj is an instance of angr.Project, we will add a custom hook at the entry
        # point of the project.
        @proj.hook(proj.entry)
        def my_hook(state):
            print "Hola! My hook is called!"

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
        if hook is None:
            # if we haven't been passed a thing to hook with, assume we're being used as a decorator
            return self._hook_decorator(addr, length=length, kwargs=kwargs)

        if kwargs is None: kwargs = {}

        l.debug('hooking %#x with %s', addr, hook)

        if self.is_hooked(addr):
            l.warning("Address is already hooked [hook(%#x, %s)]. Not re-hooking.", addr, hook)
            return

        if isinstance(hook, type):
            if once("hook_instance_warning"):
                l.critical("Hooking with a SimProcedure instance is deprecated! Please hook with an instance.")
            hook = hook(**kwargs)

        if callable(hook):
            hook = SIM_PROCEDURES['stubs']['UserHook'](user_func=hook, length=length, **kwargs)

        self._sim_procedures[addr] = hook

    def is_hooked(self, addr):
        """
        Returns True if `addr` is hooked.

        :param addr: An address.
        :returns:    True if addr is hooked, False otherwise.
        """
        return addr in self._sim_procedures

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

    def unhook(self, addr):
        """
        Remove a hook.

        :param addr:    The address of the hook.
        """
        if not self.is_hooked(addr):
            l.warning("Address %#x not hooked", addr)
            return

        del self._sim_procedures[addr]

    def hook_symbol(self, symbol_name, obj, kwargs=None):
        """
        Resolve a dependency in a binary. Uses the "externs object" (project.loader.extern_object) to
        allocate an address for a new symbol in the binary, and then tells the loader to re-perform
        the relocation process, taking into account the new symbol.

        :param symbol_name: The name of the dependency to resolve.
        :param obj:         The thing with which to satisfy the dependency.
        :param kwargs:      If you provide a SimProcedure for the hook, these are the keyword
                            arguments that will be passed to the procedure's `run` method
                            eventually.
        :returns:           The address of the new symbol.
        :rtype:             int
        """
        if type(obj) in (int, long):
            # this is pretty intensely sketchy
            l.info("Instructing the loader to re-point symbol %s at address %#x", symbol_name, obj)
            self.loader.provide_symbol(self.loader.extern_object, symbol_name, AT.from_mva(obj, self.loader.extern_object).to_rva())
            return obj

        sym = self.loader.find_symbol(symbol_name)
        if sym is None:
            l.error("Could not find symbol %s", symbol_name)
            return None

        hook_addr, _ = self._simos.prepare_function_symbol(symbol_name, basic_addr=sym.rebased_addr)

        if self.is_hooked(hook_addr):
            l.warning("Re-hooking symbol %s", symbol_name)
            self.unhook(hook_addr)

        self.hook(hook_addr, obj, kwargs=kwargs)
        return hook_addr

    def hook_symbol_batch(self, hooks):
        """
        Hook many symbols at once.

        :param dict hooks:     A mapping from symbol name to hook
        """

        if once("hook_symbol_batch warning"):
            l.critical("Due to advances in technology, hook_symbol_batch is no longer necessary for performance. Please use hook_symbol several times.")

        for x in hooks:
            self.hook_symbol(x, hooks[x])

    def is_symbol_hooked(self, symbol_name):
        """
        Check if a symbol is already hooked.

        :param str symbol_name: Name of the symbol.
        :return: True if the symbol can be resolved and is hooked, False otherwise.
        :rtype: bool
        """
        sym = self.loader.find_symbol(symbol_name)
        if sym is None:
            l.warning("Could not find symbol %s", symbol_name)
            return False
        hook_addr, _ = self._simos.prepare_function_symbol(symbol_name, basic_addr=sym.rebased_addr)
        return self.is_hooked(hook_addr)

    #
    # A convenience API (in the style of triton and manticore) for symbolic execution.
    #

    def execute(self, *args, **kwargs):
        """
        This function is a symbolic execution helper in the simple style
        supported by triton and manticore. It designed to be run after
        setting up hooks (see Project.hook), in which the symbolic state
        can be checked.

        This function can be run in three different ways:

        - When run with no parameters, this function begins symbolic execution
        from the entrypoint.
        - It can also be run with a "state" parameter specifying a SimState to
          begin symbolic execution from.
        - Finally, it can accept any arbitrary keyword arguments, which are all
          passed to project.factory.full_init_state.

        If symbolic execution finishes, this function returns the resulting
        SimulationManager.
        """

        if args:
            state = args[0]
        else:
            state = self.factory.full_init_state(**kwargs)

        pg = self.factory.simgr(state)
        self._executing = True
        return pg.step(until=lambda lpg: not self._executing)

    def terminate_execution(self):
        """
        Terminates a symbolic execution that was started with Project.execute().
        """
        self._executing = False

    #
    # Private methods related to hooking
    #

    def _hook_decorator(self, addr, length=0, kwargs=None):
        """
        Return a function decorator that allows easy hooking. Please refer to hook() for its usage.

        :return: The function decorator.
        """

        def hook_decorator(func):
            self.hook(addr, func, length=length, kwargs=kwargs)

        return hook_decorator

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


from .errors import AngrError
from .factory import AngrObjectFactory
from .simos import SimOS, os_mapping
from .analyses.analysis import Analyses
from .surveyors import Surveyors
from .knowledge_base import KnowledgeBase
from .engines import SimEngineFailure, SimEngineSyscall, SimEngineHook, SimEngineVEX, SimEngineUnicorn
from .misc.ux import once
from .procedures import SIM_PROCEDURES, SIM_LIBRARIES
