import logging
import os
import types
from io import BytesIO, IOBase
import pickle
import string
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any, Optional

import archinfo
from archinfo.arch_soot import SootAddressDescriptor, ArchSoot
import cle
from .sim_procedure import SimProcedure

from .misc.ux import deprecated
from .errors import AngrNoPluginError

l = logging.getLogger(name=__name__)

def load_shellcode(shellcode, arch, start_offset=0, load_address=0, thumb=False, **kwargs):
    """
    Load a new project based on a snippet of assembly or bytecode.

    :param shellcode:       The data to load, as either a bytestring of instructions or a string of assembly text
    :param arch:            The name of the arch to use, or an archinfo class
    :param start_offset:    The offset into the data to start analysis (default 0)
    :param load_address:    The address to place the data in memory (default 0)
    :param thumb:           Whether this is ARM Thumb shellcode
    """
    if not isinstance(arch, archinfo.Arch):
        arch = archinfo.arch_from_id(arch)
    if type(shellcode) is str:
        shellcode = arch.asm(shellcode, load_address, thumb=thumb)
    if thumb:
        start_offset |= 1

    return Project(
            BytesIO(shellcode),
            main_opts={
                'backend': 'blob',
                'arch': arch,
                'entry_point': start_offset,
                'base_addr': load_address,
            },
        **kwargs
        )


class Project:
    """
    This is the main class of the angr module. It is meant to contain a set of binaries and the relationships between
    them, and perform analyses on them.

    :param thing:                       The path to the main executable object to analyze, or a CLE Loader object.

    The following parameters are optional.

    :param default_analysis_mode:       The mode of analysis to use by default. Defaults to 'symbolic'.
    :param ignore_functions:            A list of function names that, when imported from shared libraries, should
                                        never be stepped into in analysis (calls will return an unconstrained value).
    :param use_sim_procedures:          Whether to replace resolved dependencies for which simprocedures are
                                        available with said simprocedures.
    :param exclude_sim_procedures_func: A function that, when passed a function name, returns whether or not to wrap
                                        it with a simprocedure.
    :param exclude_sim_procedures_list: A list of functions to *not* wrap with simprocedures.
    :param arch:                        The target architecture (auto-detected otherwise).
    :param simos:                       a SimOS class to use for this project.
    :param engine:                      The SimEngine class to use for this project.
    :param bool translation_cache:      If True, cache translated basic blocks rather than re-translating them.
    :param support_selfmodifying_code:  Whether we aggressively support self-modifying code. When enabled, emulation
                                        will try to read code from the current state instead of the original memory,
                                        regardless of the current memory protections.
    :type support_selfmodifying_code:   bool
    :param store_function:              A function that defines how the Project should be stored. Default to pickling.
    :param load_function:               A function that defines how the Project should be loaded. Default to unpickling.
    :param analyses_preset:             The plugin preset for the analyses provider (i.e. Analyses instance).
    :type analyses_preset:              angr.misc.PluginPreset

    Any additional keyword arguments passed will be passed onto ``cle.Loader``.

    :ivar analyses:     The available analyses.
    :type analyses:     angr.analysis.Analyses
    :ivar entry:        The program entrypoint.
    :ivar factory:      Provides access to important analysis elements such as path groups and symbolic execution results.
    :type factory:      AngrObjectFactory
    :ivar filename:     The filename of the executable.
    :ivar loader:       The program loader.
    :type loader:       cle.Loader
    :ivar storage:      Dictionary of things that should be loaded/stored with the Project.
    :type storage:      defaultdict(list)
    """
    analyses: "AnalysesHub"
    arch: archinfo.Arch
    def __init__(self, thing,
                 default_analysis_mode=None,
                 ignore_functions=None,
                 use_sim_procedures=True,
                 exclude_sim_procedures_func=None,
                 exclude_sim_procedures_list=(),
                 arch=None, simos=None,
                 engine=None,
                 load_options: Dict[str, Any]=None,
                 translation_cache=True,
                 support_selfmodifying_code=False,
                 store_function=None,
                 load_function=None,
                 analyses_preset=None,
                 concrete_target=None,
                 eager_ifunc_resolution=None,
                 **kwargs):

        # Step 1: Load the binary

        if load_options is None: load_options = {}

        load_options.update(kwargs)
        if arch is not None:
            load_options.update({'arch': arch})
        if isinstance(thing, cle.Loader):
            if load_options:
                l.warning("You provided CLE options to angr but you also provided a completed cle.Loader object!")
            self.loader = thing
            self.filename = self.loader.main_object.binary
        elif isinstance(thing, cle.Backend):
            self.filename = thing.binary
            self.loader = cle.Loader(thing, **load_options)
        elif hasattr(thing, 'read') and hasattr(thing, 'seek'):
            l.info("Loading binary from stream")
            self.filename = None
            self.loader = cle.Loader(thing, **load_options)
        elif not isinstance(thing, (str, Path)) or not os.path.exists(thing) or not os.path.isfile(thing):
            raise Exception("Not a valid binary file: %s" % repr(thing))
        else:
            # use angr's loader, provided by cle
            l.info("Loading binary %s", thing)
            self.filename = str(thing)
            self.loader = cle.Loader(self.filename, concrete_target=concrete_target, **load_options)

        # Step 2: determine its CPU architecture, ideally falling back to CLE's guess
        if isinstance(arch, str):
            self.arch = archinfo.arch_from_id(arch)  # may raise ArchError, let the user see this
        elif isinstance(arch, archinfo.Arch):
            self.arch = arch # type: archinfo.Arch
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
            l.warning("Passing a lambda type as the exclude_sim_procedures_func argument to "
                      "Project causes the resulting object to be un-serializable.")

        self._sim_procedures = {}

        self.concrete_target = concrete_target

        # It doesn't make any sense to have auto_load_libs
        # if you have the concrete target, let's warn the user about this.
        if self.concrete_target and load_options.get('auto_load_libs', None):

            l.critical("Incompatible options selected for this project, please disable auto_load_libs if "
                       "you want to use a concrete target.")
            raise Exception("Incompatible options for the project")

        if self.concrete_target and self.arch.name not in ['X86', 'AMD64', 'ARMHF', 'MIPS32']:
            l.critical("Concrete execution does not support yet the selected architecture. Aborting.")
            raise Exception("Incompatible options for the project")

        self._default_analysis_mode = default_analysis_mode
        self._exclude_sim_procedures_func = exclude_sim_procedures_func
        self._exclude_sim_procedures_list = exclude_sim_procedures_list
        self.use_sim_procedures = use_sim_procedures
        self._ignore_functions = ignore_functions
        self._support_selfmodifying_code = support_selfmodifying_code
        self._translation_cache = translation_cache
        self._eager_ifunc_resolution = eager_ifunc_resolution
        self._executing = False # this is a flag for the convenience API, exec() and terminate_execution() below

        if self._support_selfmodifying_code:
            if self._translation_cache is True:
                self._translation_cache = False
                l.warning("Disabling IRSB translation cache because support for self-modifying code is enabled.")

        self.entry = self.loader.main_object.entry
        self.storage = defaultdict(list)
        self.store_function = store_function or self._store
        self.load_function = load_function or self._load

        # Step 4: Set up the project's hubs
        # Step 4.1 Factory
        self.factory = AngrObjectFactory(self, default_engine=engine)

        # Step 4.2: Analyses
        self._analyses_preset = analyses_preset
        self.analyses = None
        self._initialize_analyses_hub()

        # Step 4.3: ...etc
        self.kb = KnowledgeBase(self, name="global")

        # Step 5: determine the guest OS
        if isinstance(simos, type) and issubclass(simos, SimOS):
            self.simos = simos(self) #pylint:disable=invalid-name
        elif isinstance(simos, str):
            self.simos = os_mapping[simos](self)
        elif simos is None:
            self.simos = os_mapping[self.loader.main_object.os](self)
        else:
            raise ValueError("Invalid OS specification or non-matching architecture.")

        self.is_java_project = isinstance(self.arch, ArchSoot)
        self.is_java_jni_project = isinstance(self.arch, ArchSoot) and self.simos.is_javavm_with_jni_support

        # Step 6: Register simprocedures as appropriate for library functions
        if isinstance(self.arch, ArchSoot) and self.simos.is_javavm_with_jni_support:
            # If we execute a Java archive that includes native JNI libraries,
            # we need to use the arch of the native simos for all (native) sim
            # procedures.
            sim_proc_arch = self.simos.native_arch
        else:
            sim_proc_arch = self.arch
        for obj in self.loader.initial_load_objects:
            self._register_object(obj, sim_proc_arch)

        # Step 7: Run OS-specific configuration
        self.simos.configure_project()

    def _initialize_analyses_hub(self):
        """
        Initializes self.analyses using a given preset.
        """
        self.analyses = AnalysesHub(self)
        self.analyses.use_plugin_preset(self._analyses_preset if self._analyses_preset is not None else 'default')

    def _register_object(self, obj, sim_proc_arch):
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
        # additionally provide libraries we _have_ loaded as a fallback fallback
        # this helps in the case that e.g. CLE picked up a linux arm libc to satisfy an android arm binary
        for lib in self.loader.all_objects:
            if lib.provides in SIM_LIBRARIES:
                simlib = SIM_LIBRARIES[lib.provides]
                if simlib not in missing_libs:
                    missing_libs.append(simlib)

        # Step 2: Categorize every "import" symbol in each object.
        # If it's IGNORED, mark it for stubbing
        # If it's blacklisted, don't process it
        # If it matches a simprocedure we have, replace it
        for reloc in obj.imports.values():
            # Step 2.1: Quick filter on symbols we really don't care about
            func = reloc.symbol
            if func is None:
                continue
            if not func.is_function and func.type != cle.backends.symbol.SymbolType.TYPE_NONE:
                continue
            if func.resolvedby is None:
                # I don't understand the binary which made me add this case. If you are debugging and see this comment,
                # good luck.
                # ref: https://github.com/angr/angr/issues/1782
                # (I also don't know why the TYPE_NONE check in the previous clause is there but I can't find a ref for
                # that. they are probably related.)
                # (I believe the TYPE_NONE check is to support ELF object files)
                continue
            if not reloc.resolved:
                # This is a hack, effectively to support Binary Ninja, which doesn't provide access to dependency
                # library names. The backend creates the Relocation objects, but leaves them unresolved so that
                # we can try to guess them here.
                if reloc.owner.guess_simprocs:
                    l.debug("Looking for matching SimProcedure for unresolved %s from %s with hint %s",
                            func.name, reloc.owner, reloc.owner.guess_simprocs_hint)
                    self._guess_simprocedure(func, reloc.owner.guess_simprocs_hint)
                else:
                    l.debug("Ignoring unresolved import '%s' from %s ...?", func.name, reloc.owner)
                continue
            export = reloc.resolvedby
            if self.is_hooked(export.rebased_addr):
                l.debug("Already hooked %s (%s)", export.name, export.owner)
                continue

            # Step 2.2: If this function has been resolved by a static dependency,
            # check if we actually can and want to replace it with a SimProcedure.
            # We opt out of this step if it is blacklisted by ignore_functions, which
            # will cause it to be replaced by ReturnUnconstrained later.
            if export.owner is not self.loader._extern_object and \
                    export.name not in self._ignore_functions:
                if self._check_user_blacklists(export.name):
                    continue
                owner_name = export.owner.provides
                if isinstance(self.loader.main_object, cle.backends.pe.PE):
                    owner_name = owner_name.lower()
                if owner_name not in SIM_LIBRARIES:
                    continue
                sim_lib = SIM_LIBRARIES[owner_name]
                if not sim_lib.has_implementation(export.name):
                    continue
                l.info("Using builtin SimProcedure for %s from %s", export.name, sim_lib.name)
                self.hook_symbol(export.rebased_addr, sim_lib.get(export.name, sim_proc_arch))

            # Step 2.3: If 2.2 didn't work, check if the symbol wants to be resolved
            # by a library we already know something about. Resolve it appropriately.
            # Note that _check_user_blacklists also includes _ignore_functions.
            # An important consideration is that even if we're stubbing a function out,
            # we still want to try as hard as we can to figure out where it comes from
            # so we can get the calling convention as close to right as possible.
            elif reloc.resolvewith is not None and reloc.resolvewith in SIM_LIBRARIES:
                sim_lib = SIM_LIBRARIES[reloc.resolvewith]
                if self._check_user_blacklists(export.name):
                    if not func.is_weak:
                        l.info("Using stub SimProcedure for unresolved %s from %s", func.name, sim_lib.name)
                        self.hook_symbol(export.rebased_addr, sim_lib.get_stub(export.name, sim_proc_arch))
                else:
                    l.info("Using builtin SimProcedure for unresolved %s from %s", export.name, sim_lib.name)
                    self.hook_symbol(export.rebased_addr, sim_lib.get(export.name, sim_proc_arch))

            # Step 2.4: If 2.3 didn't work (the symbol didn't request a provider we know of), try
            # looking through each of the SimLibraries we're using to resolve unresolved
            # functions. If any of them know anything specifically about this function,
            # resolve it with that. As a final fallback, just ask any old SimLibrary
            # to resolve it.
            elif missing_libs:
                for sim_lib in missing_libs:
                    if sim_lib.has_metadata(export.name):
                        if self._check_user_blacklists(export.name):
                            if not func.is_weak:
                                l.info("Using stub SimProcedure for unresolved %s from %s", export.name, sim_lib.name)
                                self.hook_symbol(export.rebased_addr, sim_lib.get_stub(export.name, sim_proc_arch))
                        else:
                            l.info("Using builtin SimProcedure for unresolved %s from %s", export.name, sim_lib.name)
                            self.hook_symbol(export.rebased_addr, sim_lib.get(export.name, sim_proc_arch))
                        break
                else:
                    if not func.is_weak:
                        l.info("Using stub SimProcedure for unresolved %s", export.name)
                        the_lib = missing_libs[0]
                        if export.name and export.name.startswith("_Z"):
                            # GNU C++ name. Use a C++ library to create the stub
                            if 'libstdc++.so' in SIM_LIBRARIES:
                                the_lib = SIM_LIBRARIES['libstdc++.so']
                            else:
                                l.critical("Does not find any C++ library in SIM_LIBRARIES. We may not correctly "
                                           "create the stub or resolve the function prototype for name %s.", export.name)

                        self.hook_symbol(export.rebased_addr, the_lib.get(export.name, sim_proc_arch))

            # Step 2.5: If the requesting object wants us to guess simprocedures, do the guessing
            elif reloc.owner.guess_simprocs and self._guess_simprocedure(func, reloc.owner.guess_simprocs_hint):
                continue

            # Step 2.6: If 2.4/2.5 didn't work (we have NO SimLibraries to work with), just
            # use the vanilla ReturnUnconstrained, assuming that this isn't a weak func
            elif not func.is_weak:
                l.info("Using stub SimProcedure for unresolved %s", export.name)
                self.hook_symbol(export.rebased_addr, SIM_PROCEDURES['stubs']['ReturnUnconstrained'](display_name=export.name, is_stub=True))

    def _guess_simprocedure(self, f, hint):
        """
        Does symbol name `f` exist as a SIM_PROCEDURE? If so, return it, else return None.
        Narrows down the set of libraries to search based on hint.
        """
        # First, filter the SIM_LIBRARIES to a reasonable subset based on the hint
        if hint == "win":
            hinted_libs = filter(lambda lib: lib if lib.endswith(".dll") else None, SIM_LIBRARIES)
        else:
            hinted_libs = filter(lambda lib: lib if ".so" in lib else None, SIM_LIBRARIES)

        for lib in hinted_libs:
            if SIM_LIBRARIES[lib].has_implementation(f.name):
                l.debug("Found implementation for %s in %s", f, lib)
                if f.resolvedby:
                    hook_at = f.resolvedby.rebased_addr
                else:
                    # ????
                    hook_at = f.relative_addr
                self.hook_symbol(hook_at, (SIM_LIBRARIES[lib].get(f.name, self.arch)))
                return True

        l.debug("Could not find matching SimProcedure for %s, ignoring.", f.name)
        return False

    def _check_user_blacklists(self, f):
        """
        Has symbol name `f` been marked for exclusion by any of the user
        parameters?
        """
        return not self.use_sim_procedures or \
            f in self._exclude_sim_procedures_list or \
            f in self._ignore_functions or \
            (self._exclude_sim_procedures_func is not None and self._exclude_sim_procedures_func(f))


    @staticmethod
    def _addr_to_str(addr):
        return "%s" % repr(addr) if isinstance(addr, SootAddressDescriptor) else "%#x" % addr


    #
    # Public methods
    # They're all related to hooking!
    #

    # pylint: disable=inconsistent-return-statements
    def hook(self, addr, hook=None, length=0, kwargs=None, replace=False):
        """
        Hook a section of code with a custom function. This is used internally to provide symbolic
        summaries of library functions, and can be used to instrument execution or to modify
        control flow.

        When hook is not specified, it returns a function decorator that allows easy hooking.
        Usage::

            # Assuming proj is an instance of angr.Project, we will add a custom hook at the entry
            # point of the project.
            @proj.hook(proj.entry)
            def my_hook(state):
                print("Welcome to execution!")

        :param addr:        The address to hook.
        :param hook:        A :class:`angr.project.Hook` describing a procedure to run at the
                            given address. You may also pass in a SimProcedure class or a function
                            directly and it will be wrapped in a Hook object for you.
        :param length:      If you provide a function for the hook, this is the number of bytes
                            that will be skipped by executing the hook by default.
        :param kwargs:      If you provide a SimProcedure for the hook, these are the keyword
                            arguments that will be passed to the procedure's `run` method
                            eventually.
        :param replace:     Control the behavior on finding that the address is already hooked. If
                            true, silently replace the hook. If false (default), warn and do not
                            replace the hook. If none, warn and replace the hook.
        """
        if hook is None:
            # if we haven't been passed a thing to hook with, assume we're being used as a decorator
            return self._hook_decorator(addr, length=length, kwargs=kwargs)

        if kwargs is None: kwargs = {}

        l.debug('hooking %s with %s', self._addr_to_str(addr), str(hook))

        if self.is_hooked(addr):
            if replace is True:
                pass
            elif replace is False:
                l.warning("Address is already hooked, during hook(%s, %s). Not re-hooking.", self._addr_to_str(addr), hook)
                return
            else:
                l.warning("Address is already hooked, during hook(%s, %s). Re-hooking.", self._addr_to_str(addr), hook)

        if isinstance(hook, type):
            raise TypeError("Please instanciate your SimProcedure before hooking with it")

        if callable(hook):
            hook = SIM_PROCEDURES['stubs']['UserHook'](user_func=hook, length=length, **kwargs)

        self._sim_procedures[addr] = hook

    def is_hooked(self, addr) -> bool:
        """
        Returns True if `addr` is hooked.

        :param addr: An address.
        :returns:    True if addr is hooked, False otherwise.
        """
        return addr in self._sim_procedures

    def hooked_by(self, addr) -> Optional[SimProcedure]:
        """
        Returns the current hook for `addr`.

        :param addr: An address.

        :returns:    None if the address is not hooked.
        """

        if not self.is_hooked(addr):
            l.warning("Address %s is not hooked", self._addr_to_str(addr))
            return None

        return self._sim_procedures[addr]

    def unhook(self, addr):
        """
        Remove a hook.

        :param addr:    The address of the hook.
        """
        if not self.is_hooked(addr):
            l.warning("Address %s not hooked", self._addr_to_str(addr))
            return

        del self._sim_procedures[addr]

    def hook_symbol(self, symbol_name, simproc, kwargs=None, replace=None):
        """
        Resolve a dependency in a binary. Looks up the address of the given symbol, and then hooks that
        address. If the symbol was not available in the loaded libraries, this address may be provided
        by the CLE externs object.

        Additionally, if instead of a symbol name you provide an address, some secret functionality will
        kick in and you will probably just hook that address, UNLESS you're on powerpc64 ABIv1 or some
        yet-unknown scary ABI that has its function pointers point to something other than the actual
        functions, in which case it'll do the right thing.

        :param symbol_name: The name of the dependency to resolve.
        :param simproc:     The SimProcedure instance (or function) with which to hook the symbol
        :param kwargs:      If you provide a SimProcedure for the hook, these are the keyword
                            arguments that will be passed to the procedure's `run` method
                            eventually.
        :param replace:     Control the behavior on finding that the address is already hooked. If
                            true, silently replace the hook. If false, warn and do not replace the
                            hook. If none (default), warn and replace the hook.
        :returns:           The address of the new symbol.
        :rtype:             int
        """
        if type(symbol_name) is not int:
            sym = self.loader.find_symbol(symbol_name)
            if sym is None:
                # it could be a previously unresolved weak symbol..?
                new_sym = None
                for reloc in self.loader.find_relevant_relocations(symbol_name):
                    if not reloc.symbol.is_weak:
                        raise Exception("Symbol is strong but we couldn't find its resolution? Report to @rhelmot.")
                    if new_sym is None:
                        new_sym = self.loader.extern_object.make_extern(symbol_name)
                    reloc.resolve(new_sym)
                    reloc.relocate([])

                if new_sym is None:
                    l.error("Could not find symbol %s", symbol_name)
                    return None
                sym = new_sym

            basic_addr = sym.rebased_addr
        else:
            basic_addr = symbol_name
            symbol_name = None

        hook_addr, _ = self.simos.prepare_function_symbol(symbol_name, basic_addr=basic_addr)

        self.hook(hook_addr, simproc, kwargs=kwargs, replace=replace)
        return hook_addr

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
        hook_addr, _ = self.simos.prepare_function_symbol(symbol_name, basic_addr=sym.rebased_addr)
        return self.is_hooked(hook_addr)

    def unhook_symbol(self, symbol_name):
        """
        Remove the hook on a symbol.
        This function will fail if the symbol is provided by the extern object, as that would result in a state where
        analysis would be unable to cope with a call to this symbol.
        """
        sym = self.loader.find_symbol(symbol_name)
        if sym is None:
            l.warning("Could not find symbol %s", symbol_name)
            return False
        if sym.owner is self.loader._extern_object:
            l.warning("Refusing to unhook external symbol %s, replace it with another hook if you want to change it",
                      symbol_name)
            return False

        hook_addr, _ = self.simos.prepare_function_symbol(symbol_name, basic_addr=sym.rebased_addr)
        self.unhook(hook_addr)
        return True

    def rehook_symbol(self, new_address, symbol_name, stubs_on_sync):
        """
        Move the hook for a symbol to a specific address
        :param new_address: the new address that will trigger the SimProc execution
        :param symbol_name: the name of the symbol (f.i. strcmp )
        :return: None
        """
        new_sim_procedures = {}
        for key_address, simproc_obj in self._sim_procedures.items():

            # if we don't want stubs during the sync let's skip those, we will execute the real function.
            if not stubs_on_sync and simproc_obj.is_stub:
                continue

            if simproc_obj.display_name == symbol_name:
                new_sim_procedures[new_address] = simproc_obj
            else:
                new_sim_procedures[key_address] = simproc_obj

        self._sim_procedures = new_sim_procedures

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
        simulation manager.
        """

        if args:
            state = args[0]
        else:
            state = self.factory.full_init_state(**kwargs)

        pg = self.factory.simulation_manager(state)
        self._executing = True
        return pg.run(until=lambda lpg: not self._executing)

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
            return func

        return hook_decorator

    #
    # Pickling
    #

    def __getstate__(self):
        try:
            store_func, load_func = self.store_function, self.load_function
            self.store_function, self.load_function = None, None
            # ignore analyses. we re-initialize analyses when restoring from pickling so that we do not lose any newly
            # added analyses classes
            d = dict((k, v) for k, v in self.__dict__.items() if k not in {'analyses', })
            return d
        finally:
            self.store_function, self.load_function = store_func, load_func

    def __setstate__(self, s):
        self.__dict__.update(s)
        try:
            self._initialize_analyses_hub()
        except AngrNoPluginError:
            l.warning("Plugin preset %s does not exist any more. Fall back to the default preset.")
            self._analyses_preset = 'default'
            self._initialize_analyses_hub()

    def _store(self, container):
        # If container is a filename.
        if isinstance(container, str):
            with open(container, 'wb') as f:
                try:
                    pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)
                except RuntimeError as e: # maximum recursion depth can be reached here
                    l.error("Unable to store Project: '%s' during pickling", e)

        # If container is an open file.
        elif isinstance(container, IOBase):
            try:
                pickle.dump(self, container, pickle.HIGHEST_PROTOCOL)
            except RuntimeError as e: # maximum recursion depth can be reached here
                l.error("Unable to store Project: '%s' during pickling", e)

        # If container is just a variable.
        else:
            try:
                container = pickle.dumps(self, pickle.HIGHEST_PROTOCOL)
            except RuntimeError as e: # maximum recursion depth can be reached here
                l.error("Unable to store Project: '%s' during pickling", e)

    @staticmethod
    def _load(container):
        if isinstance(container, str):
            # If container is a filename.
            if all(c in string.printable for c in container) and os.path.exists(container):
                with open(container, 'rb') as f:
                    return pickle.load(f)

            # If container is a pickle string.
            else:
                return pickle.loads(container)

        # If container is an open file
        elif isinstance(container, IOBase):
            return pickle.load(container)

        # What else could it be?
        else:
            l.error("Cannot unpickle container of type %s", type(container))
            return None

    def __repr__(self):
        return '<Project %s>' % (self.filename if self.filename is not None else 'loaded from stream')

    #
    # Compatibility
    #

    @property
    @deprecated(replacement='simos')
    def _simos(self):
        return self.simos


from .factory import AngrObjectFactory
from angr.simos import SimOS, os_mapping
from .analyses.analysis import AnalysesHub
from .knowledge_base import KnowledgeBase
from .procedures import SIM_PROCEDURES, SIM_LIBRARIES
