from simuvex import SimState
from simuvex import s_cc
from .surveyors.caller import Callable

import logging
l = logging.getLogger('angr.factory')

_deprecation_cache = set()
def deprecate(name, replacement):
    def wrapper(func):
        def inner(*args, **kwargs):
            if name not in _deprecation_cache:
                l.warning("factory.%s is deprecated! Please use factory.%s instead.", name, replacement)
                _deprecation_cache.add(name)
            return func(*args, **kwargs)
        return inner
    return wrapper

class AngrObjectFactory(object):
    """
    This factory provides access to important analysis elements.
    """
    def __init__(self, project, default_engine, procedure_engine, engines):
        # currently the default engine MUST be a vex engine... this assumption is hardcoded
        # but this can totally be changed with some interface generalization
        self._project = project
        self._default_cc = s_cc.DefaultCC[project.arch.name]

        self.default_engine = default_engine
        self.procedure_engine = procedure_engine
        self.engines = engines

    def snippet(self, addr, jumpkind=None, **block_opts):
        if self._project.is_hooked(addr) and jumpkind != 'Ijk_NoHook':
            hook = self._project._sim_procedures[addr]
            size = hook.kwargs.get('length', 0)
            return HookNode(addr, size, self._project.hooked_by(addr))
        else:
            return self.block(addr, **block_opts).codenode # pylint: disable=no-member

    def successors(self, state,
            addr=None,
            jumpkind=None,
            inline=False,
            default_engine=False,
            engines=None,
            **kwargs):
        """
        Perform execution using any applicable engine. Enumerate the current engines and use the
        first one that works. Return a SimSuccessors object classifying the results of the run.

        :param state:           The state to analyze
        :param addr:            optional, an address to execute at instead of the state's ip
        :param jumpkind:        optional, the jumpkind of the previous exit
        :param inline:          This is an inline execution. Do not bother copying the state.
        :param default_engine   Whether we should only attempt to use the default engine
                                (usually VEX)
        :param engines:         A list of engines to try to use, instead of the default.

        Additional keyword arguments will be passed directly into each engine's process method.
        """

        if default_engine:
            engines = [self.default_engine]
        if engines is None:
            engines = self.engines

        if addr is not None or jumpkind is not None:
            state = state.copy()
            if addr is not None:
                state.ip = addr
            if jumpkind is not None:
                state.scratch.jumpkind = jumpkind

        r = None
        for engine in engines:
            if engine.check(state, inline=inline, **kwargs):
                r = engine.process(state, inline=inline,**kwargs)
                if r.processed:
                    break

        if r is None or not r.processed:
            raise AngrExitError("All engines failed to execute!")

        # Peek and fix the IP for syscalls
        if r.successors and r.successors[0].scratch.jumpkind.startswith('Ijk_Sys'):
            self._fix_syscall_ip(r.successors[0])

        return r

    def blank_state(self, **kwargs):
        """
        Returns a mostly-uninitialized state object. All parameters are optional.

        :param addr:            The address the state should start at instead of the entry point.
        :param initial_prefix:  If this is provided, all symbolic registers will hold symbolic values with names
                                prefixed by this string.
        :param fs:              A dictionary of file names with associated preset SimFile objects.
        :param concrete_fs:     bool describing whether the host filesystem should be consulted when opening files.
        :param chroot:          A path to use as a fake root directory, Behaves similarly to a real chroot. Used only
                                when concrete_fs is set to True.
        :param kwargs:          Any additional keyword args will be passed to the SimState constructor.
        :return:                The blank state.
        :rtype:                 simuvex.s_state.SimState
        """
        return self._project._simos.state_blank(**kwargs)

    def entry_state(self, **kwargs):
        """
        Returns a state object representing the program at its entry point. All parameters are optional.

        :param addr:            The address the state should start at instead of the entry point.
        :param initial_prefix:  If this is provided, all symbolic registers will hold symbolic values with names
                                prefixed by this string.
        :param fs:              a dictionary of file names with associated preset SimFile objects.
        :param concrete_fs:     boolean describing whether the host filesystem should be consulted when opening files.
        :param chroot:          a path to use as a fake root directory, behaves similar to a real chroot. used only when
                                concrete_fs is set to True.
        :param argc:            a custom value to use for the program's argc. May be either an int or a bitvector. If
                                not provided, defaults to the length of args.
        :param args:            a list of values to use as the program's argv. May be mixed strings and bitvectors.
        :param env:             a dictionary to use as the environment for the program. Both keys and values may be
                                mixed strings and bitvectors.
        :return:                The entry state.
        :rtype:                 simuvex.s_state.SimState
        """

        return self._project._simos.state_entry(**kwargs)

    def full_init_state(self, **kwargs):
        """
        Very much like :meth:`entry_state()`, except that instead of starting execution at the program entry point,
        execution begins at a special SimProcedure that plays the role of the dynamic loader, calling each of the
        initializer functions that should be called before execution reaches the entry point.

        :param addr:            The address the state should start at instead of the entry point.
        :param initial_prefix:  If this is provided, all symbolic registers will hold symbolic values with names
                                prefixed by this string.
        :param fs:              a dictionary of file names with associated preset SimFile objects.
        :param concrete_fs:     boolean describing whether the host filesystem should be consulted when opening files.
        :param chroot:          a path to use as a fake root directory, behaves similar to a real chroot. used only when
                                concrete_fs is set to True.
        :param argc:            a custom value to use for the program's argc. May be either an int or a bitvector. If
                                not provided, defaults to the length of args.
        :param args:            a list of values to use as arguments to the program. May be mixed strings and bitvectors.
        :param env:             a dictionary to use as the environment for the program. Both keys and values may be
                                mixed strings and bitvectors.
        :return:                The fully initialized state.
        :rtype:                 simuvex.s_state.SimState
        """
        return self._project._simos.state_full_init(**kwargs)

    def call_state(self, addr, *args, **kwargs):
        """
        Returns a state object initialized to the start of a given function, as if it were called with given parameters.

        :param addr:            The address the state should start at instead of the entry point.
        :param args:            Any additional positional arguments will be used as arguments to the function call.

        The following parametrs are optional.

        :param base_state:      Use this SimState as the base for the new state instead of a blank state.
        :param cc:              Optionally provide a SimCC object to use a specific calling convention.
        :param ret_addr:        Use this address as the function's return target.
        :param stack_base:      An optional pointer to use as the top of the stack, circa the function entry point
        :param alloc_base:      An optional pointer to use as the place to put excess argument data
        :param grow_like_stack: When allocating data at alloc_base, whether to allocate at decreasing addresses
        :param toc:             The address of the table of contents for ppc64
        :param initial_prefix:  If this is provided, all symbolic registers will hold symbolic values with names
                                prefixed by this string.
        :param fs:              A dictionary of file names with associated preset SimFile objects.
        :param concrete_fs:     bool describing whether the host filesystem should be consulted when opening files.
        :param chroot:          A path to use as a fake root directory, Behaves similarly to a real chroot. Used only
                                when concrete_fs is set to True.
        :param kwargs:          Any additional keyword args will be passed to the SimState constructor.
        :return:                The state at the beginning of the function.
        :rtype:                 simuvex.s_state.SimState

        The idea here is that you can provide almost any kind of python type in `args` and it'll be translated to a
        binary format to be placed into simulated memory. Lists (representing arrays) must be entirely elements of the
        same type and size, while tuples (representing structs) can be elements of any type and size.
        If you'd like there to be a pointer to a given value, wrap the value in a `SimCC.PointerWrapper`. Any value
        that can't fit in a register will be automatically put in a
        PointerWrapper.

        If stack_base is not provided, the current stack pointer will be used, and it will be updated.
        If alloc_base is not provided, the current stack pointer will be used, and it will be updated.
        You might not like the results if you provide stack_base but not alloc_base.

        grow_like_stack controls the behavior of allocating data at alloc_base. When data from args needs to be wrapped
        in a pointer, the pointer needs to point somewhere, so that data is dumped into memory at alloc_base. If you
        set alloc_base to point to somewhere other than the stack, set grow_like_stack to False so that sequencial
        allocations happen at increasing addresses.
        """
        return self._project._simos.state_call(addr, *args, **kwargs)

    def path(self, state=None, **kwargs):
        """
        Constructs a new path.

        :param state:           Optional - The state to start the new path at. If not provided, an
                                :meth:`entry_state()` will be constructed using any additional keyword arguments
                                provided.
        :return:                The new path.
        :rtype:                 angr.path.Path
        """
        if state is None:
            state = self.entry_state(**kwargs)

        return Path(self._project, state)

    def path_group(self, thing=None, **kwargs):
        """
        Constructs a new path group.

        :param thing:           Optional - What to put in the new path group's active stash.
        :param kwargs:          Any additional keyword arguments will be passed to the PathGroup constructor
        :returns:               The new path group
        :rtype:                 angr.path_group.PathGroup

        Many different types can be passed to this method:

        * If nothing is passed in, the path group is seeded with a path containing a state initialized for the program
          entry point, i.e. :meth:`entry_state()`.
        * If a :class:`simuvex.s_state.SimState` is passed in, the path group is seeded with a path wrapping that state.
        * If a :class:`angr.path.Path` is passed in, the path group is seeded with that path.
        * If a list is passed in, the list must contain only SimStates and Paths, each SimState will be wrapped in a
          Path, and the whole list will be used to seed the path group.
        """
        if thing is None:
            thing = [self.path()]

        if isinstance(thing, (list, tuple)):
            thing = list(thing)
            for i, val in enumerate(thing):
                if isinstance(val, SimState):
                    thing[i] = self.path(val)
                elif not isinstance(val, Path):
                    raise AngrError("Bad type to initialize path group: %s" % repr(val))
        elif isinstance(thing, Path):
            thing = [thing]
        elif isinstance(thing, SimState):
            thing = [self.path(thing)]
        else:
            raise AngrError("BadType to initialze path group: %s" % repr(thing))

        return PathGroup(self._project, active_paths=thing, **kwargs)

    def callable(self, addr, concrete_only=False, perform_merge=True, base_state=None, toc=None, cc=None):
        """
        A Callable is a representation of a function in the binary that can be interacted with like a native python
        function.

        :param addr:            The address of the function to use
        :param concrete_only:   Throw an exception if the execution splits into multiple paths
        :param perform_merge:   Merge all result states into one at the end (only relevant if concrete_only=False)
        :param base_state:      The state from which to do these runs
        :param toc:             The address of the table of contents for ppc64
        :param cc:              The SimCC to use for a calling convention
        :returns:               A Callable object that can be used as a interface for executing guest code like a
                                python function.
        :rtype:                 angr.surveyors.caller.Callable
        """
        return Callable(self._project,
                        addr=addr,
                        concrete_only=concrete_only,
                        perform_merge=perform_merge,
                        base_state=base_state,
                        toc=toc,
                        cc=cc)


    def cc(self, args=None, ret_val=None, sp_delta=None, func_ty=None):
        """
        Return a SimCC (calling convention) parametrized for this project and, optionally, a given function.

        :param args:        A list of argument storage locations, as SimFunctionArguments.
        :param ret_val:     The return value storage location, as a SimFunctionArgument.
        :param sp_delta:    Does this even matter??
        :param func_ty:     The protoype for the given function, as a SimType.

        Relevant subclasses of SimFunctionArgument are SimRegArg and SimStackArg, and shortcuts to them can be found on
        this `cc` object.

        For stack arguments, offsets are relative to the stack pointer on function entry.
        """
        return self._default_cc(arch=self._project.arch,
                                  args=args,
                                  ret_val=ret_val,
                                  sp_delta=sp_delta,
                                  func_ty=func_ty)

    def block(self, addr, size=None, max_size=None, byte_string=None, vex=None, thumb=False, backup_state=None,
              opt_level=None, num_inst=None,
              insn_bytes=None  # backward compatibility
              ):

        if insn_bytes is not None:
            byte_string = insn_bytes

        if max_size is not None:
            l.warning('Keyword argument "max_size" has been deprecated for block(). Please use "size" instead.')
            size = max_size
        return Block(addr, project=self._project, size=size, byte_string=byte_string, vex=vex, thumb=thumb,
                     backup_state=backup_state, opt_level=opt_level, num_inst=num_inst
                     )

    def fresh_block(self, addr, size):
        return Block(addr, project=self._project, size=size)

    cc.SimRegArg = s_cc.SimRegArg
    cc.SimStackArg = s_cc.SimStackArg
    _default_cc = None
    callable.PointerWrapper = s_cc.PointerWrapper
    call_state.PointerWrapper = s_cc.PointerWrapper


    #
    # Private methods
    #

    def _fix_syscall_ip(self, state):
        """
        Resolve syscall information from the state, get the IP address of the syscall SimProcedure, and set the IP of
        the state accordingly. Don't do anything if the resolution fails.

        :param simuvex.s_state.SimState state: the program state.
        :return: None
        """

        try:
            _, syscall_addr, _, _ = self._project._simos.syscall_info(state)

            # Fix the IP
            state.ip = syscall_addr

        except AngrUnsupportedSyscallError:
            # the syscall is not supported. don't do anything
            pass

    @deprecate('sim_run()', 'successors()')
    def sim_run(self, *args, **kwargs):
        return self.successors(*args, **kwargs)

    @deprecate('sim_block()', 'successors(default_engine=True)')
    def sim_block(self, *args, **kwargs):
        kwargs['default_engine'] = True
        return self.successors(*args, **kwargs)

from .errors import AngrExitError, AngrError, AngrUnsupportedSyscallError
from .path import Path
from .path_group import PathGroup
from .knowledge import HookNode
from .block import Block
