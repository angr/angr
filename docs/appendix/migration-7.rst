Migrating to angr 7
===================

The release of angr 7 introduces several departures from long-standing angr-isms.
While the community has created a compatibility layer to give external code written for angr 6 a good chance of working on angr 7, the best thing to do is to port it to the new version.
This document serves as a guide for this.

SimuVEX is gone
---------------

angr versions up through angr 6 split the program analysis into two modules: ``simuvex``, which was responsible for analyzing the effects of a single piece of code (whether a basic block or a SimProcedure) on a program state, and ``angr``, which aggregated analyses of these basic blocks into program-level analysis such as control-flow recovery, symbolic execution, and so forth.
In theory, this would encourage for the encapsulation of block-level analyses, and allow other program analysis frameworks to build upon ``simuvex`` for their needs.
In practice, no one (to our knowledge) used ``simuvex`` without ``angr``, and the separation introduced frustrating limitations (such as not being able to reference the history of a state from a SimInspect breakpoint) and duplication of code (such as the need to synchronize data from ``state.scratch`` into ``path.history``).

Realizing that SimuVEX wasn't a usable independent package, we brainstormed about merging it into angr and further noticed that this would allow us to address the frustrations resulting from their separation.

All of the SimuVEX concepts (SimStates, SimProcedures, calling conventions, types, etc) have been migrated into angr.
The migration guide for common classes is bellow:

.. list-table::
   :header-rows: 1

   * - Before
     - After
   * - simuvex.SimState
     - angr.SimState
   * - simuvex.SimProcedure
     - angr.SimProcedure
   * - simuvex.SimEngine
     - angr.SimEngine
   * - simuvex.SimCC
     - angr.SimCC


And for common modules:

.. list-table::
   :header-rows: 1

   * - Before
     - After
   * - simuvex.s_cc
     - angr.calling_conventions
   * - simuvex.s_state
     - angr.sim_state
   * - simuvex.s_procedure
     - angr.sim_procedure
   * - simuvex.plugins
     - angr.state_plugins
   * - simuvex.engines
     - angr.engines
   * - simuvex.concretization_strategies
     - angr.concretization_strategies


Additionally, ``simuvex.SimProcedures`` has been renamed to ``angr.SIM_PROCEDURES``, since it is a global variable and not a class.
There have been some other changes to its semantics, see the section on SimProcedures for details.

Removal of angr.Path
--------------------

In angr, a Path object maintained references to a SimState and its history.
The fact that the history was separated from the state caused a lot of headaches when trying to analyze states inside a breakpoint, and caused overhead in synchronizing data from the state to its history.

In the new model, a state's history is maintained in a SimState plugin: ``state.history``.
Since the path would now simply point to the state, we got rid of it.
The mapping of concepts is roughly as follows:

.. list-table::
   :header-rows: 1

   * - Before
     - After
   * - path
     - state
   * - path.state
     - state
   * - path.history
     - state.history
   * - path.callstack
     - state.callstack
   * - path.trace
     - state.history.descriptions
   * - path.addr_trace
     - state.history.bbl_addrs
   * - path.jumpkinds
     - state.history.jumpkinds
   * - path.guards
     - state.history.jump_guards
   * - path.targets
     - state.history.jump_targets
   * - path.actions
     - state.history.actions
   * - path.events
     - state.history.events
   * - path.recent_actions
     - state.history.recent_actions
   * - path.reachable
     - state.history.reachable()


An important behavior change about ``path.actions`` and ``path.recent_actions`` - actions are no longer tracked by default.
If you would like them to be tracked again, please add ``angr.options.refs`` to your state.

Path Group -> Simulation Manager
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Since there are no paths, there cannot be a path group.
Instead, we have a Simulation Manager now (we recommend using the abbreviation "simgr" in places you were previously using "pg"), which is exactly the same as a path group except it holds states instead of paths.
You can make one with ``project.factory.simulation_manager(...)``.

Errored Paths
^^^^^^^^^^^^^

Before, error resilience was handled at the path level, where stepping a path that caused an error would return a subclass of Path called ErroredPath, and these paths would be put in the ``errored`` stash of a path group.
Now, error resilience is handled at the simulation manager level, and any state that throws an error during stepping will be wrapped in an ErrorRecord object, which is *not* a subclass of SimState, and put into the ``errored`` list attribute of the simulation manager, which is *not* a stash.

An ErrorRecord object has attributes for ``.state`` (the initial state that caused the error), ``.error`` (the error that was thrown), and ``.traceback`` (the traceback from the error).
To debug these errors you can call ``.debug()``.

These changes are because we were uncomfortable making a subclass of SimState, and the ErrorRecord class then has sufficiently different semantics from a normal state that it cannot be placed in a stash.

Changes to SimProcedures
------------------------

The most noticeable difference from the old version to the new version is that the catalog of built-in simprocedures are no longer organized strictly according to which library they live in.
Now, they are organized according to which *standards* they conform to, which helps with re-using procedures between different libraries.
For instance, the old ``SimProcedures['libc.so.6']`` has been split up between ``SIM_PROCEDURES['libc']``, ``SIM_PROCEDURES['posix']``, and ``SIM_PROCEDURES['glibc']``, depending on what specifications each function conforms to.
This allows us to reuse the ``libc`` catalog in ``msvcrt.dll`` and the MUSL libc, for example.

In order to group SimProcedures together by libraries, we have introduced a new abstraction called the SimLibrary, the definitions for which are stored in ``angr.procedures.definitions``.
Each SimLibrary object stores information about a single shared library, and can contain SimProcedure implementations, calling convention information, and type information.
SimLibraries are scraped from the filesystem at import time, just like SimProcedures, and placed into ``angr.SIM_LIBRARIES``.

Syscalls are now categorized through a subclass of SimLibrary called SimSyscallLibrary.
The API for managing syscalls through SimOS has been changed - check the API docs for the SimUserspace class.

One important implication of this change is that if you previously used a trick where you changed one of the SimProcedures present in the ``SimProcedures`` dict in order to change which SimProcedures would be used to hook over library functions by default, this will no longer work.
Instead of ``SimProcedures[lib][func_name] = proc``, you now need to say ``SIM_LIBRARIES[lib].add(func_name, proc)``.
But really you should just be using ``hook_symbol`` anyway.

Changes to hooking
------------------

The ``Hook`` class is gone.
Instead, we now can hook with individual instances of SimProcedure objects, as opposed to just the classes.
A shallow copy of the SimProcedure will be made at runtime to preserve thread safety.

So, previously, where you would have done ``project.hook(addr, Hook(proc, ...))`` or ``project.hook(addr, proc)``, you can now do ``project.hook(addr, proc(...))``.
In order to use simple functions as hooks, you can either say ``project.hook(addr, func)`` or decorate the declaration of your function with ``@project.hook(addr)``.

Having simprocedures as instances and letting them have access to the project cleans up a lot of other hacks that were present in the codebase, mostly related to the ``self.call(...)`` SimProcedure continuation system.
It is no longer required to set ``IS_FUNCTION = True`` if you intend to use ``self.call()`` while writing a SimProcedure, and each call-return target you use will have a unique address associated with it.
These addresses will be allocated lazily, which does have the side effect of making address allocation nondeterministic, sometimes based on dictionary-iteration order.

Changes to loading
------------------

The ``hook_symbol`` method will no longer attempt to redo relocations for the given symbol, instead just hooking directly over the address of the symbol in whatever library it comes from.
This speeds up loading substantially and ensures more consistent behavior for when mixing and matching native library code and SimProcedure summaries.

The angr externs object has been moved into CLE, which will ALWAYS make sure that every dependency is resolved to something, never left unrelocated.
Similarly, CLE provides the "kernel object" used to provide addresses for syscalls now.

.. list-table::
   :header-rows: 1

   * - Before
     - After
   * - ``project._extern_obj``
     - ``loader.extern_object``
   * - ``project._syscall_obj``
     - ``loader.kernel_object``


Several properties and methods have been renamed in CLE in order to maintain a more consistent and explicit API.
The most common changes are listed below:

.. list-table::
   :header-rows: 1

   * - Before
     - After
   * - ``loader.whats_at()``
     - ``loader.describe_addr``
   * - ``loader.addr_belongs_to_object()``
     - ``loader.find_object_containing()``
   * - ``loader.find_symbol_name()``
     - ``loader.find_symbol().name``
   * - whatever the hell you were doing before to look up a symbol
     - ``loader.find_symbol(name or addr)``
   * - ``loader.find_module_name()``
     - ``loader.find_object_containing().provides``
   * - ``loader.find_symbol_got_entry()``
     - ``loader.find_relevant_relocations()``
   * - ``loader.main_bin``
     - ``loader.main_object``
   * - ``anything.get_min_addr()``
     - ``anything.min_addr``
   * - ``symbol.addr``
     - ``symbol.linked_addr``


Changes to the solver interface
-------------------------------

We cleaned up the menagerie of functions present on ``state.solver`` (if you're still referring to it as ``state.se`` you should stop) and simplified it into a cleaner interface:


* ``solver.eval(expression)`` will give you one possible solution to the given expression.
* ``solver.eval_one(expression)`` will give you the solution to the given expression, or throw an error if more than one solution is possible.
* ``solver.eval_upto(expression, n)`` will give you up to n solutions to the given expression, returning fewer than n if fewer than n are possible.
* ``solver.eval_atleast(expression, n)`` will give you n solutions to the given expression, throwing an error if fewer than n are possible.
* ``solver.eval_exact(expression, n)`` will give you n solutions to the given expression, throwing an error if fewer or more than are possible.
* ``solver.min(expression)`` will give you the minimum possible solution to the given expression.
* ``solver.max(expression)`` will give you the maximum possible solution to the given expression.

Additionally, all of these methods can take the following keyword arguments:


* ``extra_constraints`` can be passed as a tuple of constraints.
  These constraints will be taken into account for this evaluation, but will not be added to the state.
* ``cast_to`` can be passed a data type to cast the result to.
  Currently, this can only be ``str``, which will cause the method to return the byte representation of the underlying data.
  For example, ``state.solver.eval(state.solver.BVV(0x41424344, 32, cast_to=str)`` will return ``"ABCD"``.
