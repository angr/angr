Changelog
=========

This lists the *major* changes in angr.
Tracking minor changes are left as an exercise for the reader :-)

angr 9.1
--------


* (#2961) Refactored SimCC to support passing and returning structs and arrays by value
* (#2964) Functions from the knowledge base may now be pretty-printed, showing colors and reference arrows
* Improved ``import angr`` speed substantially
* (#2948) RDA's ``dep_graph`` can now be used to track dependencies between temporaries, constants, guard conditions, and function calls - if you want it!
* (#2929) Basic support for structs with bitfields in SimType
* There's a decompiler now

angr 9.0
--------


* Switched to a new versioning scheme: major.minor.build_id

angr 8.19.7.25
--------------


* (#1503) Implement necessary helpers and information storage for call pretty printing
* (#1546) Add a new state option MEMORY_FIND_STRICT_SIZE_LIMIT
* (#1548) SimProcedure.static_exits: Allow providing name hints
* (cle#177) Use Enums for Symbol Types
* (cle#193) Add support for "named regions"
* (claripy#151) Implement operator precedence in claripy op rendering
* Added support for interaction recording in angr-management
* Several new simprocedure implementations
* Substantial imporvments to our CFG

angr 8.19.4.5
-------------


* (#1234) Massive improvements to CFG recovery for ARM and ARM cortex-m binaries.
* (#1416) Added support for analyzing Java programs via the Soot IR, including the ability to analyze interplay between Java code and JNI libraries. This branch was two years old!
* (#1427) Added a MemoryWatcher exploration technique to take action when the system is running out of RAM. Thanks @bannsec.
* (#1432) Added a ``state.heap`` plugin which manages the heap (with pluggable heap schemes!) and provides malloc functionality. Thanks @tgduckworth.
* Speed improvements for using the VEX engine and working with concrete data.
* Added SimLightRegisters, an alternate registers plugin that eliminates the abstraction of the register file for performance improvements at the cost of removing all instrumentability.
* ``version__`` variable has been added to all modules.
* The ``stack_base`` kwarg for ``call_state`` is not broken for the first time ever
* https://github.com/python/cpython/pull/11384

angr 8.19.2.4
-------------


* (#1279) Support C++ function name demangling via itanium-demangler. Thanks @fmagin.
* (#1283) ``security_cookie`` is initialized for SimWindows. Thanks @zeroSteiner.
* (#1298) Introduce ``SimData``. It's a cleaner interface to deal with data imports in CLE -- especially for those data entries that are not imported because of missing or unloaded libraries. This commit fixes long-standing issues #151 and #693.
* (#1299, #1300, #1301, #1313, #1314, #1315, #1336, #1337, #1343, ...) Multiple CFGFast-related improvements and bug fixes.
* (#1332) ``UnresolvableTarget`` is now split into two classes: ``UnresolvableJumpTarget`` and ``UnresolvableCallTarget``. Thanks @Kyle-Kyle.
* (#1382) Add a preliminary implementation of angr decompiler. Give it a try! ``p = angr.Project("cfg_loop_unrolling", auto_load_libs=False); p.analyses.CFG(); print(p.analyses.Decompiler(p.kb.functions['test_func']).codegen.text)``.
* (#1421) ``SimAction``\ s now have incrementing IDs. Thanks @bannsec.
* (#1408) ``ANA``, angr's old identity-aware serialization backend, has been removed. Instead of non-obvious serialization behavior, all angr objects should now be pickleable. If one is not, please file an issue. For use-cases that require identity-awareness (i.e., deduplicating ASTs across states serialized at different times), an ``angr.vaults`` module has been introduced.
* Added a `facility to synchronize state between angr and a running target a la avatar2 <http://angr.io/blog/angr_symbion/>`_
* Changed unconstrained registers/memory warning to be less obnoxious and contain useful information. Also added ``SYMBOL_FILL_UNCONSTRAINED_REGISTERS`` and ``SYMBOL_FILL_UNCONSTRAINED_MEMORY`` state options to silence them.

angr 8.18.10.25
---------------


* The IDA backend for CLE has been removed. It has been broken for quite some time, but now it has been disabled for your own safety.
* Surveyors have been removed! Finally! This is thanks to @danse-macabre who contributed an Exploration Technique for the Slicecutor. Backwards slicing has now been brought out of the angr dark ages.
* SimCC can now be initialized with a string containing C function prototype in its ``func_ty`` argument
* Similarly, Callable can now be run with its arguments instantiated from a string containing C expressions
* Tracer has been substantially refactored - it will now handle more kinds of desyncs, ASLR slides, and is much more friendly for hacking. We will be continuing to improve it!
* The Oppologist and Driller have been refactored to play nice with other exploration techniques
* SimProcedure continuations now have symbols in the externs object, so ``describe_addr`` will work on them. Additionally, the representation for SimProcedure (appearing in ``history.descriptions`` and ``project._sim_procedures`` among other places) has been improved to show this information.

angr 8.18.10.5
--------------

Largely a bugfix release, but with a few bonus treats:


* API documentation has been rewritten for Exploration Technique. It should be much easier to use now.
* Simulation Manager will throw an error if you pass incorrect keyword arguments (??? why was it like this)
* The ``save_unconstrained`` flag of Simulation Manager is now on by default
* If a step produces only unsatisfiable states, they will appear in the ``'unsat'`` stash regardless of the ``save_unsat`` setting, since this usually indicates a bug. Add ``unsat`` to the ``auto_drop`` parameter to restore the old behavior.

angr 8.18.10.1
--------------

Welcome to angr 8!
The biggest change for this major version bump is the transition to Python 3.
You can read about this, as well as a few other breaking changes, in the :ref:`Migrating to angr 8`.


* Switch to Python 3
* Refactor to Clemory to clean up the API and speed things up drastically
* Remove ``object.symbols_by_addr`` (dict) and add ``object.symbols`` (sorted list); add ``fuzzy`` parameter to ``loader.find_symbol``
* CFGFast is much, much faster now. CFGAccurate has been renamed to CFGEmulated.
* Support for avx2 unpack instructions, courtesy of D. J. Bernstein
* Removed support for immutable simulation managers
* angr will now show you a warning when using uninitialized memory or registers
* angr will now NOT show you a warning if you have a capstone 3.x install unless you're actually interacting with the relevant missing parts
* Many, many, many bug fixes

angr 7.8.7.1
------------


* Remove ``LoopLimiter`` and ``DFG``.
* (#1063) ``CFGAccurate`` can now leverage indirect jump resolvers to resolve indirect jumps.

angr 7.8.6.23
-------------


* (PyVEX!#134) We now recognize LDMDB r11, {xxx, pc} as a ret instruction for ARM.
* (#1053) CFGFast spends less time running next_pos_with_sort_not_in(), thus it runs faster on large binaries.
* (#1080) Jump table resolvers now support resolving ARM jump tables.
* (#1081, together with the PyVEX commit 61efbdcf6303a936aa3de35011d2d1e3fe5fdea5) The memory footprint of CFGFast is noticeably smaller, especially on large binaries (over 10 MB in size).
* (#1034) Concretizing a SimFile with unconstrained size can no longer run you out of memory.
* Other minor changes and bug fixes.

angr 7.8.6.16
-------------


* The modeling of file system is refactored.
* (#808) Add a new class Control flow blanket (CFBlanket) to support generating a linear view of a control flow graph.
* (#863) Add support to AIL, the new angr intermediate language (still pretty WIP though). Merged in several static analyses (reaching definition analysis, VEX-to-AIL translation, redundant assignment elimination, code region identification, control flow structuring, etc.) that support the development of decompilation in the near future.
* (#888) SimulationManager is extensively refactored and cleaned up.
* (#892) Keystone is integrated. You can assemble instructions inside angr now.
* (#897) A new class ``PluginHub`` is added. Plugins (analyses, engines) are refactored to be based on ``PluginHub``.
* (#899) Support of bidirectional mapping between syscall numbers and syscalls.
* (#925, #941, #942) A bunch of library function prototypes (including glibc) are added to angr.
* (#953) Fix the issue where evaluating the jump target of a jump table that contains many entries (e.g., > 512) is extremely slow.
* (#964) State options are now stored in insances of SimStateOptions. ``state.options`` is no longer a set of strings.
* (#973) Add two new exploration techniques: Stochastic and unique.
* (#996) SimType structs are now much easier to use.
* (#998) Add a new state option ``PRODUCE_ZERODIV_SUCCESSORS`` to generate divide-by-zero successors.
* Speed improvements and bug fixes in CFG generation (CFGFast and CFGAccurate).

angr 7.8.2.21
-------------


* Refactor of how syscall handling and SimSyscallLibrary work - it is now possible to handle syscalls using multiple ABIs in the same process
* Added syscall name-number mappings from all linux ABIs, parsed from gdb
* Add ``ManualMergepoint`` exploration technique for when veritesting is too mysterious for your tastes
* Add ``LoopSeer`` exploration technique for managing loops during symbolic exploration (credit @tyb0807)
* Add ``ProxyTechnique`` exploration technique for easily composing simple lambda-based instrumentations (credit @danse-macabre)

angr 7.7.12.16
--------------


* You can now tell where the variables implicitly created by angr come from! ``state.solver.BVS`` now can take a ``key`` parameter, which describes its meaning in relation to the emulated environment. You can then use ``state.solver.get_variables(...)`` and ``state.solver.describe_variables(...)`` to map tags and ASTs to and from each other. Check out the `API docs <http://angr.io/api-doc/angr.html#angr.state_plugins.solver.SimSolver>`_!
* The SimOS for a project is now a public property - ``project.simos`` instead of ``project._simos``. Additionally, the SimOS code structure has been shuffled around a bit - it's now a subpackage instead of a submodule.
* The core components of Tracer and Driller have been refactored into Exploration Techniques and integrated into angr proper, so you can now follow instruction traces without installing another repository! (credit @tyb0807)
* Archinfo now contains a ``byte_width`` parameter and angr supports emulation of platforms with non-octet bytes, lord help us
* Upgraded to networkx 2 (credit @tyb0807)
* Hopefully installation issues with capstone should be fixed FOREVER
* Minor fixes to gender

angr 7.7.9.8
------------

Welcome to angr 7!
We worked long and hard all summer to make this release the best ever.
It introduces several breaking changes, so for a quick guide on the most common ways you'll need to update your scripts, take a look at the :ref:`Migrating to angr 7`.


* SimuVEX has been removed and its components have been integrated into angr
* Path has been removed and its components have been integrated into SimState, notably the new ``history`` state plugin
* PathGroup has been renamed to SimulationManager
* SimState and SimProcedure now have a reference to their parent Project, though it is verboten to use it in anything other than an append-only fashion
* A new class SimLibrary is used to track SimProcedure and metadata corresponding to an individual shared library
* Several CLE interfaces have been refactored up for consistency
* Hook has been removed. Hooking is now done with individual SimProcedure instances, which are shallow-copied at execution time for thread-safety.
* The ``state.solver`` interface has been cleaned up drastically

These are the major refactor-y points.
As for the improvements:


* Greatly improved support for analyzing 32 bit windows binaries (partial credit @schieb)
* Unicorn will now stop for stop points and breakpoints in the middle of blocks (credit @bennofs)
* The processor flags for a state can now be accessed through ``state.regs.eflags`` on x86 and ``state.regs.flags`` on ARM (partial credit @tyb0807)
* Fledgling support for emulating exception handling. Currently the only implementation of this is support for Structured Exception Handling on Windows, see ``angr.SimOS.handle_exception`` for details
* Fledgling support for runtime library loading by treating the CLE loader as an append-only interface, though only implemented for windows. See ``cle.Loader.dynamic_load`` and ``angr.procedures.win32.dynamic_loading`` for details.
* The knowledge base has been refactored into a series of plugins similar to SimState (credit @danse-macabre)
* The testcase-based function identifier we wrote for CGC has been integrated into angr as the Identifier analysis
* Improved support for writing custom VEX lifters

angr 6.7.6.9
------------


* angr: A static data-flow analysis framework has been introduced, and implemented as part of the ``ForwardAnalysis`` class. Additionally, a few exemplary data-flow analyses, like ``VariableRecovery`` and ``VariableRecoveryFast``, have been implemented in angr.
* angr: We introduced the notion of *variable* to the angr world. Now a VariableManager is available in the knowledge base. Variable information can be recovered by running a variable recovery analysis. Currently the variable information recovered for each function is still pretty coarse. More updates to it will arrive soon.
* angr: Fix a bug in the topological sorting in ``CFGUtils``, which resulted in suboptimal graph node ordering after sorting.
* SimuVEX: ``LAZY_SOLVES`` is no longer enabled by default during symbolic execution. It's still there if it's wanted, but it just caused confusion when on by default.
* SimuVEX: Thanks to @ekilmer, a few new libc SimProcedures are added.
* SimuVEX: The default memory model has been refactored for expandability. Custom pages can now be created (derive the simuvex.storage.ListPage class) and used instead of the default page classes to implement custom memory behavior for specific pages. The user-friendly API for this is pending the next release.
* angr-management: Implemented our own graph layout and edge routing algorithm. We do not rely on grandalf anymore.
* angr-management: Added support for displaying variable information for operands.
* angr-management: Added support for highlighting dependent operands when an operand is highlighted.

angr 6.7.3.26
-------------

Building off of the engine changes from the last release, we have begun to extend angr to other architectures. AVR and MSP430 are in progress. In the meantime, subwire has created a reference implementation of BrainFuck support in angr, done two different ways! Check out `angr-platforms <https://github.com/angr/angr-platforms>`_ for more info!


* We have rebased our fork of VEX on the latest master branch from Valgrind (as of 2 months ago, at least...). We have also submitted our patches to VEX to upstream, so we should be able to stop maintaining a fork pretty soon.
* The way we interact with VEX has changed substantially, and should speed things up a bit.
* Loading sets of binaries with many import symbols has been sped up
* Many, many improvements to angr-management, including the switch away from enaml to using pyside directly.

angr 6.7.1.13
-------------

For the last month, we have been working on a major refactor of the angr to change the way that angr reasons about the code that it analyzes.
Until now, angr has been bound to the VEX intermediate representation to lift native code, supporting a wide range of architectures but not being very expandable past them.
This release represents the ground work for what we call translation and execution engines.
These engines are independent backends, pluggable into the angr framework, that will allow angr to reason about a wide range of targets.
For now, we have restructured the existing VEX and Unicorn Engine support into this engine paradigm, but as we discuss in `our blog post <http://angr.io/blog/2017_01_10.html>`_, the plan is to create engines to enable angr's reasoning of Java bytecode and source code, and to augment angr's environment support through the use of external dynamic sandboxes.

For now, these changes are mostly internal.
We have attempted to maintain compatibility for end-users, but those building systems atop angr will have to adapt to the modern codebase.
The following are the major changes:


* simuvex: we have introduced SimEngine. SimEngine is a base class for abstractions over native code. For example, angr's VEX-specific functionality is now concentrated in SimEngineVEX, and new engines (such as SimEngineLLVM) can be implemented (even outside of simuvex itself) to support the analysis of new types of code.
* simuvex: as part of the engines refactor, the SimRun class has been eliminated. Instead of different subclasses of SimRun that would be instantiated from an input state, engines each have a ``process`` function that, from an input state, produces a SimSuccessors instance containing lists of different successor states (normal, unsat, unconstrained, etc) and any engine-specific artifacts (such as the VEX statements. Take a look at ``successors.artifacts``).
* simuvex: ``state.mem[x:] = y`` now *requires* a type for storage (for example ``state.mem[x:].dword = y``).
* simuvex: the way of calling inline SimProcedures has been changed. Now you have to create a SimProcedure, and then call ``execute()`` on it and pass in a program state as well as the arguments.
* simuvex: accessing registers through ``SimRegNameView`` (like ``state.regs.eax``) always triggers SimInspect breakpoints and creates new actions. Now you can access a register by prefixing its name with an underscore (e.g. ``state.regs._eax`` or ``state._ip``) to avoid triggering breakpoints or creating actions.
* angr: the way hooks work has slightly changed, though is backwards-compatible. The new angr.Hook class acts as a wrapper for hooks (SimProcedures and functions), keeping things cleaner in the ``project._sim_procedures`` dict.
* angr: we have deprecated the keyword argument ``max_size`` and changed it to to ``size`` in the ``angr.Block`` constructor (i.e., the argument to ``project.factory.block`` and more upstream methods (``path.step``, ``path_group.step``, etc).
* angr: we have deprecated ``project.factory.sim_run`` and changed it to to ``project.factory.successors``, and it now generates a ``SimSuccessors`` object.
* angr: ``project.factory.sim_block`` has been deprecated and replaced with ``project.factory.successors(default_engine=True)``.
* angr: angr syscalls are no longer hooks. Instead, the syscall table is now in ``project._simos.syscall_table``. This will be made "public" after a usability refactor. If you were using ``project.is_hooked(addr)`` to see if an address has a related SimProcedure, now you probably want to check if there is a related syscall as well (using ``project._simos.syscall_table.get_by_addr(addr) is not None``).
* pyvex: to support custom lifters to VEX, pyvex has introduced the concept of backend lifters. Lifters can be written in pure Python to produce VEX IR, allowing for extendability of angr's VEX-based analyses to other hardware architectures.

As usual, there are many other improvements and minor bugfixes.


* claripy: support ``unsat_core()`` to get the core of unsatness of constraints. It is in fact a thin wrapper of the ``unsat_core()`` function provided by Z3. Also a new state option ``CONSTRAINT_TRACKING_IN_SOLVER`` is added to SimuVEX. That state option must be enabled if you want to use ``unsat_core()`` on any state.
* simuvex: ``SimMemory.load()`` and ``SimMemory.store()`` now takes a new parameter ``disable_actions``. Setting it to True will prevent any SimAction creation.
* angr: CFGFast has a better support for ARM binaries, especially for code in THUMB mode.
* angr: thanks to an improvement in SimuVEX, CFGAccurate now uses slightly less memory than before.
* angr: ``len()`` on path ``trace`` or ``addr_trace`` is made much faster.
* angr: Fix a crash during CFG generation or symbolic execution on platforms/architectures with no syscall defined.
* angr: as part of the refactor, ``BackwardSlicing`` is temporarily disabled. It will be re-enabled once all DDG-related refactor are merged to master.

Additionally, packaging and build-system improvements coordinated between the angr and Unicorn Engine projects have allowed angr's Unicorn support to be built on Windows. Because of this, ``unicorn`` is now a dependency for ``simuvex``.

Looking forward, angr is poised to become a program analysis engine for binaries *and more*!

angr 5.6.12.3
-------------

It has been over a month since the last release 5.6.10.12.
Again, we’ve made some significant changes and improvements on the code base.


* angr: Labels are now stored in KnowledgeBase.
* angr: Add a new analysis: ``Disassembly``.
  The new Disassembly analysis provides an easy-to-use interface to render assembly of functions.
* angr: Fix the issue that ``ForwardAnalysis`` may prematurely terminate while there are still un-processed jobs.
* angr: Many small improvements and bug fixes on ``CFGFast``.
* angr: Many small improvements and bug fixes on ``VFG``.
  Bring back widening support.
  Fix the issue that ``VFG`` may not terminate under certain cases.
  Implement a new graph traversal algorithm to have an optimal traversal order.
  Allow state merging at non-merge-points, which allows faster convergence.
* angr-management: Display a progress during initial CFG recovery.
* angr-management: Display a “Load binary” window upon binary loading.
  Some analysis options can be adjusted there.
* angr-management: Disassembly view: Edge routing on the graph is improved.
* angr-management: Disassembly view: Support starting a new symbolic execution task from an arbitrary address in the program.
* angr-management: Disassembly view: Support renaming of function names and labels.
* angr-management: Disassembly view: Support “Jump to address”.
* angr-management: Disassembly view: Display resolved and unresolved jump targets.
  All jump targets are double-clickable.
* SimuVEX: Move region mapping from ``SimAbstractMemory`` to ``SimMemory``.
  This will allow an easier conversion between ``SimAbstractMemory`` and ``SimSymbolicMemory``, which is to say, conversion between symbolic states and static states is now possible.
* SimuVEX & claripy: Provide support for ``unsat_core`` in Z3.
  It returns a set of constraints that led to unsatness of the constraint set on the current state.
* archinfo: Add a new Boolean variable ``branch_delay_slot`` for each architecture.
  It is set to True on MIPS32.

angr 5.6.8.22
-------------

Major point release! An incredible number of things have changed in the month run-up to the Cyber Grand Challenge.


* Integration with `Unicorn Engine <https://github.com/unicorn-engine/unicorn>`_ supported for concrete execution.
  A new SimRun type, SimUnicorn, may step through many basic blocks at once, so long as there is no operation on symbolic data.
  Please use `our fork of unicorn engine <https://github.com/angr/unicorn>`_, which has many patches applied.
  All these patches are pending merge into upstream.
* Lots of improvements and bug fixes to CFGFast.
  Rumors are angr’s CFG was only "optimized" for x86-64 binaries (which is really because most of our test cases are compiled as 64-bit ELFs).
  Now it is also “optimized” for x86 binaries :)
  (editor's note: angr is built with cross-architecture analysis in mind. CFG construction is pretty much the only component which has architecture-specific behavior.)
* Lots of improvements to the VFG analysis, including speed and accuracy. However, there is still a lot to be done.
* Lots of speed optimizations in general - CFGFast should be 3-6x faster under CPython with much less memory usage.
* Now data dependence graph gives you a real dependence graph between variable definitions. Try ``data_graph`` and ``simplified_data_graph`` on a DDG object!
* New state option ``simuvex.o.STRICT_PAGE_ACCESS`` will cause a ``SimSegfaultError`` to be raised whenever the guest reads/writes/executes memory that is either unmapped or doesn't have the appropriate permissions.
* Merging of paths (as opposed to states) is performed in a much smarter way.
* The behavior of the ``support_selfmodifying_code`` project option is changed:
  Before, this would allow the state to be used as a fallback source of instruction bytes when no backer from CLE is available.
  Now, this option makes instruction lifting use the state as the source of bytes always.
  When the option is disabled and execution jumps outside the normal binary, the state will be used automatically.
* *Actually* support self-modifying code - if a basic block of code modifies itself, the block will be re-lifted before the next instruction starts.
* Syscalls are handled differently now - Before you would see a SimRun for a syscall helper, now you'll just see a SimProcedure for the given syscall.
  Additionally, each syscall has its own address in a "syscalls segment", and syscalls are treated as jumps to this segment.
  This simplifies a lot of things analysis-wise.
* CFGAccurate accepts a ``base_graph`` keyword to its constructor, e.g. ``CFGFast().graph``, or even ``.graph`` of a function, to use as a base for analysis.
* New fast memory model for cases where symbolic-addressed reads and writes are unlikely.
* Conflicts between the ``find`` and ``avoid`` parameters to the Explorer otiegnqwvk are resolved correctly. (credit clslgrnc)
* New analysis ``StaticHooker`` which hooks library functions in unstripped statically linked binaries.
* ``Lifter`` can be used without creating an angr Project.
  You must manually specify the architecture and bytestring in calls to ``.lift()`` and ``.fresh_block()``.
  If you like, you can also specify the architecture as a parameter to the constructor and omit it from the lifting calls.
* Add two new analyses developed for the CGC (mostly as examples of doing static analysis with angr): Reassembler and BinaryOptimizer.

angr 4.6.6.28
-------------

In general, there have been enormous amounts of speed improvements in this release.
Depending on the workload, angr should run about twice as fast.
Aside from this, there have also been many submodule-specific changes:

angr
^^^^

Quite a few changes and improvements are made to ``CFGFast`` and ``CFGAccurate`` in order to have better and faster CFG recovery.
The two biggest changes in ``CFGFast`` are jump table resolution and data references collection, respectively.
Now ``CFGFast`` resolves indirect jumps by default.
You may get a list of indirect jumps recovered in ``CFGFast`` by accessing the ``indirect_jumps`` attribute.
For many cases, it resolves the jump table accurately.
Data references collection is still in alpha mode.
To test data references collection, just pass ``collect_data_references=True`` when creating a fast CFG, and access the ``memory_data`` attribute after the CFG is constructed.

CFG recovery on ARM binaries is also improved.

A new paradigm called an "otiegnqwvk", or an "exploration technique", allows the packaging of special logic related to path group stepping.

SimuVEX
^^^^^^^

Reads/writes to the x87 fpu registers now work correctly - there is special logic that rotates a pointer into part of the register file to simulate the x87 stack.

With the recent changes to Claripy, we have configured SimuVEX to use the composite solver by default.
This should be transparent, but should be considered if strange issues (or differences in behavior) arise during symbolic execution.

Claripy
^^^^^^^

Fixed a bug in claripy where ``div__`` was not always doing unsigned division, and added new methods ``SDiv`` and ``SMod`` for signed division and signed remainder, respectively.

Claripy frontends have been completely rewritten into a mixin-centric solver design. Basic frontend functionality (i.e., calling into the solver or dealing with backends) is handled by frontends (in ``claripy.frontends``), and additional functionality (such as caching, deciding when to simplify, etc) is handled by frontend mixins (in ``claripy.frontend_mixins``). This makes it considerably easier to customize solvers to your specific needE. For examples, look at ``claripy/solver.py``.

Alongside the solver rewrite, the composite solver (which splits constraints into independent constraint sets for faster solving) has been immensely improved and is now functional and fast.

angr 4.6.6.4
------------

Syscalls are no longer handled by ``simuvex.procedures.syscalls.handler``.
Instead, syscalls are now handled by ``angr.SimOS.handle_syscall()``.
Previously, the address of a syscall SimProcedure is the address right after the syscall instruction (e.g. ``int 80h``), which collides with the real basic block starting at that address, and is very confusing.
Now each syscall SimProcedure has its own address, just as a normal SimProcedure.
To support this, there is another region mapped for the syscall addresses, ``Project._syscall_obj``.

Some refactoring and bug fixes in ``CFGFast``.

Claripy has been given the ability to handle *annotations* on ASTs.
An annotation can be used to customize the behavior of some backends without impacting others.
For more information, check the docstrings of ``claripy.Annotation`` and ``claripy.Backend.apply_annotation``.

angr 4.6.5.25
-------------

New state constructor - ``call_state``. Comes with a refactor to ``SimCC``, a refactor to ``callable``, and the removal of ``PathGroup.call``.
All these changes are thoroughly documented, in ``angr/docs/advanced-topics/structured_data.md``

Refactor of ``SimType`` to make it easier to use types - they can be instantiated without a SimState and one can be added later.
Comes with some usability improvements to SimMemView.
Also, there's a better wrapper around PyCParser for generating SimType instances from c declarations and definitions.
Again, thoroughly documented, still in the structured data doc.

``CFG`` is now an alias to ``CFGFast`` instead of ``CFGAccurate``.
In general, ``CFGFast`` should work under most cases, and it's way faster than ``CFGAccurate``.
We believe such a change is necessary, and will make angr more approachable to new users.
You will have to change your code from ``CFG`` to ``CFGAccurate`` if you are relying on specific functionalities that only exist in ``CFGAccurate``, for example, context-sensitivity and state-preserving.
An exception will be raised by angr if any parameter passed to ``CFG`` is only supported by ``CFGAccurate``.
For more detailed explanation, please take a look at the documentation of ``angr.analyses.CFG``.

angr 4.6.3.28
-------------

PyVEX has a structural overhaul. The ``IRExpr``, ``IRStmt``, and ``IRConst`` modules no longer exist as submodules, and those module names are deprecated.
Use ``pyvex.expr``, ``pyvex.stmt``, and ``pyvex.const`` if you need to access the members of those modules.

The names of the first three parameters to ``pyvex.IRSB`` (the required ones) have been changed.
If you were passing the positional args to IRSB as keyword args, consider switching to positional args.
The order is ``data``, ``mem_addr``, ``arch``.

The optional parameter ``sargc`` to the ``entry_state`` and ``full_init_state`` constructors has been removed and replaced with an ``argc`` parameter.
``sargc`` predates being able to have claripy ASTs independent from a solver.
The new system is to pass in the exact value, ast or integer, that you'd like to have as the guest program's arg count.

CLE and angr can now accept file-like streams, that is, objects that support ``stream.read()`` and ``stream.seek()`` can be passed in wherever a filepath is expected.

Documentation is much more complete, especially for PyVEX and angr's symbolic execution control components.

angr 4.6.3.15
-------------

There have been several improvements to claripy that should be transparent to users:


* There's been a refactoring of the VSA StridedInterval classes to fix cases where operations were not sound. Precision might suffer as a result, however.
* Some general speed improvements.
* We've introduced a new backend into claripy: the ReplacementBackend. This frontend generates replacement sets from constraints added to it, and uses these replacement sets to increase the precision of VSA. Additionally, we have introduced the HybridBackend, which combines this functionality with a constraint solver, allowing for memory index resolution using VSA.

angr itself has undergone some improvements, with API changes as a result:


* We are moving toward a new way to store information that angr has recovered about a program: the knowledge base. When an analysis recovers some truth about a program (i.e., "there's a basic block at 0x400400", or "the block at 0x400400 has a jump to 0x400500"), it gets stored in a knowledge-base. Analysis that used to store data (currently, the CFG) now store them in a knowledge base and can *share* the global knowledge base of the project, now accessible via ``project.kb``. Over time, this knowledge base will be expanded in the course of any analysis or symbolic execution, so angr is constantly learning more information about the program it is analyzing.
* A forward data-flow analysis framework (called ForwardAnalysis) has been introduced, and the CFG was rewritten on top of it. The framework is still in alpha stage - expect more changes to be made. Documentation and more details will arrive shortly. The goal is to refactor other data-flow analysis, like CFGFast, VFG, DDG, etc. to use ForwardAnalysis.
* We refactored the CFG to a) improve code readability, and b) eliminate some bad designs that linger due to historical reasons.

angr 4.5.12.?
-------------

Claripy has a new manager for backends, allowing external backends (i.e., those implemented by other modules) to be used.
The result is that ``claripy.backend_concrete`` is now ``claripy.backends.concrete``, ``claripy.backend_vsa`` is now ``claripy.backends.vsa``, and so on.

angr 4.5.12.12
--------------

Improved the ability to recover from failures in instruction decoding.
You can now hook specific addresses at which VEX fails to decode with ``project.hook``, even if those addresses are not the beginning of a basic block.

angr 4.5.11.23
--------------

This is a pretty beefy release, with over half of claripy having been rewritten and major changes to other analyses.
Internally, Claripy has been unified -- the VSA mode and symbolic mode now work on the same structures instead of requiring structures to be created differently.
This opens the door for awesome capabilities in the future, but could also result in unexpected behavior if we failed to account for something.

Claripy has had some major interface changes:


* claripy.BV has been renamed to claripy.BVS (bit-vector symbol). It can now create bitvectors out of strings (i.e., claripy.BVS(0x41, 8) and claripy.BVS("A") are identical).
* state.BV and state.BVV are deprecated. Please use state.se.BVS and state.se.BVV.
* BV.model is deprecated. If you're using it, you're doing something wrong, anyways. If you really need a specific model, convert it with the appropriate backend (i.e., claripy.backend_concrete.convert(bv)).

There have also been some changes to analyses:


* Interface: CFG argument ``keep_input_state`` has been renamed to ``keep_state``. With this option enabled, both input and final states are kept.
* Interface: Two arguments ``cfg_node`` and ``stmt_id`` of ``BackwardSlicing`` have been deprecated. Instead, ``BackwardSlicing`` takes a single argument, ``targets``. This means that we now support slicing from multiple sources.
* Performance: The speed of CFG recovery has been slightly improved. There is a noticeable speed improvement on MIPS binaries.
* Several bugs have been fixed in DDG, and some sanity checks were added to make it more usable.

And some general changes to angr itself:


* StringSpec is deprecated! You can now pass claripy bitvectors directly as arguments.
