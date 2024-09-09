Simulation Managers
===================

The most important control interface in angr is the SimulationManager, which
allows you to control symbolic execution over groups of states simultaneously,
applying search strategies to explore a program's state space. Here, you'll
learn how to use it.

Simulation managers let you wrangle multiple states in a slick way. States are
organized into "stashes", which you can step forward, filter, merge, and move
around as you wish. This allows you to, for example, step two different stashes
of states at different rates, then merge them together. The default stash for
most operations is the ``active`` stash, which is where your states get put when
you initialize a new simulation manager.

Stepping
^^^^^^^^

The most basic capability of a simulation manager is to step forward all states
in a given stash by one basic block. You do this with ``.step()``.

.. code-block:: python

   >>> import angr
   >>> proj = angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
   >>> state = proj.factory.entry_state()
   >>> simgr = proj.factory.simgr(state)
   >>> simgr.active
   [<SimState @ 0x400580>]

   >>> simgr.step()
   >>> simgr.active
   [<SimState @ 0x400540>]

Of course, the real power of the stash model is that when a state encounters a
symbolic branch condition, both of the successor states appear in the stash, and
you can step both of them in sync. When you don't really care about controlling
analysis very carefully and you just want to step until there's nothing left to
step, you can just use the ``.run()`` method.

.. code-block:: python

   # Step until the first symbolic branch
   >>> while len(simgr.active) == 1:
   ...    simgr.step()

   >>> simgr
   <SimulationManager with 2 active>
   >>> simgr.active
   [<SimState @ 0x400692>, <SimState @ 0x400699>]

   # Step until everything terminates
   >>> simgr.run()
   >>> simgr
   <SimulationManager with 3 deadended>

We now have 3 deadended states! When a state fails to produce any successors
during execution, for example, because it reached an ``exit`` syscall, it is
removed from the active stash and placed in the ``deadended`` stash.

Stash Management
^^^^^^^^^^^^^^^^

Let's see how to work with other stashes.

To move states between stashes, use ``.move()``,  which takes ``from_stash``,
``to_stash``, and ``filter_func`` (optional, default is to move everything). For
example, let's move everything that has a certain string in its output:

.. code-block:: python

   >>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome' in s.posix.dumps(1))
   >>> simgr
   <SimulationManager with 2 authenticated, 1 deadended>

We were able to just create a new stash named "authenticated" just by asking for
states to be moved to it. All the states in this stash have "Welcome" in their
stdout, which is a fine metric for now.

Each stash is just a list, and you can index into or iterate over the list to
access each of the individual states, but there are some alternate methods to
access the states too. If you prepend the name of a stash with ``one_``, you
will be given the first state in the stash. If you prepend the name of a stash
with ``mp_``, you will be given a `mulpyplexed
<https://github.com/zardus/mulpyplexer>`_ version of the stash.

.. code-block:: python

   >>> for s in simgr.deadended + simgr.authenticated:
   ...     print(hex(s.addr))
   0x1000030
   0x1000078
   0x1000078

   >>> simgr.one_deadended
   <SimState @ 0x1000030>
   >>> simgr.mp_authenticated
   MP([<SimState @ 0x1000078>, <SimState @ 0x1000078>])
   >>> simgr.mp_authenticated.posix.dumps(0)
   MP(['\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
       '\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x80\x80\x80\x80@\x80@\x00'])

Of course, ``step``, ``run``, and any other method that operates on a single
stash of paths can take a ``stash`` argument, specifying which stash to operate
on.

There are lots of fun tools that the simulation manager provides you for
managing your stashes. We won't go into the rest of them for now, but you should
check out the API documentation. TODO: link

Stash types
-----------

You can use stashes for whatever you like, but there are a few stashes that will
be used to categorize some special kinds of states. These are:

.. list-table::
   :header-rows: 1

   * - Stash
     - Description
   * - active
     - This stash contains the states that will be stepped by default, unless an
       alternate stash is specified.
   * - deadended
     - A state goes to the deadended stash when it cannot continue the execution
       for some reason, including no more valid instructions, unsat state of all
       of its successors, or an invalid instruction pointer.
   * - pruned
     - When using ``LAZY_SOLVES``, states are not checked for satisfiability
       unless absolutely necessary. When a state is found to be unsat in the
       presence of ``LAZY_SOLVES``, the state hierarchy is traversed to identify
       when, in its history, it initially became unsat. All states that are
       descendants of that point (which will also be unsat, since a state cannot
       become un-unsat) are pruned and put in this stash.
   * - unconstrained
     - If the ``save_unconstrained`` option is provided to the SimulationManager
       constructor, states that are determined to be unconstrained (i.e., with
       the instruction pointer controlled by user data or some other source of
       symbolic data) are placed here.
   * - unsat
     - If the ``save_unsat`` option is provided to the SimulationManager
       constructor, states that are determined to be unsatisfiable (i.e., they
       have constraints that are contradictory, like the input having to be both
       "AAAA" and "BBBB" at the same time) are placed here.


There is another list of states that is not a stash: ``errored``. If, during
execution, an error is raised, then the state will be wrapped in an
``ErrorRecord`` object, which contains the state and the error it raised, and
then the record will be inserted into ``errored``. You can get at the state as
it was at the beginning of the execution tick that caused the error with
``record.state``, you can see the error that was raised with ``record.error``,
and you can launch a debug shell at the site of the error with
``record.debug()``. This is an invaluable debugging tool!

Simple Exploration
^^^^^^^^^^^^^^^^^^

An extremely common operation in symbolic execution is to find a state that
reaches a certain address, while discarding all states that go through another
address. Simulation manager has a shortcut for this pattern, the ``.explore()``
method.

When launching ``.explore()`` with a ``find`` argument, execution will run until
a state is found that matches the find condition, which can be the address of an
instruction to stop at, a list of addresses to stop at, or a function which
takes a state and returns whether it meets some criteria. When any of the states
in the active stash match the ``find`` condition, they are placed in the
``found`` stash, and execution terminates. You can then explore the found state,
or decide to discard it and continue with the other ones. You can also specify
an ``avoid`` condition in the same format as ``find``. When a state matches the
avoid condition, it is put in the ``avoided`` stash, and execution continues.
Finally, the ``num_find`` argument controls the number of states that should be
found before returning, with a default of 1. Of course, if you run out of states
in the active stash before finding this many solutions, execution will stop
anyway.

Let's look at a simple crackme `example
<./examples.md#reverseme-modern-binary-exploitation---csci-4968>`:

First, we load the binary.

.. code-block:: python

   >>> proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')

Next, we create a SimulationManager.

.. code-block:: python

   >>> simgr = proj.factory.simgr()

Now, we symbolically execute until we find a state that matches our condition
(i.e., the "win" condition).

.. code-block:: python

   >>> simgr.explore(find=lambda s: b"Congrats" in s.posix.dumps(1))
   <SimulationManager with 1 active, 1 found>

Now, we can get the flag out of that state!

.. code-block:: python

   >>> s = simgr.found[0]
   >>> print(s.posix.dumps(1))
   Enter password: Congrats!

   >>> flag = s.posix.dumps(0)
   >>> print(flag)
   g00dJ0B!

Pretty simple, isn't it?

Other examples can be found by browsing the :ref:`examples <angr examples>`.

Exploration Techniques
----------------------

angr ships with several pieces of canned functionality that let you customize
the behavior of a simulation manager, called *exploration techniques*. The
archetypical example of why you would want an exploration technique is to modify
the pattern in which the state space of the program is explored - the default
"step everything at once" strategy is effectively breadth-first search, but with
an exploration technique you could implement, for example, depth-first search.
However, the instrumentation power of these techniques is much more flexible
than that - you can totally alter the behavior of angr's stepping process.
Writing your own exploration techniques will be covered in a later chapter.

To use an exploration technique, call ``simgr.use_technique(tech)``, where tech
is an instance of an ExplorationTechnique subclass. angr's built-in exploration
techniques can be found under ``angr.exploration_techniques``.

Here's a quick overview of some of the built-in ones:


* *DFS*: Depth first search, as mentioned earlier. Keeps only one state active
  at once, putting the rest in the ``deferred`` stash until it deadends or
  errors.
* *Explorer*: This technique implements the ``.explore()`` functionality,
  allowing you to search for and avoid addresses.
* *LengthLimiter*: Puts a cap on the maximum length of the path a state goes
  through.
* *LoopSeer*: Uses a reasonable approximation of loop counting to discard states
  that appear to be going through a loop too many times, putting them in a
  ``spinning`` stash and pulling them out again if we run out of otherwise
  viable states.
* *ManualMergepoint*: Marks an address in the program as a merge point, so
  states that reach that address will be briefly held, and any other states that
  reach that same point within a timeout will be merged together.
* *MemoryWatcher*: Monitors how much memory is free/available on the system
  between simgr steps and stops exploration if it gets too low.
* *Oppologist*: The "operation apologist" is an especially fun gadget - if this
  technique is enabled and angr encounters an unsupported instruction, for
  example a bizarre and foreign floating point SIMD op, it will concretize all
  the inputs to that instruction and emulate the single instruction using the
  unicorn engine, allowing execution to continue.
* *Spiller*: When there are too many states active, this technique can dump some
  of them to disk in order to keep memory consumption low.
* *Threading*: Adds thread-level parallelism to the stepping process. This
  doesn't help much because of Python's global interpreter locks, but if you
  have a program whose analysis spends a lot of time in angr's native-code
  dependencies (unicorn, z3, libvex) you can seem some gains.
* *Tracer*: An exploration technique that causes execution to follow a dynamic
  trace recorded from some other source. The `dynamic tracer repository
  <https://github.com/angr/tracer>`_ has some tools to generate those traces.
* *Veritesting*: An implementation of a `CMU paper
  <https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf>`_
  on automatically identifying useful merge points. This is so useful, you can
  enable it automatically with ``veritesting=True`` in the SimulationManager
  constructor! Note that it frequenly doesn't play nice with other techniques
  due to the invasive way it implements static symbolic execution.

Look at the API documentation for the
:py:class:`~angr.sim_manager.SimulationManager` and
:py:class:`~angr.exploration_techniques.ExplorationTechnique` classes for more
information.

