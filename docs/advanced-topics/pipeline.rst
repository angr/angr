Understanding the Execution Pipeline
====================================

If you've made it this far you know that at its core, angr is a highly flexible
and intensely instrumentable emulator. In order to get the most mileage out of
it, you'll want to know what happens at every step of the way when you say
``simgr.run()``.

This is intended to be a more advanced document; you'll need to understand the
function and intent of ``SimulationManager``, ``ExplorationTechnique``,
``SimState``, and ``SimEngine`` in order to understand what we're talking about
at times! You may want to have the angr source open to follow along with this.

At every step along the way, each function will take ``**kwargs`` and pass them
along to the next function in the hierarchy, so you can pass parameters to any
point in the hierarchy and they will trickle down to everything below.

Simulation Managers
-------------------

So you've set your analysis in motion. Time to begin our journey.

``run()``
^^^^^^^^^^^^^

``SimulationManager.run()`` takes several optional parameters, all of which
control when to break out of the stepping loop. Notably, ``n``, and ``until``.
``n`` is used immediately - the run function loops, calling the ``step()``
function and passing on all its parameters until either ``n`` steps have
happened or some other termination condition has occurred. If ``n`` is not
provided, it defaults to 1, unless an ``until`` function is provided, in which
case there will be no numerical cap on the loop. Additionally, the stash that is
being used is taken into consideration, as if it becomes empty execution must
terminate.

So, in summary, when you call ``run()``, ``step()`` will be called in a loop
until any of the following:


#. The ``n`` number of steps have elapsed
#. The ``until`` function returns true
#. The exploration techniques ``complete()`` hooks (combined via the
   ``SimulationManager.completion_mode`` parameter/attribute - it is by default
   the ``any`` builtin function but can be changed to ``all`` for example)
   indicate that the analysis is complete
#. The stash being executed becomes empty

An aside: ``explore()``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

``SimulationManager.explore()`` is a very thin wrapper around ``run()`` which
adds the ``Explorer`` exploration technique, since performing one-off
explorations is a very common action. Its code in its entirety is below:

.. code-block::

   num_find += len(self._stashes[find_stash]) if find_stash in self._stashes else 0
   tech = self.use_technique(Explorer(find, avoid, find_stash, avoid_stash, cfg, num_find))

   try:
       self.run(stash=stash, n=n, **kwargs)
   finally:
       self.remove_technique(tech)

   return self

Exploration technique hooking
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

From here down, every function in the simulation manager can be instrumented by
an exploration technique. The exact mechanism through which this works is that
when you call ``SimulationManager.use_technique()``, angr monkeypatches the
simulation manager to replace any function implemented in the exploration
technique's body with a function which will first call the exploration
technique's function, and then on the second call will call the original
function. This is somewhat messy to implement and certainly not thread safe by
any means, but does produce a clean and powerful interface for exploration
techniques to instrument stepping behavior, either before or after the original
function is called, even choosing whether or not to call the original function
whatsoever. Additionally, it allows multiple exploration techniques to hook the
same function, as the monkeypatched function simply becomes the "original"
function for the next-applied hook.

``step()``
^^^^^^^^^^^^^^

There is a lot of complicated logic in ``step()`` to handle degenerate cases -
mostly implementing the population of the ``deadended`` stash, the
``save_unsat`` option, and calling the ``filter()`` exploration technique hooks.
Beyond this, though, most of the logic is looping through the stash specified by
the ``stash`` argument and calling ``step_state()`` on each state, then applying
the dict result of ``step_state()`` to the stash list. Finally, if the
``step_func`` parameter is provided, it is called with the simulation manager as
a parameter before the step ends.

``step_state()``
^^^^^^^^^^^^^^^^^^^^

The default ``step_state()``, which can be overridden or instrumented by
exploration techniques, is also simple - it calls ``successors()``, which
returns a ``SimSuccessors`` object, and then translates it into a dict mapping
stash names to new states which should be added to that stash. It also
implements error handling - if ``successors()`` throws an error, it will be
caught and an ``ErrorRecord`` will be inserted into
``SimulationManager.errored``.

``successors()``
^^^^^^^^^^^^^^^^^^^^

We've almost made it out of SimulationManager. ``successors()``, which can also
be instrumented by exploration techniques, is supposed to take a state and step
it forward, returning a ``SimSuccessors`` object categorizing its successors
independently of any stash logic. If the ``successor_func`` parameter was
provided, it is used and its return value is returned directly. If this
parameter was not provided, we use the ``project.factory.successors`` method to
tick the state forward and get our ``SimSuccessors``.

The Engine
----------

When we get to the actual successors generation, we need to figure out how to
actually perform the execution. Hopefully, the angr documentation has been
organized in a way such that by the time you reach this page, you know that a
``SimEngine`` is a device that knows how to take a state and produce its
successors. There is only one "default engine" per project, but you can provide
the ``engine`` parameter to specify which engine will be used to perform the
step.

Keep in mind that this parameter can be provided way at the top, to ``.step()``,
``.explore()``, ``.run()`` or anything else that starts execution, and they will
be filtered down to this level. Any additional parameters will continue being
passed down, until they reach the part of the engine they are intended for. The
engine will discard any parameters it doesn't understand.

Generally, the main entry point of an engine is ``SimEngine.process()``, which
can return whatever result it likes, but for simulation managers, engines are
required to use ``SuccessorsMixin``, which provides a ``process()`` method,
which creates a ``SimSuccessors`` object and then calls ``process_successors()``
so that other mixins can fill it out.

angr's default engine, the ``UberEngine``, contains several mixins which provide
the ``process_successors()`` method:


* ``SimEngineFailure`` - handles stepping states with degenerate jumpkinds
* ``SimEngineSyscall`` - handles stepping states which have performed a syscall
  and need it executed
* ``HooksMixin`` - handles stepping states which have reached a hooked address
  and need the hook executed
* ``SimEngineUnicorn`` - executes machine code via the unicorn engine
* ``SootMixin`` - executes java bytecode via the SOOT IR
* ``HeavyVEXMixin`` - executes machine code via the VEX IR

Each of these mixins is implemented to fill out the ``SimSuccessors`` object if
they can handle the current state, otherwise they call ``super()`` to pass the
job on to the next class in the stack.

Engine mixins
-------------

``SimEngineFailure`` handles error cases. It is only used when the previous
jumpkind is one of ``Ijk_EmFail``, ``Ijk_MapFail``, ``Ijk_Sig*``,
``Ijk_NoDecode`` (but only if the address is not hooked), or ``Ijk_Exit``. In
the first four cases, its action is to raise an exception. In the last case, its
action is to simply produce no successors.

``SimEngineSyscall`` services syscalls. It is used when the previous jumpkind is
anything of the form ``Ijk_Sys*``. It works by making a call into ``SimOS`` to
retrieve the SimProcedure that should be run to respond to this syscall, and
then running it! Pretty simple.

``HooksMixin`` provides the hooking functionality in angr. It is used when a
state is at an address that is hooked, and the previous jumpkind is *not*
``Ijk_NoHook``. It simply looks up the associated SimProcedure and runs it on
the state! It also takes the parameter ``procedure``, which will cause the given
procedure to be run for the current step even if the address is not hooked.

``SimEngineUnicorn`` performs concrete execution with the Unicorn Engine. It is
used when the state option ``o.UNICORN`` is enabled, and a myriad of other
conditions designed for maximum efficiency (described below) are met.

``SootMixin`` performs execution over the SOOT IR. Not very important unless you
are analyzing java bytecode, in which case it is very important.

``SimEngineVEX`` is the big fellow. It is used whenever any of the previous
can't be used. It attempts to lift bytes from the current address into an IRSB,
and then executes that IRSB symbolically. There are a huge number of parameters
that can control this process, so it is best to reference the API doc for
:py:meth:`angr.engines.vex.engine.SimEngineVEX.process` describing them.

The exact process by which SimEngineVEX digs into an IRSB is a little
complicated, but essentially it runs all the block's statements in order. This
code is worth reading if you want to see the true inner core of angr's symbolic
execution.

When using Unicorn Engine
-------------------------

If you add the ``o.UNICORN`` state option, at every step ``SimEngineUnicorn``
will be invoked, and try to see if it is allowed to use Unicorn to execute
concretely.

What you REALLY want to do is to add the predefined set ``o.unicorn`` (lowercase) of options to your state:

.. code-block:: python

   unicorn = { UNICORN, UNICORN_SYM_REGS_SUPPORT, INITIALIZE_ZERO_REGISTERS, UNICORN_HANDLE_TRANSMIT_SYSCALL }

These will enable some additional functionalities and defaults which will
greatly enhance your experience. Additionally, there are a lot of options you
can tune on the ``state.unicorn`` plugin.

A good way to understand how unicorn works is by examining the logging output (``logging.getLogger('angr.engines.unicorn_engine').setLevel('DEBUG'); logging.getLogger('angr.state_plugins.unicorn_engine').setLevel('DEBUG')`` from a sample run of unicorn.

.. code-block::

   INFO    | 2017-02-25 08:19:48,012 | angr.state_plugins.unicorn | started emulation at 0x4012f9 (1000000 steps)

Here, angr diverts to unicorn engine, beginning with the basic block at
0x4012f9. The maximum step count is set to 1000000, so if execution stays in
Unicorn for 1000000 blocks, it'll automatically pop out. This is to avoid
hanging in an infinite loop. The block count is configurable via the
``state.unicorn.max_steps`` variable.

.. code-block::

   INFO    | 2017-02-25 08:19:48,014 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
   INFO    | 2017-02-25 08:19:48,016 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
   INFO    | 2017-02-25 08:19:48,019 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
   INFO    | 2017-02-25 08:19:48,022 | angr.state_plugins.unicorn | mmap [0x602000, 0x602fff], 3 (symbolic)
   INFO    | 2017-02-25 08:19:48,023 | angr.state_plugins.unicorn | mmap [0x400000, 0x400fff], 5
   INFO    | 2017-02-25 08:19:48,025 | angr.state_plugins.unicorn | mmap [0x7000000, 0x7000fff], 5

angr performs lazy mapping of data that is accessed by unicorn engine, as it is
accessed. 0x401000 is the page of instructions that it is executing,
0x7fffffffffe0000 is the stack, and so on. Some of these pages are symbolic,
meaning that they contain at least some data that, when accessed, will cause
execution to abort out of Unicorn.

.. code-block::

   INFO    | 2017-02-25 08:19:48,037 | angr.state_plugins.unicorn | finished emulation at 0x7000080 after 3 steps: STOP_STOPPOINT

Execution stays in Unicorn for 3 basic blocks (a computational waste,
considering the required setup), after which it reaches a simprocedure location
and jumps out to execute the simproc in angr.

.. code-block::

   INFO    | 2017-02-25 08:19:48,076 | angr.state_plugins.unicorn | started emulation at 0x40175d (1000000 steps)
   INFO    | 2017-02-25 08:19:48,077 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
   INFO    | 2017-02-25 08:19:48,079 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
   INFO    | 2017-02-25 08:19:48,081 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3

After the simprocedure, execution jumps back into Unicorn.

.. code-block::

   WARNING | 2017-02-25 08:19:48,082 | angr.state_plugins.unicorn | fetching empty page [0x0, 0xfff]
   INFO    | 2017-02-25 08:19:48,103 | angr.state_plugins.unicorn | finished emulation at 0x401777 after 1 steps: STOP_EXECNONE

Execution bounces out of Unicorn almost right away because the binary accessed
the zero-page.

.. code-block::

   INFO    | 2017-02-25 08:19:48,120 | angr.engines.unicorn_engine | not enough runs since last unicorn (100)
   INFO    | 2017-02-25 08:19:48,125 | angr.engines.unicorn_engine | not enough runs since last unicorn (99)

To avoid thrashing in and out of Unicorn (which is expensive), we have cooldowns
(attributes of the ``state.unicorn`` plugin) that wait for certain conditions to
hold (i.e., no symbolic memory accesses for X blocks) before jumping back into
unicorn when a unicorn run is aborted due to anything but a simprocedure or
syscall. Here, the condition it's waiting for is for 100 blocks to be executed
before jumping back in.
