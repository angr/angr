Symbion: Interleaving symbolic and concrete execution
=====================================================

Let's suppose you want to symbolically analyze a specific function of a program,
but there is a huge initialization step that you want to skip because it is not
necessary for your analysis, or cannot properly be emulated by angr. For
example, maybe your program is running on an embedded system and you have access
to a debug interface, but you can't easily replicate the hardware in a simulated
environment.

This is the perfect scenario for ``Symbion``, our interleaved execution
technique!

We implemented a built-in system that let users define a ``ConcreteTarget`` that
is used to "import" a concrete state of the target program from an external
source into ``angr``. Once the state is imported you can make parts of the state
symbolic, use symbolic execution on this state, run your analyses, and finally
concretize the symbolic parts and resume concrete execution in the external
environment. By iterating this process it is possible to implement run-time and
interactive advanced symbolic analyses that are backed up by the real program's
execution!

Isn't that cool?

How to install
--------------

To use this technique you'll need an implementation of a ``ConcreteTarget``
(effectively, an object that is going to be the "glue" between angr and the
external process.) We ship a default one (the AvatarGDBConcreteTarget, which
control an instance of a program being debugged under GDB) in the following repo
https://github.com/angr/angr-targets.

Assuming you installed angr-dev, activate the virtualenv and run:

.. code-block:: bash

   git clone https://github.com/angr/angr-targets.git
   cd angr-targets
   pip install .

Now you're ready to go!

Gists
-----

Once you have created an entry state, instantiated a ``SimulationManager``, and
specified a list of *stop_points* using the ``Symbion`` interface we are going
to resume the concrete process execution.

.. code-block:: python

   # Instantiating the ConcreteTarget
   avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64,
                                        GDB_SERVER_IP, GDB_SERVER_PORT)

   # Creating the Project
   p = angr.Project(binary_x64, concrete_target=avatar_gdb,
                                use_sim_procedures=True)

   # Getting an entry_state
   entry_state = p.factory.entry_state()

   # Forget about these options as for now, will explain later.
   entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
   entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

   # Use Symbion!
   simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x85b853])

When one of your stop_points (effectively a breakpoint) is hit, we give control
to ``angr``. A new plugin called *concrete* is in charge of synchronizing the
concrete state of the program inside a new ``SimState``.

Roughly, synchronization does the following:


* All the registers' values (NOT marked with concrete=False in the respective
  arch file in archinfo) are copied inside the new SimState.
* The underlying memory backend is hooked in a way that all the further memory
  accesses triggered during symbolic execution are redirected to the concrete
  process.
* If the project is initialized with SimProcedure (use_sim_procedures=True) we
  are going to re-hook the external functions' addresses with a ``SimProcedure``
  if we happen to have it, otherwise with a ``SimProcedure`` stub (you can
  control this decision by using the Options SYMBION_KEEP_STUBS_ON_SYNC).
  Conversely, the real code of the function is executed inside angr (Warning: do
  that at your own risk!)

Once this process is completed, you can play with your new ``SimState`` backed
by the concrete process stopped at that particular stop_point.

Options
-------

The way we synchronize the concrete process inside angr is customizable by 2
state options:


* **SYMBION_SYNC_CLE**: this option controls the synchronization of the memory
  mapping of the program inside angr. When the project is created, the memory
  mapping inside angr is different from the one inside the concrete process
  (this will change as soon as Symbion will be fully compatible with archr). If
  you want the process mapping to be fully synchronized with the one of the
  concrete process, set this option to the SimState before initializing the
  SimulationManager (Note that this is going to happen at the first
  synchronization of the concrete process inside angr, NOT before)

  .. code-block:: python

     entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
     simgr = project.factory.simgr(state)

* **SYMBION_KEEP_STUBS_ON_SYNC**: this option controls how we re-hook external
  functions with SimProcedures. If the project has been initialized to use
  SimProcedures (use_sim_procedures=True), we are going to re-hook external
  functions with SimProcedures (if we have that particular implementation) or
  with a generic stub. If you want to execute SimProcedures for functions for
  which we have an available implementation and a generic stub SimProcedure for
  the ones we have not, set this option to the SimState before initializing the
  SimulationManager. In the other case, we are going to execute the real code
  for the external functions that miss a SimProcedure (no generic stub is going
  to be used).

  .. code-block:: python

     entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
     simgr = project.factory.simgr(state)

Example
-------

You can find more information about this technique and a complete example in our
blog post: https://angr.io/blog/angr_symbion/. For more technical details a
public paper will be available soon, or, ping @degrigis on our ``angr`` Slack
channel.
