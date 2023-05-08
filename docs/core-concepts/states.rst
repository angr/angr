Machine State - memory, registers, and so on
============================================

So far, we've only used angr's simulated program states (``SimState`` objects)
in the barest possible way in order to demonstrate basic concepts about angr's
operation. Here, you'll learn about the structure of a state object and how to
interact with it in a variety of useful ways.

Review: Reading and writing memory and registers
------------------------------------------------

If you've been reading this book in order (and you should be, at least for this
first section), you already saw the basics of how to access memory and
registers. ``state.regs`` provides read and write access to the registers
through attributes with the names of each register, and ``state.mem`` provides
typed read and write access to memory with index-access notation to specify the
address followed by an attribute access to specify the type you would like to
interpret the memory as.

Additionally, you should now know how to work with ASTs, so you can now
understand that any bitvector-typed AST can be stored in registers or memory.

Here are some quick examples for copying and performing operations on data from
the state:

.. code-block:: python

   >>> import angr, claripy
   >>> proj = angr.Project('/bin/true')
   >>> state = proj.factory.entry_state()

   # copy rsp to rbp
   >>> state.regs.rbp = state.regs.rsp

   # store rdx to memory at 0x1000
   >>> state.mem[0x1000].uint64_t = state.regs.rdx

   # dereference rbp
   >>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

   # add rax, qword ptr [rsp + 8]
   >>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved

Basic Execution
---------------

Earlier, we showed how to use a Simulation Manager to do some basic execution.
We'll show off the full capabilities of the simulation manager in the next
chapter, but for now we can use a much simpler interface to demonstrate how
symbolic execution works: ``state.step()``. This method will perform one step of
symbolic execution and return an object called
:py:class:`angr.engines.successors.SimSuccessors`. Unlike normal emulation,
symbolic execution can produce several successor states that can be classified
in a number of ways. For now, what we care about is the ``.successors`` property
of this object, which is a list containing all the "normal" successors of a
given step.

Why a list, instead of just a single successor state? Well, angr's process of
symbolic execution is just the taking the operations of the individual
instructions compiled into the program and performing them to mutate a SimState.
When a line of code like ``if (x > 4)`` is reached, what happens if x is a
symbolic bitvector? Somewhere in the depths of angr, the comparison ``x > 4`` is
going to get performed, and the result is going to be ``<Bool x_32_1 > 4>``.

That's fine, but the next question is, do we take the "true" branch or the
"false" one? The answer is, we take both! We generate two entirely separate
successor states - one simulating the case where the condition was true and
simulating the case where the condition was false. In the first state, we add
``x > 4`` as a constraint, and in the second state, we add ``!(x > 4)`` as a
constraint. That way, whenever we perform a constraint solve using either of
these successor states, *the conditions on the state ensure that any solutions
we get are valid inputs that will cause execution to follow the same path that
the given state has followed.*

To demonstrate this, let's use a `fake firmware image
<../examples/fauxware/fauxware>` as an example. If you look at the `source code
<../examples/fauxware/fauxware.c>` for this binary, you'll see that the
authentication mechanism for the firmware is backdoored; any username can be
authenticated as an administrator with the password "SOSNEAKY". Furthermore, the
first comparison against user input that happens is the comparison against the
backdoor, so if we step until we get more than one successor state, one of those
states will contain conditions constraining the user input to be the backdoor
password. The following snippet implements this:

.. code-block:: python

   >>> proj = angr.Project('examples/fauxware/fauxware')
   >>> state = proj.factory.entry_state(stdin=angr.SimFile)  # ignore that argument for now - we're disabling a more complicated default setup for the sake of education
   >>> while True:
   ...     succ = state.step()
   ...     if len(succ.successors) == 2:
   ...         break
   ...     state = succ.successors[0]

   >>> state1, state2 = succ.successors
   >>> state1
   <SimState @ 0x400629>
   >>> state2
   <SimState @ 0x400699

Don't look at the constraints on these states directly - the branch we just went
through involves the result of ``strcmp``, which is a tricky function to emulate
symbolically, and the resulting constraints are *very* complicated.

The program we emulated took data from standard input, which angr treats as an
infinite stream of symbolic data by default. To perform a constraint solve and
get a possible value that input could have taken in order to satisfy the
constraints, we'll need to get a reference to the actual contents of stdin.
We'll go over how our file and input subsystems work later on this very page,
but for now, just use ``state.posix.stdin.load(0, state.posix.stdin.size)`` to
retrieve a bitvector representing all the content read from stdin so far.

.. code-block:: python

   >>> input_data = state1.posix.stdin.load(0, state1.posix.stdin.size)

   >>> state1.solver.eval(input_data, cast_to=bytes)
   b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00\x00\x00'

   >>> state2.solver.eval(input_data, cast_to=bytes)
   b'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00\x00\x00'

As you can see, in order to go down the ``state1`` path, you must have given as
a password the backdoor string "SOSNEAKY". In order to go down the ``state2``
path, you must have given something *besides* "SOSNEAKY". z3 has helpfully
provided one of the billions of strings fitting this criteria.

Fauxware was the first program angr's symbolic execution ever successfully
worked on, back in 2013. By finding its backdoor using angr you are
participating in a grand tradition of having a bare-bones understanding of how
to use symbolic execution to extract meaning from binaries!

State Presets
-------------

So far, whenever we've been working with a state, we've created it with
``project.factory.entry_state()``. This is just one of several *state
constructors* available on the project factory:


* ``.blank_state()`` constructs a "blank slate" blank state, with most of its
  data left uninitialized. When accessing uninitialized data, an unconstrained
  symbolic value will be returned.
* ``.entry_state()`` constructs a state ready to execute at the main binary's
  entry point.
* ``.full_init_state()`` constructs a state that is ready to execute through any
  initializers that need to be run before the main binary's entry point, for
  example, shared library constructors or preinitializers. When it is finished
  with these it will jump to the entry point.
* ``.call_state()`` constructs a state ready to execute a given function.

You can customize the state through several arguments to these constructors:


* All of these constructors can take an ``addr`` argument to specify the exact
  address to start.

* If you're executing in an environment that can take command line arguments or
  an environment, you can pass a list of arguments through ``args`` and a
  dictionary of environment variables through ``env`` into ``entry_state`` and
  ``full_init_state``. The values in these structures can be strings or
  bitvectors, and will be serialized into the state as the arguments and
  environment to the simulated execution. The default ``args`` is an empty list,
  so if the program you're analyzing expects to find at least an ``argv[0]``,
  you should always provide that!

* If you'd like to have ``argc`` be symbolic, you can pass a symbolic bitvector
  as ``argc`` to the ``entry_state`` and ``full_init_state`` constructors. Be
  careful, though: if you do this, you should also add a constraint to the
  resulting state that your value for argc cannot be larger than the number of
  args you passed into ``args``.

* To use the call state, you should call it with ``.call_state(addr, arg1, arg2,
  ...)``, where ``addr`` is the address of the function you want to call and
  ``argN`` is the Nth argument to that function, either as a Python integer,
  string, or array, or a bitvector. If you want to have memory allocated and
  actually pass in a pointer to an object, you should wrap it in an
  PointerWrapper, i.e. ``angr.PointerWrapper("point to me!")``. The results of
  this API can be a little unpredictable, but we're working on it.

* To specify the calling convention used for a function with ``call_state``, you
  can pass a :py:class:`~angr.calling_conventions.SimCC` instance as the ``cc``
  argument.:raw-html-m2r:`<br>` We try to pick a sane default, but for special
  cases you will need to help angr out.

There are several more options that can be used in any of these constructors!
See the docs on the ``project.factory`` object (an
:py:class:`angr.factory.AngrObjectFactory`) for more details.

Low level interface for memory
------------------------------

The ``state.mem`` interface is convenient for loading typed data from memory,
but when you want to do raw loads and stores to and from ranges of memory, it's
very cumbersome. It turns out that ``state.mem`` is actually just a bunch of
logic to correctly access the underlying memory storage, which is just a flat
address space filled with bitvector data: ``state.memory``. You can use
``state.memory`` directly with the ``.load(addr, size)`` and ``.store(addr,
val)`` methods:

.. code-block:: python

   >>> s = proj.factory.blank_state()
   >>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
   >>> s.memory.load(0x4004, 6) # load-size is in bytes
   <BV48 0x89abcdef0123>

As you can see, the data is loaded and stored in a "big-endian" fashion, since
the primary purpose of ``state.memory`` is to load an store swaths of data with
no attached semantics. However, if you want to perform a byteswap on the loaded
or stored data, you can pass a keyword argument ``endness`` - if you specify
little-endian, byteswap will happen. The endness should be one of the members of
the ``Endness`` enum in the ``archinfo`` package used to hold declarative data
about CPU architectures for angr. Additionally, the endness of the program being
analyzed can be found as ``arch.memory_endness`` - for instance
``state.arch.memory_endness``.

.. code-block:: python

   >>> import archinfo
   >>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
   <BV32 0x67452301>

There is also a low-level interface for register access, ``state.registers``,
that uses the exact same API as ``state.memory``, but explaining its behavior
involves a :ref:`dive <Intermediate Representation>` into the abstractions that
angr uses to seamlessly work with multiple architectures. The short version is
that it is simply a register file, with the mapping between registers and
offsets defined in `archinfo <https://github.com/angr/archinfo>`_.

State Options
-------------

There are a lot of little tweaks that can be made to the internals of angr that
will optimize behavior in some situations and be a detriment in others. These
tweaks are controlled through state options.

On each SimState object, there is a set (``state.options``) of all its enabled
options. Each option (really just a string) controls the behavior of angr's
execution engine in some minute way. A listing of the full domain of options,
along with the defaults for different state types, can be found in :ref:`the
appendix <List of State Options>`. You can access an individual option for
adding to a state through ``angr.options``. The individual options are named
with CAPITAL_LETTERS, but there are also common groupings of objects that you
might want to use bundled together, named with lowercase_letters.

When creating a SimState through any constructor, you may pass the keyword
arguments ``add_options`` and ``remove_options``, which should be sets of
options that modify the initial options set from the default.

.. code-block:: python

   # Example: enable lazy solves, an option that causes state satisfiability to be checked as infrequently as possible.
   # This change to the settings will be propagated to all successor states created from this state after this line.
   >>> s.options.add(angr.options.LAZY_SOLVES)

   # Create a new state with lazy solves enabled
   >>> s = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})

   # Create a new state without simplification options enabled
   >>> s = proj.factory.entry_state(remove_options=angr.options.simplification)

State Plugins
-------------

With the exception of the set of options just discussed, everything stored in a
SimState is actually stored in a *plugin* attached to the state. Almost every
property on the state we've discussed so far is a plugin - ``memory``,
``registers``, ``mem``, ``regs``, ``solver``, etc. This design allows for code
modularity as well as the ability to easily :ref:`implement new kinds of data
storage <State Plugins>` for other aspects of an emulated state, or the ability
to provide alternate implementations of plugins.

For example, the normal ``memory`` plugin simulates a flat memory space, but
analyses can choose to enable the "abstract memory" plugin, which uses alternate
data types for addresses to simulate free-floating memory mappings independent
of address, to provide ``state.memory``. Conversely, plugins can reduce code
complexity: ``state.memory`` and ``state.registers`` are actually two different
instances of the same plugin, since the registers are emulated with an address
space as well.

The globals plugin
^^^^^^^^^^^^^^^^^^

``state.globals`` is an extremely simple plugin: it implements the interface of
a standard Python dict, allowing you to store arbitrary data on a state.

The history plugin
^^^^^^^^^^^^^^^^^^

``state.history`` is a very important plugin storing historical data about the
path a state has taken during execution. It is actually a linked list of several
history nodes, each one representing a single round of execution---you can
traverse this list with ``state.history.parent.parent`` etc.

To make it more convenient to work with this structure, the history also
provides several efficient iterators over the history of certain values. In
general, these values are stored as ``history.recent_NAME`` and the iterator
over them is just ``history.NAME``. For example, ``for addr in
state.history.bbl_addrs: print hex(addr)`` will print out a basic block address
trace for the binary, while ``state.history.recent_bbl_addrs`` is the list of
basic blocks executed in the most recent step,
``state.history.parent.recent_bbl_addrs`` is the list of basic blocks executed
in the previous step, etc. If you ever need to quickly obtain a flat list of
these values, you can access ``.hardcopy``, e.g.
``state.history.bbl_addrs.hardcopy``. Keep in mind though, index-based accessing
is implemented on the iterators.

Here is a brief listing of some of the values stored in the history:


* ``history.descriptions`` is a listing of string descriptions of each of the
  rounds of execution performed on the state.
* ``history.bbl_addrs`` is a listing of the basic block addresses executed by
  the state. There may be more than one per round of execution, and not all
  addresses may correspond to binary code - some may be addresses at which
  SimProcedures are hooked.
* ``history.jumpkinds`` is a listing of the disposition of each of the control
  flow transitions in the state's history, as VEX enum strings.
* ``history.jump_guards`` is a listing of the conditions guarding each of the
  branches that the state has encountered.
* ``history.events`` is a semantic listing of "interesting events" which
  happened during execution, such as the presence of a symbolic jump condition,
  the program popping up a message box, or execution terminating with an exit
  code.
* ``history.actions`` is usually empty, but if you add the ``angr.options.refs``
  options to the state, it will be populated with a log of all the memory,
  register, and temporary value accesses performed by the program.

The callstack plugin
^^^^^^^^^^^^^^^^^^^^

angr will track the call stack for the emulated program. On every call
instruction, a frame will be added to the top of the tracked callstack, and
whenever the stack pointer drops below the point where the topmost frame was
called, a frame is popped. This allows angr to robustly store data local to the
current emulated function.

Similar to the history, the callstack is also a linked list of nodes, but there
are no provided iterators over the contents of the nodes - instead you can
directly iterate over ``state.callstack`` to get the callstack frames for each
of the active frames, in order from most recent to oldest. If you just want the
topmost frame, this is ``state.callstack``.


* ``callstack.func_addr`` is the address of the function currently being
  executed
* ``callstack.call_site_addr`` is the address of the basic block which called
  the current function
* ``callstack.stack_ptr`` is the value of the stack pointer from the beginning
  of the current function
* ``callstack.ret_addr`` is the location that the current function will return
  to if it returns

More about I/O: Files, file systems, and network sockets
--------------------------------------------------------

Please refer to :ref:`Working with File System, Sockets, and Pipes` for a more
complete and detailed documentation of how I/O is modeled in angr.

Copying and Merging
-------------------

A state supports very fast copies, so that you can explore different
possibilities:

.. code-block:: python

   >>> proj = angr.Project('/bin/true')
   >>> s = proj.factory.blank_state()
   >>> s1 = s.copy()
   >>> s2 = s.copy()

   >>> s1.mem[0x1000].uint32_t = 0x41414141
   >>> s2.mem[0x1000].uint32_t = 0x42424242

States can also be merged together.

.. code-block:: python

   # merge will return a tuple. the first element is the merged state
   # the second element is a symbolic variable describing a state flag
   # the third element is a boolean describing whether any merging was done
   >>> (s_merged, m, anything_merged) = s1.merge(s2)

   # this is now an expression that can resolve to "AAAA" *or* "BBBB"
   >>> aaaa_or_bbbb = s_merged.mem[0x1000].uint32_t

.. todo:: describe limitations of merging
