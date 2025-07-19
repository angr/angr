Core Concepts
=============

To get started with angr, you'll need to have a basic overview of some
fundamental angr concepts and how to construct some basic angr objects. We'll go
over this by examining what's directly available to you after you've loaded a
binary!

Your first action with angr will always be to load a binary into a *project*.
We'll use ``/bin/true`` for these examples.

.. code-block:: python

   >>> import angr
   >>> proj = angr.Project('/bin/true')

A project is your control base in angr. With it, you will be able to dispatch
analyses and simulations on the executable you just loaded. Almost every single
object you work with in angr will depend on the existence of a project in some
form.

.. tip::
   Using and exploring angr in IPython (or other Python command line
   interpreters) is a main use case that we design angr for. When you are not
   sure what interfaces are available, tab completion is your friend!

   Sometimes tab completion in IPython can be slow. We find the following
   workaround helpful without degrading the validity of completion results:

   .. code-block:: python

      # Drop this file in IPython profile's startup directory to avoid running it every time.
      import IPython
      py = IPython.get_ipython()
      py.Completer.use_jedi = False


Basic properties
----------------

First, we have some basic properties about the project: its CPU architecture,
its filename, and the address of its entry point.

.. code-block:: python

   >>> import monkeyhex # this will format numerical results in hexadecimal
   >>> proj.arch
   <Arch AMD64 (LE)>
   >>> proj.entry
   0x401670
   >>> proj.filename
   '/bin/true'


* *arch* is an instance of an ``archinfo.Arch`` object for whichever
  architecture the program is compiled, in this case little-endian amd64. It
  contains a ton of clerical data about the CPU it runs on, which you can peruse
  `at your leisure
  <https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py>`_. The
  common ones you care about are ``arch.bits``, ``arch.bytes`` (that one is a
  ``@property`` declaration on the `main Arch class
  <https://github.com/angr/archinfo/blob/master/archinfo/arch.py>`_),
  ``arch.name``, and ``arch.memory_endness``.
* *entry* is the entry point of the binary!
* *filename* is the absolute filename of the binary. Riveting stuff!

Loading
----------

Getting from a binary file to its representation in a virtual address space is
pretty complicated! We have a module called CLE to handle that. CLE's result,
called the loader, is available in the ``.loader`` property. We'll get into
detail on how to use this :ref:`soon <Loading a Binary>`, but for now just know
that you can use it to see the shared libraries that angr loaded alongside your
program and perform basic queries about the loaded address space.

.. code-block:: python

   >>> proj.loader
   <Loaded true, maps [0x400000:0x5004000]>

   >>> proj.loader.shared_objects # may look a little different for you!
   {'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
    'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

   >>> proj.loader.min_addr
   0x400000
   >>> proj.loader.max_addr
   0x5004000

   >>> proj.loader.main_object  # we've loaded several binaries into this project. Here's the main one!
   <ELF Object true, maps [0x400000:0x60721f]>

   >>> proj.loader.main_object.execstack  # sample query: does this binary have an executable stack?
   False
   >>> proj.loader.main_object.pic  # sample query: is this binary position-independent?
   True

The factory
-----------

There are a lot of classes in angr, and most of them require a project to be
instantiated. Instead of making you pass around the project everywhere, we
provide ``project.factory``, which has several convenient constructors for
common objects you'll want to use frequently.

This section will also serve as an introduction to several basic angr concepts.
Strap in!

Blocks
~~~~~~

First, we have ``project.factory.block()``, which is used to extract a `basic
block <https://en.wikipedia.org/wiki/Basic_block>`_ of code from a given
address. This is an important fact - *angr analyzes code in units of basic
blocks.* You will get back a Block object, which can tell you lots of fun things
about the block of code:

.. code-block:: python

   >>> block = proj.factory.block(proj.entry) # lift a block of code from the program's entry point
   <Block for 0x401670, 42 bytes>

   >>> block.pp()                          # pretty-print a disassembly to stdout
   0x401670:       xor     ebp, ebp
   0x401672:       mov     r9, rdx
   0x401675:       pop     rsi
   0x401676:       mov     rdx, rsp
   0x401679:       and     rsp, 0xfffffffffffffff0
   0x40167d:       push    rax
   0x40167e:       push    rsp
   0x40167f:       lea     r8, [rip + 0x2e2a]
   0x401686:       lea     rcx, [rip + 0x2db3]
   0x40168d:       lea     rdi, [rip - 0xd4]
   0x401694:       call    qword ptr [rip + 0x205866]

   >>> block.instructions                  # how many instructions are there?
   0xb
   >>> block.instruction_addrs             # what are the addresses of the instructions?
   [0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]

Additionally, you can use a Block object to get other representations of the
block of code:

.. code-block:: python

   >>> block.capstone                       # capstone disassembly
   <CapstoneBlock for 0x401670>
   >>> block.vex                            # VEX IRSB (that's a Python internal address, not a program address)
   <pyvex.block.IRSB at 0x7706330>

States
~~~~~~

Here's another fact about angr - the ``Project`` object only represents an
"initialization image" for the program. When you're performing execution with
angr, you are working with a specific object representing a *simulated program
state* - a ``SimState``. Let's grab one right now!

.. code-block:: python

   >>> state = proj.factory.entry_state()
   <SimState @ 0x401670>

A SimState contains a program's memory, registers, filesystem data... any "live
data" that can be changed by execution has a home in the state. We'll cover how
to interact with states in depth later, but for now, let's use ``state.regs``
and ``state.mem`` to access the registers and memory of this state:

.. code-block:: python

   >>> state.regs.rip        # get the current instruction pointer
   <BV64 0x401670>
   >>> state.regs.rax
   <BV64 0x1c>
   >>> state.mem[proj.entry].int.resolved  # interpret the memory at the entry point as a C int
   <BV32 0x8949ed31>

Those aren't Python ints! Those are *bitvectors*. Python integers don't have the
same semantics as words on a CPU, e.g. wrapping on overflow, so we work with
bitvectors, which you can think of as an integer as represented by a series of
bits, to represent CPU data in angr. Note that each bitvector has a ``.length``
property describing how wide it is in bits.

We'll learn all about how to work with them soon, but for now, here's how to
convert from Python ints to bitvectors and back again:

.. code-block:: python

   >>> bv = claripy.BVV(0x1234, 32)       # create a 32-bit-wide bitvector with value 0x1234
   <BV32 0x1234>                               # BVV stands for bitvector value
   >>> state.solver.eval(bv)                # convert to Python int
   0x1234

You can store these bitvectors back to registers and memory, or you can directly
store a Python integer and it'll be converted to a bitvector of the appropriate
size:

.. code-block:: python

   >>> state.regs.rsi = claripy.BVV(3, 64)
   >>> state.regs.rsi
   <BV64 0x3>

   >>> state.mem[0x1000].long = 4
   >>> state.mem[0x1000].long.resolved
   <BV64 0x4>

The ``mem`` interface is a little confusing at first, since it's using some
pretty hefty Python magic. The short version of how to use it is:


* Use array[index] notation to specify an address
* Use ``.<type>`` to specify that the memory should be interpreted as
  :class:`type` (common values: char, short, int, long, size_t, uint8_t,
  uint16_t...)
* From there, you can either:

  * Store a value to it, either a bitvector or a Python int
  * Use ``.resolved`` to get the value as a bitvector
  * Use ``.concrete`` to get the value as a Python int

There are more advanced usages that will be covered later!

Finally, if you try reading some more registers you may encounter a very strange
looking value:

.. code-block:: python

   >>> state.regs.rdi
   <BV64 reg_48_11_64{UNINITIALIZED}>

This is still a 64-bit bitvector, but it doesn't contain a numerical value.
Instead, it has a name! This is called a *symbolic variable* and it is the
underpinning of symbolic execution. Don't panic! We will discuss all of this in
detail exactly two chapters from now.

Simulation Managers
~~~~~~~~~~~~~~~~~~~

If a state lets us represent a program at a given point in time, there must be a
way to get it to the *next* point in time. A simulation manager is the primary
interface in angr for performing execution, simulation, whatever you want to
call it, with states. As a brief introduction, let's show how to tick that state
we created earlier forward a few basic blocks.

First, we create the simulation manager we're going to be using. The constructor
can take a state or a list of states.

.. code-block:: python

   >>> simgr = proj.factory.simulation_manager(state)
   <SimulationManager with 1 active>
   >>> simgr.active
   [<SimState @ 0x401670>]

A simulation manager can contain several *stashes* of states. The default stash,
``active``, is initialized with the state we passed in. We could look at
``simgr.active[0]`` to look at our state some more, if we haven't had enough!

Now... get ready, we're going to do some execution.

.. code-block:: python

   >>> simgr.step()

We've just performed a basic block's worth of symbolic execution! We can look at
the active stash again, noticing that it's been updated, and furthermore, that
it has **not** modified our original state. SimState objects are treated as
immutable by execution - you can safely use a single state as a "base" for
multiple rounds of execution.

.. code-block:: python

   >>> simgr.active
   [<SimState @ 0x1020300>]
   >>> simgr.active[0].regs.rip                 # new and exciting!
   <BV64 0x1020300>
   >>> state.regs.rip                           # still the same!
   <BV64 0x401670>

``/bin/true`` isn't a very good example for describing how to do interesting
things with symbolic execution, so we'll stop here for now.

Analyses
--------

angr comes pre-packaged with several built-in analyses that you can use to extract some fun kinds of information from a program. Here they are:

.. code-block::

   >>> proj.analyses.            # Press TAB here in ipython to get an autocomplete-listing of everything:
    proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses
    proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker
    proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery
    proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast
    proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting
    proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG
    proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG
    proj.analyses.CFGFast              proj.analyses.Reassembler

A couple of these are documented later in this book, but in general, if you want
to find how to use a given analysis, you should look in the api documentation
for :py:mod:`angr.analyses`. As an extremely brief example: here's how you
construct and use a quick control-flow graph:

.. code-block:: python

   # Originally, when we loaded this binary it also loaded all its dependencies into the same virtual address  space
   # This is undesirable for most analysis.
   >>> proj = angr.Project('/bin/true', auto_load_libs=False)
   >>> cfg = proj.analyses.CFGFast()
   <CFGFast Analysis Result at 0x2d85130>

   # cfg.graph is a networkx DiGraph full of CFGNode instances
   # You should go look up the networkx APIs to learn how to use this!
   >>> cfg.graph
   <networkx.classes.digraph.DiGraph at 0x2da43a0>
   >>> len(cfg.graph.nodes())
   951

   # To get the CFGNode for a given address, use cfg.model.get_any_node
   >>> entry_node = cfg.model.get_any_node(proj.entry)
   >>> len(list(cfg.graph.successors(entry_node)))
   2

Now what?
---------

Having read this page, you should now be acquainted with several important angr
concepts: basic blocks, states, bitvectors, simulation managers, and analyses.
You can't really do anything interesting besides just use angr as a glorified
debugger, though! Keep reading, and you will unlock deeper powers...
