Control-flow Graph Recovery (CFG)
=================================

angr includes analyses to recover the control-flow graph of a binary program.
This also includes recovery of function boundaries, as well as reasoning about
indirect jumps and other useful metadata.

General ideas
-------------

A basic analysis that one might carry out on a binary is a Control Flow Graph. A
CFG is a graph with (conceptually) basic blocks as nodes and
jumps/calls/rets/etc as edges.

In angr, there are two types of CFG that can be generated: a static CFG
(CFGFast) and a dynamic CFG (CFGEmulated).

CFGFast uses static analysis to generate a CFG. It is significantly faster, but
is theoretically bounded by the fact that some control-flow transitions can only
be resolved at execution-time. This is the same sort of CFG analysis performed
by other popular reverse-engineering tools, and its results are comparable with
their output.

CFGEmulated uses symbolic execution to capture the CFG. While it is
theoretically more accurate, it is dramatically slower. It is also typically
less complete, due to issues with the accuracy of emulation (system calls,
missing hardware features, and so on)

*If you are unsure which CFG to use, or are having problems with CFGEmulated,
try CFGFast first.*

A CFG can be constructed by doing:

.. code-block:: python

   >>> import angr
   # load your project
   >>> p = angr.Project('/bin/true', load_options={'auto_load_libs': False})

   # Generate a static CFG
   >>> cfg = p.analyses.CFGFast()

   # generate a dynamic CFG
   >>> cfg = p.analyses.CFGEmulated(keep_state=True)

Using the CFG
-------------

The CFG, at its core, is a `NetworkX <https://networkx.github.io/>`_ di-graph.
This means that all of the normal NetworkX APIs are available:

.. code-block:: python

   >>> print("This is the graph:", cfg.graph)
   >>> print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))

The nodes of the CFG graph are instances of class ``CFGNode``. Due to context
sensitivity, a given basic block can have multiple nodes in the graph (for
multiple contexts).

.. code-block:: python

   # this grabs *any* node at a given location:
   >>> entry_node = cfg.get_any_node(p.entry)

   # on the other hand, this grabs all of the nodes
   >>> print("There were %d contexts for the entry block" % len(cfg.get_all_nodes(p.entry)))

   # we can also look up predecessors and successors
   >>> print("Predecessors of the entry point:", entry_node.predecessors)
   >>> print("Successors of the entry point:", entry_node.successors)
   >>> print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ])

Viewing the CFG
^^^^^^^^^^^^^^^

Control-flow graph rendering is a hard problem. angr does not provide any
built-in mechanism for rendering the output of a CFG analysis, and attempting to
use a traditional graph rendering library, like matplotlib, will result in an
unusable image.

One solution for viewing angr CFGs is found in `axt's angr-utils repository
<https://github.com/axt/angr-utils>`_.

Shared Libraries
----------------

The CFG analysis does not distinguish between code from different binary
objects. This means that by default, it will try to analyze control flow through
loaded shared libraries. This is almost never intended behavior, since this will
extend the analysis time to several days, probably. To load a binary without
shared libraries, add the following keyword argument to the ``Project``
constructor: ``load_options={'auto_load_libs': False}``

Function Manager
----------------

The CFG result produces an object called the *Function Manager*, accessible
through ``cfg.kb.functions``. The most common use case for this object is to
access it like a dictionary. It maps addresses to ``Function`` objects, which
can tell you properties about a function.

.. code-block:: python

   >>> entry_func = cfg.kb.functions[p.entry]

Functions have several important properties!


* ``entry_func.block_addrs`` is a set of addresses at which basic blocks
  belonging to the function begin.
* ``entry_func.blocks`` is the set of basic blocks belonging to the function,
  that you can explore and disassemble using capstone.
* ``entry_func.string_references()`` returns a list of all the constant strings
  that were referred to at any point in the function. They are formatted as
  ``(addr, string)`` tuples, where addr is the address in the binary's data
  section the string lives, and string is a Python string that contains the
  value of the string.
* ``entry_func.returning`` is a boolean value signifying whether or not the
  function can return. ``False`` indicates that all paths do not return.
* ``entry_func.callable`` is an angr Callable object referring to this function.
  You can call it like a Python function with Python arguments and get back an
  actual result (may be symbolic) as if you ran the function with those
  arguments!
* ``entry_func.transition_graph`` is a NetworkX DiGraph describing control flow
  within the function itself. It resembles the control-flow graphs IDA displays
  on a per-function level.
* ``entry_func.name`` is the name of the function.
* ``entry_func.has_unresolved_calls`` and ``entry.has_unresolved_jumps`` have to
  do with detecting imprecision within the CFG. Sometimes, the analysis cannot
  detect what the possible target of an indirect call or jump could be. If this
  occurs within a function, that function will have the appropriate
  ``has_unresolved_*`` value set to ``True``.
* ``entry_func.get_call_sites()`` returns a list of all the addresses of basic
  blocks which end in calls out to other functions.
* ``entry_func.get_call_target(callsite_addr)`` will, given ``callsite_addr``
  from the list of call site addresses, return where that callsite will call out
  to.
* ``entry_func.get_call_return(callsite_addr)`` will, given ``callsite_addr``
  from the list of call site addresses, return where that callsite should return
  to.

and many more !

CFGFast details
---------------

CFGFast performs a static control-flow and function recovery. Starting with the
entry point (or any user-defined points) roughly the following procedure is
performed:

1) The basic block is lifted to VEX IR, and all its exits (jumps, calls,
   returns, or continuation to the next block) are collected
2) For each exit, if this exit is a constant address, we add an edge to the CFG
   of the correct type, and add the destination block to the set of blocks to be
   analyzed.
3) In the event of a function call, the destination block is also considered the
   start of a new function. If the target function is known to return, the block
   after the call is also analyzed.
4) In the event of a return, the current function is marked as returning, and
   the appropriate edges in the callgraph and CFG are updated.
5) For all indirect jumps (block exits with a non-constant destination) Indirect
   Jump Resolution is performed.

Finding function starts
^^^^^^^^^^^^^^^^^^^^^^^

CFGFast supports multiple ways of deciding where a function starts and ends.

First the binary's main entry point will be analyzed. For binaries with symbols
(e.g., non-stripped ELF and PE binaries) all function symbols will be used as
possible starting points. For binaries without symbols, such as stripped
binaries, or binaries loaded using the ``blob`` loader backend, CFG will scan
the binary for a set of function prologues defined for the binary's
architecture. Finally, by default, the binary's entire code section will be
scanned for executable contents, regardless of prologues or symbols.

In addition to these, as with CFGEmulated, function starts will also be
considered when they are the target of a "call" instruction on the given
architecture.

All of these options can be disabled

FakeRets and function returns
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When a function call is observed, we first assume that the callee function
eventually returns, and treat the block after it as part of the caller function.
This inferred control-flow edge is known as a "FakeRet". If, in analyzing the
callee, we find this not to be true, we update the CFG, removing this "FakeRet",
and updating the callgraph and function blocks accordingly. As such, the CFG is
recovered *twice*.  In doing this, the set of blocks in each function, and
whether the function returns, can be recovered and propagated directly.

Indirect Jump Resolution
^^^^^^^^^^^^^^^^^^^^^^^^

.. todo::

Options
^^^^^^^

These are the most useful options when working with CFGFast:

.. list-table::
   :header-rows: 1

   * - Option
     - Description
   * - force_complete_scan
     - (Default: True) Treat the entire binary as code for the purposes of
       function detection.  If you have a blob (e.g., mixed code and data) *you
       want to turn this off*.
   * - function_starts
     - A list of addresses, to use as entry points into the analysis.
   * - normalize
     - (Default: False) Normalize the resulting functions (e.g., each basic
       block belongs to at most one function, back-edges point to the start of
       basic blocks)
   * - resolve_indirect_jumps
     - (Default: True) Perform additional analysis to attempt to find targets
       for every indirect jump found during CFG creation.
   * - more!
     - Examine the docstring on p.analyses.CFGFast for more up-to-date options


CFGEmulated details
-------------------

Options
^^^^^^^

The most common options for CFGEmulated include:

.. list-table::
   :header-rows: 1

   * - Option
     - Description
   * - context_sensitivity_level
     - This sets the context sensitivity level of the analysis. See the context
       sensitivity level section below for more information. This is 1 by
       default.
   * - starts
     - A list of addresses, to use as entry points into the analysis.
   * - avoid_runs
     - A list of addresses to ignore in the analysis.
   * - call_depth
     - Limit the depth of the analysis to some number calls. This is useful for
       checking which functions a specific function can directly jump to (by
       setting ``call_depth`` to 1).
   * - initial_state
     - An initial state can be provided to the CFG, which it will use throughout
       its analysis.
   * - keep_state
     - To save memory, the state at each basic block is discarded by default. If
       ``keep_state`` is True, the state is saved in the CFGNode.
   * - enable_symbolic_back_traversal
     - Whether to enable an intensive technique for resolving indirect jumps
   * - enable_advanced_backward_slicing
     - Whether to enable another intensive technique for resolving direct jumps
   * - more!
     - Examine the docstring on p.analyses.CFGEmulated for more up-to-date
       options


Context Sensitivity Level
^^^^^^^^^^^^^^^^^^^^^^^^^

angr constructs a CFG by executing every basic block and seeing where it goes.
This introduces some challenges: a basic block can act differently in different
*contexts*. For example, if a block ends in a function return, the target of
that return will be different, depending on different callers of the function
containing that basic block.

The context sensitivity level is, conceptually, the number of such callers to
keep on the callstack. To explain this concept, let's look at the following
code:

.. code-block:: c

   void error(char *error)
   {
       puts(error);
   }

   void alpha()
   {
       puts("alpha");
       error("alpha!");
   }

   void beta()
   {
       puts("beta");
       error("beta!");
   }

   void main()
   {
       alpha();
       beta();
   }

The above sample has four call chains: ``main>alpha>puts``,
``main>alpha>error>puts`` and ``main>beta>puts``, and ``main>beta>error>puts``.
While, in this case, angr can probably execute both call chains, this becomes
unfeasible for larger binaries. Thus, angr executes the blocks with states
limited by the context sensitivity level. That is, each function is re-analyzed
for each unique context that it is called in.

For example, the ``puts()`` function above will be analyzed with the following
contexts, given different context sensitivity levels:

.. list-table::
   :header-rows: 1

   * - Level
     - Meaning
     - Contexts
   * - 0
     - Callee-only
     - ``puts``
   * - 1
     - One caller, plus callee
     - ``alpha>puts`` ``beta>puts`` ``error>puts``
   * - 2
     - Two callers, plus callee
     - ``alpha>error>puts`` ``main>alpha>puts`` ``beta>error>puts`` ``main>beta>puts``
   * - 3
     - Three callers, plus callee
     - ``main>alpha>error>puts`` ``main>alpha>puts`` ``main>beta>error>puts`` ``main>beta>puts``


The upside of increasing the context sensitivity level is that more information
can be gleaned from the CFG. For example, with context sensitivity of 1, the CFG
will show that, when called from ``alpha``, ``puts`` returns to ``alpha``, when
called from ``error``, ``puts`` returns to ``error``, and so forth. With context
sensitivity of 0, the CFG simply shows that ``puts`` returns to ``alpha``,
``beta``, and ``error``. This, specifically, is the context sensitivity level
used in IDA. The downside of increasing the context sensitivity level is that it
exponentially increases the analysis time.
