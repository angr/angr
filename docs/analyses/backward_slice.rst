Backward Slicing
================

A *program slice* is a subset of statements that is obtained from the original
program, usually by removing zero or more statements. Slicing is often helpful
in debugging and program understanding. For instance, it's usually easier to
locate the source of a variable on a program slice.

A backward slice is constructed from a *target* in the program, and all data
flows in this slice end at the *target*.

angr has a built-in analysis, called ``BackwardSlice``, to construct a backward
program slice. This section will act as a how-to for angr's ``BackwardSlice``
analysis, and followed by some in-depth discussion over the implementation
choices and limitations.

First Step First
----------------

To build a ``BackwardSlice``, you will need the following information as input.


* **Required** CFG. A control flow graph (CFG) of the program. This CFG must be
  an accurate CFG (CFGEmulated).
* **Required** Target, which is the final destination that your backward slice
  terminates at.
* **Optional** CDG. A control dependence graph (CDG) derived from the CFG.
  angr has a built-in analysis ``CDG`` for that purpose.
* **Optional** DDG. A data dependence graph (DDG) built on top of the CFG.
  angr has a built-in analysis ``DDG`` for that purpose.

A ``BackwardSlice`` can be constructed with the following code:

.. code-block:: python

   >>> import angr
   # Load the project
   >>> b = angr.Project("examples/fauxware/fauxware", load_options={"auto_load_libs": False})

   # Generate a CFG first. In order to generate data dependence graph afterwards, you'll have to:
   # - keep all input states by specifying keep_state=True.
   # - store memory, register and temporary values accesses by adding the angr.options.refs option set.
   # Feel free to provide more parameters (for example, context_sensitivity_level) for CFG
   # recovery based on your needs.
   >>> cfg = b.analyses.CFGEmulated(keep_state=True,
   ...                              state_add_options=angr.sim_options.refs,
   ...                              context_sensitivity_level=2)

   # Generate the control dependence graph
   >>> cdg = b.analyses.CDG(cfg)

   # Build the data dependence graph. It might take a while. Be patient!
   >>> ddg = b.analyses.DDG(cfg)

   # See where we wanna go... let's go to the exit() call, which is modeled as a
   # SimProcedure.
   >>> target_func = cfg.kb.functions.function(name="exit")
   # We need the CFGNode instance
   >>> target_node = cfg.get_any_node(target_func.addr)

   # Let's get a BackwardSlice out of them!
   # ``targets`` is a list of objects, where each one is either a CodeLocation
   # object, or a tuple of CFGNode instance and a statement ID. Setting statement
   # ID to -1 means the very beginning of that CFGNode. A SimProcedure does not
   # have any statement, so you should always specify -1 for it.
   >>> bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

   # Here is our awesome program slice!
   >>> print(bs)

Sometimes it's difficult to get a data dependence graph, or you may simply want
build a program slice on top of a CFG. That's basically why DDG is an optional
parameter. You can build a ``BackwardSlice`` solely based on CFG by doing:

.. code-block::

   >>> bs = b.analyses.BackwardSlice(cfg, control_flow_slice=True)
   BackwardSlice (to [(<CFGNode exit (0x10000a0) [0]>, -1)])

Using The ``BackwardSlice`` Object
--------------------------------------

Before you go ahead and use ``BackwardSlice`` object, you should notice that the
design of this class is fairly arbitrary right now, and it is still subject to
change in the near future. We'll try our best to keep this documentation
up-to-date.

Members
^^^^^^^

After construction, a ``BackwardSlice`` has the following members which describe
a program slice:

.. list-table::
   :header-rows: 1

   * - Member
     - Mode
     - Meaning
   * - runs_in_slice
     - CFG-only
     - A ``networkx.DiGraph`` instance showing addresses of blocks and
       SimProcedures in the program slice, as well as transitions between them
   * - cfg_nodes_in_slice
     - CFG-only
     - A ``networkx.DiGraph`` instance showing CFGNodes in the program slice and
       transitions in between
   * - chosen_statements
     - With DDG
     - A dict mapping basic block addresses to lists of statement IDs that are
       part of the program slice
   * - chosen_exits
     - With DDG
     - A dict mapping basic block addresses to a list of "exits". Each exit in
       the list is a valid transition in the program slice


Each "exit" in ``chosen_exit`` is a tuple including a statement ID and a list of
target addresses. For example, an "exit" might look like the following:

.. code-block::

   (35, [ 0x400020 ])

If the "exit" is the default exit of a basic block, it'll look like the
following:

.. code-block::

   ("default", [ 0x400085 ])

Export an Annotated Control Flow Graph
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. todo::

User-friendly Representation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Take a look at ``BackwardSlice.dbg_repr()``!

.. todo::

Implementation Choices
----------------------

.. todo::

Limitations
-----------

.. todo::

Completeness
^^^^^^^^^^^^

.. todo::

Soundness
^^^^^^^^^

.. todo::
