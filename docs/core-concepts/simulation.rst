Simulation  and Instrumentation
===============================

When you ask for a step of execution to happen in angr, something has to
actually perform the step. angr uses a series of engines (subclasses of the
``SimEngine`` class) to emulate the effects that of a given section of code has
on an input state. The execution core of angr simply tries all the available
engines in sequence, taking the first one that is able to handle the step. The
following is the default list of engines, in order:


* The failure engine kicks in when the previous step took us to some
  uncontinuable state
* The syscall engine kicks in when the previous step ended in a syscall
* The hook engine kicks in when the current address is hooked
* The unicorn engine kicks in when the ``UNICORN`` state option is enabled and
  there is no symbolic data in the state
* The VEX engine kicks in as the final fallback.

SimSuccessors
-------------

The code that actually tries all the engines in turn is
``project.factory.successors(state, **kwargs)``, which passes its arguments onto
each of the engines. This function is at the heart of ``state.step()`` and
``simulation_manager.step()``. It returns a SimSuccessors object, which we
discussed briefly before. The purpose of SimSuccessors is to perform a simple
categorization of the successor states, stored in various list attributes. They
are:

.. list-table::
   :header-rows: 1

   * - Attribute
     - Guard Condition
     - Instruction Pointer
     - Description
   * - ``successors``
     - True (can be symbolic, but constrained to True)
     - Can be symbolic (but 256 solutions or less; see
       ``unconstrained_successors``).
     - A normal, satisfiable successor state to the state processed by the
       engine. The instruction pointer of this state may be symbolic (i.e., a
       computed jump based on user input), so the state might actually represent
       *several* potential continuations of execution going forward.
   * - ``unsat_successors``
     - False (can be symbolic, but constrained to False).
     - Can be symbolic.
     - Unsatisfiable successors. These are successors whose guard conditions can
       only be false (i.e., jumps that cannot be taken, or the default branch of
       jumps that *must* be taken).
   * - ``flat_successors``
     - True (can be symbolic, but constrained to True).
     - Concrete value.
     - As noted above, states in the ``successors`` list can have symbolic
       instruction pointers. This is rather confusing, as elsewhere in the code
       (i.e., in ``SimEngineVEX.process``, when it's time to step that state
       forward), we make assumptions that a single program state only represents
       the execution of a single spot in the code. To alleviate this, when we
       encounter states in ``successors`` with symbolic instruction pointers, we
       compute all possible concrete solutions (up to an arbitrary threshold of
       256) for them, and make a copy of the state for each such solution. We
       call this process "flattening". These ``flat_successors`` are states,
       each of which has a different, concrete instruction pointer. For example,
       if the instruction pointer of a state in ``successors`` was ``X+5``,
       where ``X`` had constraints of ``X > 0x800000`` and ``X <= 0x800010``, we
       would flatten it into 16 different ``flat_successors`` states, one with
       an instruction pointer of ``0x800006``, one with ``0x800007``, and so on
       until ``0x800015``.
   * - ``unconstrained_successors``
     - True (can be symbolic, but constrained to True).
     - Symbolic (with more than 256 solutions).
     - During the flattening procedure described above, if it turns out that
       there are more than 256 possible solutions for the instruction pointer,
       we assume that the instruction pointer has been overwritten with
       unconstrained data (i.e., a stack overflow with user data). *This
       assumption is not sound in general*. Such states are placed in
       ``unconstrained_successors`` and not in ``successors``.
   * - ``all_successors``
     - Anything
     - Can be symbolic.
     - This is ``successors + unsat_successors + unconstrained_successors``.


Breakpoints
-----------

.. todo:: rewrite this to fix the narrative

Like any decent execution engine, angr supports breakpoints. This is pretty
cool! A point is set as follows:

.. code-block:: python

   >>> import angr
   >>> b = angr.Project('examples/fauxware/fauxware')

   # get our state
   >>> s = b.factory.entry_state()

   # add a breakpoint. This breakpoint will drop into ipdb right before a memory write happens.
   >>> s.inspect.b('mem_write')

   # on the other hand, we can have a breakpoint trigger right *after* a memory write happens.
   # we can also have a callback function run instead of opening ipdb.
   >>> def debug_func(state):
   ...     print("State %s is about to do a memory write!")

   >>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_func)

   # or, you can have it drop you in an embedded IPython!
   >>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=angr.BP_IPYTHON)

There are many other places to break than a memory write. Here is the list. You
can break at BP_BEFORE or BP_AFTER for each of these events.

.. list-table::
   :header-rows: 1

   * - Event type
     - Event meaning
   * - mem_read
     - Memory is being read.
   * - mem_write
     - Memory is being written.
   * - address_concretization
     - A symbolic memory access is being resolved.
   * - reg_read
     - A register is being read.
   * - reg_write
     - A register is being written.
   * - tmp_read
     - A temp is being read.
   * - tmp_write
     - A temp is being written.
   * - expr
     - An expression is being created (i.e., a result of an arithmetic operation
       or a constant in the IR).
   * - statement
     - An IR statement is being translated.
   * - instruction
     - A new (native) instruction is being translated.
   * - irsb
     - A new basic block is being translated.
   * - constraints
     - New constraints are being added to the state.
   * - exit
     - A successor is being generated from execution.
   * - fork
     - A symbolic execution state has forked into multiple states.
   * - symbolic_variable
     - A new symbolic variable is being created.
   * - call
     - A call instruction is hit.
   * - return
     - A ret instruction is hit.
   * - simprocedure
     - A simprocedure (or syscall) is executed.
   * - dirty
     - A dirty IR callback is executed.
   * - syscall
     - A syscall is executed (called in addition to the simprocedure event).
   * - engine_process
     - A SimEngine is about to process some code.


These events expose different attributes:

.. list-table::
   :header-rows: 1

   * - Event type
     - Attribute name
     - Attribute availability
     - Attribute meaning
   * - mem_read
     - mem_read_address
     - BP_BEFORE or BP_AFTER
     - The address at which memory is being read.
   * - mem_read
     - mem_read_expr
     - BP_AFTER
     - The expression at that address.
   * - mem_read
     - mem_read_length
     - BP_BEFORE or BP_AFTER
     - The length of the memory read.
   * - mem_read
     - mem_read_condition
     - BP_BEFORE or BP_AFTER
     - The condition of the memory read.
   * - mem_write
     - mem_write_address
     - BP_BEFORE or BP_AFTER
     - The address at which memory is being written.
   * - mem_write
     - mem_write_length
     - BP_BEFORE or BP_AFTER
     - The length of the memory write.
   * - mem_write
     - mem_write_expr
     - BP_BEFORE or BP_AFTER
     - The expression that is being written.
   * - mem_write
     - mem_write_condition
     - BP_BEFORE or BP_AFTER
     - The condition of the memory write.
   * - reg_read
     - reg_read_offset
     - BP_BEFORE or BP_AFTER
     - The offset of the register being read.
   * - reg_read
     - reg_read_length
     - BP_BEFORE or BP_AFTER
     - The length of the register read.
   * - reg_read
     - reg_read_expr
     - BP_AFTER
     - The expression in the register.
   * - reg_read
     - reg_read_condition
     - BP_BEFORE or BP_AFTER
     - The condition of the register read.
   * - reg_write
     - reg_write_offset
     - BP_BEFORE or BP_AFTER
     - The offset of the register being written.
   * - reg_write
     - reg_write_length
     - BP_BEFORE or BP_AFTER
     - The length of the register write.
   * - reg_write
     - reg_write_expr
     - BP_BEFORE or BP_AFTER
     - The expression that is being written.
   * - reg_write
     - reg_write_condition
     - BP_BEFORE or BP_AFTER
     - The condition of the register write.
   * - tmp_read
     - tmp_read_num
     - BP_BEFORE or BP_AFTER
     - The number of the temp being read.
   * - tmp_read
     - tmp_read_expr
     - BP_AFTER
     - The expression of the temp.
   * - tmp_write
     - tmp_write_num
     - BP_BEFORE or BP_AFTER
     - The number of the temp written.
   * - tmp_write
     - tmp_write_expr
     - BP_AFTER
     - The expression written to the temp.
   * - expr
     - expr
     - BP_BEFORE or BP_AFTER
     - The IR expression.
   * - expr
     - expr_result
     - BP_AFTER
     - The value (e.g. AST) which the expression was evaluated to.
   * - statement
     - statement
     - BP_BEFORE or BP_AFTER
     - The index of the IR statement (in the IR basic block).
   * - instruction
     - instruction
     - BP_BEFORE or BP_AFTER
     - The address of the native instruction.
   * - irsb
     - address
     - BP_BEFORE or BP_AFTER
     - The address of the basic block.
   * - constraints
     - added_constraints
     - BP_BEFORE or BP_AFTER
     - The list of constraint expressions being added.
   * - call
     - function_address
     - BP_BEFORE or BP_AFTER
     - The name of the function being called.
   * - exit
     - exit_target
     - BP_BEFORE or BP_AFTER
     - The expression representing the target of a SimExit.
   * - exit
     - exit_guard
     - BP_BEFORE or BP_AFTER
     - The expression representing the guard of a SimExit.
   * - exit
     - exit_jumpkind
     - BP_BEFORE or BP_AFTER
     - The expression representing the kind of SimExit.
   * - symbolic_variable
     - symbolic_name
     - BP_AFTER
     - The name of the symbolic variable being created. The solver engine might
       modify this name (by appending a unique ID and length). Check the
       symbolic_expr for the final symbolic expression.
   * - symbolic_variable
     - symbolic_size
     - BP_AFTER
     - The size of the symbolic variable being created.
   * - symbolic_variable
     - symbolic_expr
     - BP_AFTER
     - The expression representing the new symbolic variable.
   * - address_concretization
     - address_concretization_strategy
     - BP_BEFORE or BP_AFTER
     - The SimConcretizationStrategy being used to resolve the address. This can
       be modified by the breakpoint handler to change the strategy that will be
       applied. If your breakpoint handler sets this to None, this strategy will
       be skipped.
   * - address_concretization
     - address_concretization_action
     - BP_BEFORE or BP_AFTER
     - The SimAction object being used to record the memory action.
   * - address_concretization
     - address_concretization_memory
     - BP_BEFORE or BP_AFTER
     - The SimMemory object on which the action was taken.
   * - address_concretization
     - address_concretization_expr
     - BP_BEFORE or BP_AFTER
     - The AST representing the memory index being resolved. The breakpoint
       handler can modify this to affect the address being resolved.
   * - address_concretization
     - address_concretization_add_constraints
     - BP_BEFORE or BP_AFTER
     - Whether or not constraints should/will be added for this read.
   * - address_concretization
     - address_concretization_result
     - BP_AFTER
     - The list of resolved memory addresses (integers). The breakpoint handler
       can overwrite these to effect a different resolution result.
   * - syscall
     - syscall_name
     - BP_BEFORE or BP_AFTER
     - The name of the system call.
   * - simprocedure
     - simprocedure_name
     - BP_BEFORE or BP_AFTER
     - The name of the simprocedure.
   * - simprocedure
     - simprocedure_addr
     - BP_BEFORE or BP_AFTER
     - The address of the simprocedure.
   * - simprocedure
     - simprocedure_result
     - BP_AFTER
     - The return value of the simprocedure. You can also *override* it in
       BP_BEFORE, which will cause the actual simprocedure to be skipped and for
       your return value to be used instead.
   * - simprocedure
     - simprocedure
     - BP_BEFORE or BP_AFTER
     - The actual SimProcedure object.
   * - dirty
     - dirty_name
     - BP_BEFORE or BP_AFTER
     - The name of the dirty call.
   * - dirty
     - dirty_handler
     - BP_BEFORE
     - The function that will be run to handle the dirty call. You can override
       this.
   * - dirty
     - dirty_args
     - BP_BEFORE or BP_AFTER
     - The address of the dirty.
   * - dirty
     - dirty_result
     - BP_AFTER
     - The return value of the dirty call. You can also *override* it in
       BP_BEFORE, which will cause the actual dirty call to be skipped and for
       your return value to be used instead.
   * - engine_process
     - sim_engine
     - BP_BEFORE or BP_AFTER
     - The SimEngine that is processing.
   * - engine_process
     - successors
     - BP_BEFORE or BP_AFTER
     - The SimSuccessors object defining the result of the engine.


These attributes can be accessed as members of ``state.inspect`` during the
appropriate breakpoint callback to access the appropriate values. You can even
modify these value to modify further uses of the values!

.. code-block:: python

   >>> def track_reads(state):
   ...     print('Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address)
   ...
   >>> s.inspect.b('mem_read', when=angr.BP_AFTER, action=track_reads)

Additionally, each of these properties can be used as a keyword argument to
``inspect.b`` to make the breakpoint conditional:

.. code-block:: python

   # This will break before a memory write if 0x1000 is a possible value of its target expression
   >>> s.inspect.b('mem_write', mem_write_address=0x1000)

   # This will break before a memory write if 0x1000 is the *only* value of its target expression
   >>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

   # This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
   >>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)

Cool stuff! In fact, we can even specify a function as a condition:

.. code-block:: python

   # this is a complex condition that could do anything! In this case, it makes sure that RAX is 0x41414141 and
   # that the basic block starting at 0x8004 was executed sometime in this path's history
   >>> def cond(state):
   ...     return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.backtrace

   >>> s.inspect.b('mem_write', condition=cond)

That is some cool stuff!

Caution about ``mem_read`` breakpoint
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``mem_read`` breakpoint gets triggered anytime there are memory reads by
either the executing program or the binary analysis. If you are using breakpoint
on ``mem_read`` and also using ``state.mem`` to load data from memory addresses,
then know that the breakpoint will be fired as you are technically reading
memory.

So if you want to load data from memory and not trigger any ``mem_read``
breakpoint you have had set up, then use ``state.memory.load`` with the keyword
arguments ``disable_actions=True`` and ``inspect=False``.

This is also true for ``state.find`` and you can use the same keyword arguments
to prevent ``mem_read`` breakpoints from firing.
