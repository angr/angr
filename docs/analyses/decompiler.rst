angr Decompiler
===============

Analysis Passes
---------------

.. list-table::
   :header-rows: 1

   * - Name
     - Description
     - Sub-analysis
   * - CFG recovery
     - Recover the control flow graph.
     - Indirect branch resolving
   * - Indirect branch resolving
     - Resolve the targets of indirect branches.
     - Jump table resolving
   * - Removing alignment blocks
     -
     -
   * - Calling convention recovery
     -
     -
   * - Stack pointer analysis
     - Determine values of stack pointer at each instruction.
     -
   * - IR Lifting
     - Lift the original representation to AIL, block by block.
     -
   * - AIL graph building
     -
     -
   * - Rewriting single-target indirect branches
     - Replace single-target indirect branches with direct branches.
     -
   * - Making return statements
     - Convert Ijk_Ret jump kinds into AIL Return statements.
     -
   * - Simplifying AIL blocks
     - Simplify each AIL block.
     - Constant folding, copy propagation, dead assignment elimination, peephole
       optimizations
   * - Reaching definition analysis
     -
     -
   * - Constant folding
     -
     -
   * - Copy propagation
     -
     -
   * - Dead assignment elimination
     -
     -
   * - Peephole optimizations
     -
     -
   * - Simplifying AIL function
     - Simplify the entire AIL function.
     - Assignment expression folding, unifying local variables, call expression
       folding, reaching definition analysis
   * - Assignment expression folding
     - Eliminate variables that are assigned to once and used once.
     - Copy propagation
   * - Unifying local variables
     - Find local variables that are always equivalent and eliminate redundant
       copies.
     - Copy propagation
   * - Call expression folding
     - Fold call expressions into the variable where its return value is stored.
     - Copy propagation
   * - Call site building
     - Apply calling conventions to each call site and rewrite call statements
       to ones with arguments
     - Reaching definition analysis
   * - Variable recovery
     - Identify local and global variables.
     -
   * - Variable type inference
     - Collect type constraints and infer variable types.
     -
   * - Simplification passes
     -
     -
   * - Region identification
     - Identify single-entry, single-exit regions.
     -
   * - Structure analysis
     - Structure each identified region to create high-level control flow
       structures.
     -
   * - Code generation
     -
     -

