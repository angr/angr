List of Claripy Operations
==========================

Arithmetic and Logic
~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1

   * - Name
     - Description
     - Example
   * - LShR
     - Logically shifts an expression to the right. (the default shifts are
       arithmetic)
     - ``x.LShR(10)``
   * - RotateLeft
     - Rotates an expression left
     - ``x.RotateLeft(8)``
   * - RotateRight
     - Rotates an expression right
     - ``x.RotateRight(8)``
   * - And
     - Logical And (on boolean expressions)
     - ``claripy.And(x == y, x > 0)``
   * - Or
     - Logical Or (on boolean expressions)
     - ``claripy.Or(x == y, y < 10)``
   * - Not
     - Logical Not (on a boolean expression)
     - ``claripy.Not(x == y)`` is the same as ``x != y``
   * - If
     - An If-then-else
     - Choose the maximum of two expressions: ``claripy.If(x > y, x, y)``
   * - ULE
     - Unsigned less than or equal to
     - Check if x is less than or equal to y: ``x.ULE(y)``
   * - ULT
     - Unsigned less than
     - Check if x is less than y: ``x.ULT(y)``
   * - UGE
     - Unsigned greater than or equal to
     - Check if x is greater than or equal to y: ``x.UGE(y)``
   * - UGT
     - Unsigned greater than
     - Check if x is greater than y: ``x.UGT(y)``
   * - SLE
     - Signed less than or equal to
     - Check if x is less than or equal to y: ``x.SLE(y)``
   * - SLT
     - Signed less than
     - Check if x is less than y: ``x.SLT(y)``
   * - SGE
     - Signed greater than or equal to
     - Check if x is greater than or equal to y: ``x.SGE(y)``
   * - SGT
     - Signed greater than
     - Check if x is greater than y: ``x.SGT(y)``


.. todo:: Add the floating point ops

Bitvector Manipulation
~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1

   * - Name
     - Description
     - Example
   * - SignExt
     - Pad a bitvector on the left with ``n`` sign bits
     - ``x.sign_extend(n)``
   * - ZeroExt
     - Pad a bitvector on the left with ``n`` zero bits
     - ``x.zero_extend(n)``
   * - Extract
     - Extracts the given bits (zero-indexed from the *right*, inclusive) from
       an expression.
     - Extract the least significant byte of x: ``x[7:0]``
   * - Concat
     - Concatenates any number of expressions together into a new expression.
     - ``x.concat(y, ...)``


Extra Functionality
~~~~~~~~~~~~~~~~~~~

There's a bunch of prepackaged behavior that you *could* implement by analyzing
the ASTs and composing sets of operations, but here's an easier way to do it:


* You can chop a bitvector into a list of chunks of ``n`` bits with
  ``val.chop(n)``
* You can endian-reverse a bitvector with ``x.reversed``
* You can get the width of a bitvector in bits with ``val.length``
* You can test if an AST has any symbolic components with ``val.symbolic``
* You can get a set of the names of all the symbolic variables implicated in the
  construction of an AST with ``val.variables``
