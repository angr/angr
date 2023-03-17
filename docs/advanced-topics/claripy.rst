Solver Engine
=============

angr's solver engine is called Claripy. Claripy exposes the following design:


* Claripy ASTs (the subclasses of claripy.ast.Base) provide a unified way to
  interact with concrete and symbolic expressions
* ``Frontend``\ s provide different paradigms for evaluating these expressions.
  For example, the ``FullFrontend`` solves expressions using something like an
  SMT solver backend, while ``LightFrontend`` handles them by using an abstract
  (and approximating) data domain backend.
* Each ``Frontend`` needs to, at some point, do actual operation and evaluations
  on an AST. ASTs don't support this on their own. Instead, ``Backend``\ s
  translate ASTs into backend objects (i.e., Python primitives for
  ``BackendConcrete``, Z3 expressions for ``BackendZ3``, strided intervals for
  ``BackendVSA``, etc) and handle any appropriate state-tracking objects (such
  as tracking the solver state in the case of ``BackendZ3``). Roughly speaking,
  frontends take ASTs as inputs and use backends to ``backend.convert()`` those
  ASTs into backend objects that can be evaluated and otherwise reasoned about.
* ``FrontendMixin``\ s customize the operation of ``Frontend``\ s. For example,
  ``ModelCacheMixin`` caches solutions from an SMT solver.
* The combination of a Frontend, a number of FrontendMixins, and a number of
  Backends comprise a claripy ``Solver``.

Internally, Claripy seamlessly mediates the co-operation of multiple disparate
backends -- concrete bitvectors, VSA constructs, and SAT solvers. It is pretty
badass.

Most users of angr will not need to interact directly with Claripy (except for,
maybe, claripy AST objects, which represent symbolic expressions) -- angr
handles most interactions with Claripy internally. However, for dealing with
expressions, an understanding of Claripy might be useful.

Claripy ASTs
------------

Claripy ASTs abstract away the differences between mathematical constructs that
Claripy supports. They define a tree of operations (i.e., ``(a + b) / c)`` on
any type of underlying data. Claripy handles the application of these operations
on the underlying objects themselves by dispatching requests to the backends.

Currently, Claripy supports the following types of ASTs:

.. list-table::
   :header-rows: 1

   * - Name
     - Description
     - Supported By (Claripy Backends)
     - Example Code
   * - BV
     - This is a bitvector, whether symbolic (with a name) or concrete (with a
       value). It has a size (in bits).
     - BackendConcrete, BackendVSA, BackendZ3
     - Create a 32-bit symbolic bitvector "x": `claripy.BVS('x', 32)` Create a
       32-bit bitvector with the value `0xc001b3475`: `claripy.BVV(0xc001b3a75,
       32)`</li><li>Create a 32-bit "strided interval" (see VSA documentation)
       that can be any divisible-by-10 number between 1000 and 2000:
       `claripy.SI(name='x', bits=32, lower_bound=1000, upper_bound=2000,
       stride=10)`</li></ul>`
   * - FP
     - This is a floating-point number, whether symbolic (with a name) or
       concrete (with a value).
     - BackendConcrete, BackendZ3
     - Create a `claripy.fp.FSORT_DOUBLE` symbolic floating point "b": `claripy.FPS('b',
          claripy.fp.FSORT_DOUBLE)`Create a `claripy.fp.FSORT_FLOAT`
          floating point with value `3.2`: `claripy.FPV(3.2,
          claripy.fp.FSORT_FLOAT)`
   * - Bool
     - This is a boolean operation (True or False).
     - BackendConcrete, BackendVSA, BackendZ3
     - ``claripy.BoolV(True)``, or ``claripy.true`` or ``claripy.false``, or by
       comparing two ASTs (i.e., ``claripy.BVS('x', 32) < claripy.BVS('y', 32)``


All of the above creation code returns claripy.AST objects, on which operations
can then be carried out.

ASTs provide several useful operations.

.. code-block:: python

   >>> import claripy

   >>> bv = claripy.BVV(0x41424344, 32)

   # Size - you can get the size of an AST with .size()
   >>> assert bv.size() == 32

   # Reversing - .reversed is the reversed version of the BVV
   >>> assert bv.reversed is claripy.BVV(0x44434241, 32)
   >>> assert bv.reversed.reversed is bv

   # Depth - you can get the depth of the AST
   >>> print(bv.depth)
   >>> assert bv.depth == 1
   >>> x = claripy.BVS('x', 32)
   >>> assert (x+bv).depth == 2
   >>> assert ((x+bv)/10).depth == 3

Applying a condition (==, !=, etc) on ASTs will return an AST that represents
the condition being carried out. For example:

.. code-block:: python

   >>> r = bv == x
   >>> assert isinstance(r, claripy.ast.Bool)

   >>> p = bv == bv
   >>> assert isinstance(p, claripy.ast.Bool)
   >>> assert p.is_true()

You can combine these conditions in different ways.

.. code-block:: python

   >>> q = claripy.And(claripy.Or(bv == x, bv * 2 == x, bv * 3 == x), x == 0)
   >>> assert isinstance(p, claripy.ast.Bool)

The usefulness of this will become apparent when we discuss Claripy solvers.

In general, Claripy supports all of the normal Python operations (+, -, |, ==,
etc), and provides additional ones via the Claripy instance object. Here's a
list of available operations from the latter.

.. list-table::
   :header-rows: 1

   * - Name
     - Description
     - Example
   * - LShR
     - Logically shifts a bit expression (BVV, BV, SI) to the right.
     - ``claripy.LShR(x, 10)``
   * - SignExt
     - Sign-extends a bit expression.
     - ``claripy.SignExt(32, x)`` or ``x.sign_extend(32)``
   * - ZeroExt
     - Zero-extends a bit expression.
     - ``claripy.ZeroExt(32, x)`` or ``x.zero_extend(32)``
   * - Extract
     - Extracts the given bits (zero-indexed from the *right*, inclusive) from a
       bit expression.
     - Extract the rightmost byte of x: ``claripy.Extract(7, 0, x)`` or ``x[7:0]``
   * - Concat
     - Concatenates several bit expressions together into a new bit expression.
     - ``claripy.Concat(x, y, z)``
   * - RotateLeft
     - Rotates a bit expression left.
     - ``claripy.RotateLeft(x, 8)``
   * - RotateRight
     - Rotates a bit expression right.
     - ``claripy.RotateRight(x, 8)``
   * - Reverse
     - Endian-reverses a bit expression.
     - ``claripy.Reverse(x)`` or ``x.reversed``
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
     - Unsigned less than or equal to.
     - Check if x is less than or equal to y: ``claripy.ULE(x, y)``
   * - ULT
     - Unsigned less than.
     - Check if x is less than y: ``claripy.ULT(x, y)``
   * - UGE
     - Unsigned greater than or equal to.
     - Check if x is greater than or equal to y: ``claripy.UGE(x, y)``
   * - UGT
     - Unsigned greater than.
     - Check if x is greater than y: ``claripy.UGT(x, y)``
   * - SLE
     - Signed less than or equal to.
     - Check if x is less than or equal to y: ``claripy.SLE(x, y)``
   * - SLT
     - Signed less than.
     - Check if x is less than y: ``claripy.SLT(x, y)``
   * - SGE
     - Signed greater than or equal to.
     - Check if x is greater than or equal to y: ``claripy.SGE(x, y)``
   * - SGT
     - Signed greater than.
     - Check if x is greater than y: ``claripy.SGT(x, y)``


.. note::
   The default Python ``>``, ``<``, ``>=``, and ``<=`` are unsigned in Claripy.
   This is different than their behavior in Z3, because it seems more natural in
   binary analysis.

Solvers
-------

The main point of interaction with Claripy are the Claripy Solvers. Solvers
expose an API to interpret ASTs in different ways and return usable values.
There are several different solvers.

.. list-table::
   :header-rows: 1

   * - Name
     - Description
   * - Solver
     - This is analogous to a ``z3.Solver()``. It is a solver that tracks
       constraints on symbolic variables and uses a constraint solver
       (currently, Z3) to evaluate symbolic expressions.
   * - SolverVSA
     - This solver uses VSA to reason about values. It is an *approximating*
       solver, but produces values without performing actual constraint solves.
   * - SolverReplacement
     - This solver acts as a pass-through to a child solver, allowing the
       replacement of expressions on-the-fly. It is used as a helper by other
       solvers and can be used directly to implement exotic analyses.
   * - SolverHybrid
     - This solver combines the SolverReplacement and the Solver (VSA and Z3) to
       allow for *approximating* values. You can specify whether or not you want
       an exact result from your evaluations, and this solver does the rest.
   * - SolverComposite
     - This solver implements optimizations that solve smaller sets of
       constraints to speed up constraint solving.


Some examples of solver usage:

.. code-block:: python

   # create the solver and an expression
   >>> s = claripy.Solver()
   >>> x = claripy.BVS('x', 8)

   # now let's add a constraint on x
   >>> s.add(claripy.ULT(x, 5))

   >>> assert sorted(s.eval(x, 10)) == [0, 1, 2, 3, 4]
   >>> assert s.max(x) == 4
   >>> assert s.min(x) == 0

   # we can also get the values of complex expressions
   >>> y = claripy.BVV(65, 8)
   >>> z = claripy.If(x == 1, x, y)
   >>> assert sorted(s.eval(z, 10)) == [1, 65]

   # and, of course, we can add constraints on complex expressions
   >>> s.add(z % 5 != 0)
   >>> assert s.eval(z, 10) == (1,)
   >>> assert s.eval(x, 10) == (1,) # interestingly enough, since z can't be y, x can only be 1!

Custom solvers can be built by combining a Claripy Frontend (the class that
handles the actual interaction with SMT solver or the underlying data domain)
and some combination of frontend mixins (that handle things like caching,
filtering out duplicate constraints, doing opportunistic simplification, and so
on).

Claripy Backends
----------------

Backends are Claripy's workhorses. Claripy exposes ASTs to the world, but when
actual computation has to be done, it pushes those ASTs into objects that can be
handled by the backends themselves. This provides a unified interface to the
outside world while allowing Claripy to support different types of computation.
For example, BackendConcrete provides computation support for concrete
bitvectors and booleans, BackendVSA introduces VSA constructs such as
StridedIntervals (and details what happens when operations are performed on
them, and BackendZ3 provides support for symbolic variables and constraint
solving.

There are a set of functions that a backend is expected to implement. For all of
these functions, the "public" version is expected to be able to deal with
claripy's AST objects, while the "private" version should only deal with objects
specific to the backend itself. This is distinguished with Python idioms: a
public function will be named func() while a private function will be _func().
All functions should return objects that are usable by the backend in its
private methods. If this can't be done (i.e., some functionality is being
attempted that the backend can't handle), the backend should raise a
BackendError. In this case, Claripy will move on to the next backend in its
list.

All backends must implement a ``convert()`` function. This function receives a
claripy AST and should return an object that the backend can handle in its
private methods. Backends should also implement a ``convert()`` method, which
will receive anything that is *not* a claripy AST object (i.e., an integer or an
object from a different backend). If ``convert()`` or ``convert()`` receives
something that the backend can't translate to a format that is usable
internally, the backend should raise BackendError, and thus won't be used for
that object. All backends must also implement any functions of the base
``Backend`` abstract class that currently raise ``NotImplementedError()``.

Claripy's contract with its backends is as follows: backends should be able to
handle, in their private functions, any object that they return from their
private *or* public functions. Claripy will never pass an object to any backend
private function that did not originate as a return value from a private or
public function of that backend. One exception to this is ``convert()`` and
``convert()``, as Claripy can try to stuff anything it feels like into
_convert() to see if the backend can handle that type of object.

Backend Objects
^^^^^^^^^^^^^^^

To perform actual, useful computation on ASTs, Claripy uses backend objects. A
``BackendObject`` is a result of the operation represented by the AST. Claripy
expects these objects to be returned from their respective backends, and will
pass such objects into that backend's other functions.
