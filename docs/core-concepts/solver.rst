Symbolic Expressions and Constraint Solving
===========================================

angr's power comes not from it being an emulator, but from being able to execute
with what we call *symbolic variables*. Instead of saying that a variable has a
*concrete* numerical value, we can say that it holds a *symbol*, effectively
just a name. Then, performing arithmetic operations with that variable will
yield a tree of operations (termed an *abstract syntax tree* or *AST*, from
compiler theory). ASTs can be translated into constraints for an *SMT solver*,
like z3, in order to ask questions like *"given the output of this sequence of
operations, what must the input have been?"* Here, you'll learn how to use angr
to answer this.

Working with Bitvectors
-----------------------

Let's get a dummy project and state so we can start playing with numbers.

.. code-block:: python

   >>> import angr, monkeyhex
   >>> proj = angr.Project('/bin/true')
   >>> state = proj.factory.entry_state()

A bitvector is just a sequence of bits, interpreted with the semantics of a
bounded integer for arithmetic. Let's make a few.

.. code-block:: python

   # 64-bit bitvectors with concrete values 1 and 100
   >>> one = state.solver.BVV(1, 64)
   >>> one
    <BV64 0x1>
   >>> one_hundred = state.solver.BVV(100, 64)
   >>> one_hundred
    <BV64 0x64>

   # create a 27-bit bitvector with concrete value 9
   >>> weird_nine = state.solver.BVV(9, 27)
   >>> weird_nine
   <BV27 0x9>

As you can see, you can have any sequence of bits and call them a bitvector. You
can do math with them too:

.. code-block:: python

   >>> one + one_hundred
   <BV64 0x65>

   # You can provide normal Python integers and they will be coerced to the
   appropriate type: >>> one_hundred + 0x100 <BV64 0x164>

   # The semantics of normal wrapping arithmetic apply
   >>> one_hundred - one*200
   <BV64 0xffffffffffffff9c>

You *cannot* say ``one + weird_nine``, though. It is a type error to perform an
operation on bitvectors of differing lengths. You can, however, extend
``weird_nine`` so it has an appropriate number of bits:

.. code-block:: python

   >>> weird_nine.zero_extend(64 - 27)
   <BV64 0x9>
   >>> one + weird_nine.zero_extend(64 - 27)
   <BV64 0xa>

``zero_extend`` will pad the bitvector on the left with the given number of zero
bits. You can also use ``sign_extend`` to pad with a duplicate of the highest
bit, preserving the value of the bitvector under two's compliment signed integer
semantics.

Now, let's introduce some symbols into the mix.

.. code-block:: python

   # Create a bitvector symbol named "x" of length 64 bits
   >>> x = state.solver.BVS("x", 64)
   >>> x
   <BV64 x_9_64>
   >>> y = state.solver.BVS("y", 64)
   >>> y
   <BV64 y_10_64>

``x`` and ``y`` are now *symbolic variables*, which are kind of like the variables you learned to work with in 7th grade algebra.
Notice that the name you provided has been been mangled by appending an incrementing counter and
You can do as much arithmetic as you want with them, but you won't get a number back, you'll get an AST instead.

.. code-block:: python

   >>> x + one
   <BV64 x_9_64 + 0x1>

   >>> (x + one) / 2
   <BV64 (x_9_64 + 0x1) / 0x2>

   >>> x - y
   <BV64 x_9_64 - y_10_64>

Technically ``x`` and ``y`` and even ``one`` are also ASTs - any bitvector is a
tree of operations, even if that tree is only one layer deep. To understand
this, let's learn how to process ASTs.

Each AST has a ``.op`` and a ``.args``. The op is a string naming the operation
being performed, and the args are the values the operation takes as input.
Unless the op is ``BVV`` or ``BVS`` (or a few others...), the args are all other
ASTs, the tree eventually terminating with BVVs or BVSs.

.. code-block:: python

   >>> tree = (x + 1) / (y + 2)
   >>> tree
   <BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
   >>> tree.op
   '__floordiv__'
   >>> tree.args
   (<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
   >>> tree.args[0].op
   '__add__'
   >>> tree.args[0].args
   (<BV64 x_9_64>, <BV64 0x1>)
   >>> tree.args[0].args[1].op
   'BVV'
   >>> tree.args[0].args[1].args
   (1, 64)

From here on out, we will use the word "bitvector" to refer to any AST whose
topmost operation produces a bitvector. There can be other data types
represented through ASTs, including floating point numbers and, as we're about
to see, booleans.

Symbolic Constraints
--------------------

Performing comparison operations between any two similarly-typed ASTs will yield
another AST - not a bitvector, but now a symbolic boolean.

.. code-block:: python

   >>> x == 1
   <Bool x_9_64 == 0x1>
   >>> x == one
   <Bool x_9_64 == 0x1>
   >>> x > 2
   <Bool x_9_64 > 0x2>
   >>> x + y == one_hundred + 5
   <Bool (x_9_64 + y_10_64) == 0x69>
   >>> one_hundred > 5
   <Bool True>
   >>> one_hundred > -5
   <Bool False>

One tidbit you can see from this is that the comparisons are unsigned by
default. The -5 in the last example is coerced to ``<BV64 0xfffffffffffffffb>``,
which is definitely not less than one hundred. If you want the comparison to be
signed, you can say ``one_hundred.SGT(-5)`` (that's "signed greater-than"). A
full list of operations can be found at the end of this chapter.

This snippet also illustrates an important point about working with angr - you
should never directly use a comparison between variables in the condition for an
if- or while-statement, since the answer might not have a concrete truth value.
Even if there is a concrete truth value, ``if one > one_hundred`` will raise an
exception. Instead, you should use ``solver.is_true`` and ``solver.is_false``,
which test for concrete truthyness/falsiness without performing a constraint
solve.

.. code-block:: python

   >>> yes = one == 1
   >>> no = one == 2
   >>> maybe = x == y
   >>> state.solver.is_true(yes)
   True
   >>> state.solver.is_false(yes)
   False
   >>> state.solver.is_true(no)
   False
   >>> state.solver.is_false(no)
   True
   >>> state.solver.is_true(maybe)
   False
   >>> state.solver.is_false(maybe)
   False

Constraint Solving
------------------

You can treat any symbolic boolean as an assertion about the valid values of a
symbolic variable by adding it as a *constraint* to the state. You can then
query for a valid value of a symbolic variable by asking for an evaluation of a
symbolic expression.

An example will probably be more clear than an explanation here:

.. code-block:: python

   >>> state.solver.add(x > y)
   >>> state.solver.add(y > 2)
   >>> state.solver.add(10 > x)
   >>> state.solver.eval(x)
   4

By adding these constraints to the state, we've forced the constraint solver to
consider them as assertions that must be satisfied about any values it returns.
If you run this code, you might get a different value for x, but that value will
definitely be greater than 3 (since y must be greater than 2 and x must be
greater than y) and less than 10. Furthermore, if you then say
``state.solver.eval(y)``, you'll get a value of y which is consistent with the
value of x that you got. If you don't add any constraints between two queries,
the results will be consistent with each other.

From here, it's easy to see how to do the task we proposed at the beginning of
the chapter - finding the input that produced a given output.

.. code-block:: python

   # get a fresh state without constraints
   >>> state = proj.factory.entry_state()
   >>> input = state.solver.BVS('input', 64)
   >>> operation = (((input + 4) * 3) >> 1) + input
   >>> output = 200
   >>> state.solver.add(operation == output)
   >>> state.solver.eval(input)
   0x3333333333333381

Note that, again, this solution only works because of the bitvector semantics.
If we were operating over the domain of integers, there would be no solutions!

If we add conflicting or contradictory constraints, such that there are no
values that can be assigned to the variables such that the constraints are
satisfied, the state becomes *unsatisfiable*, or unsat, and queries against it
will raise an exception. You can check the satisfiability of a state with
``state.satisfiable()``.

.. code-block:: python

   >>> state.solver.add(input < 2**32)
   >>> state.satisfiable()
   False

You can also evaluate more complex expressions, not just single variables.

.. code-block:: python

   # fresh state
   >>> state = proj.factory.entry_state()
   >>> state.solver.add(x - y >= 4)
   >>> state.solver.add(y > 0)
   >>> state.solver.eval(x)
   5
   >>> state.solver.eval(y)
   1
   >>> state.solver.eval(x + y)
   6

From this we can see that ``eval`` is a general purpose method to convert any
bitvector into a Python primitive while respecting the integrity of the state.
This is why we use ``eval`` to convert from concrete bitvectors to Python ints,
too!

Also note that the x and y variables can be used in this new state despite
having been created using an old state. Variables are not tied to any one state,
and can exist freely.

Floating point numbers
----------------------

z3 has support for the theory of IEEE754 floating point numbers, and so angr can
use them as well. The main difference is that instead of a width, a floating
point number has a *sort*. You can create floating point symbols and values with
``FPV`` and ``FPS``.

.. code-block:: python

   # fresh state
   >>> state = proj.factory.entry_state()
   >>> a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)
   >>> a
   <FP64 FPV(3.2, DOUBLE)>

   >>> b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)
   >>> b
   <FP64 FPS('FP_b_0_64', DOUBLE)>

   >>> a + b
   <FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>

   >>> a + 4.4
   <FP64 FPV(7.6000000000000005, DOUBLE)>

   >>> b + 2 < 0
   <Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>

So there's a bit to unpack here - for starters the pretty-printing isn't as
smart about floating point numbers. But past that, most operations actually have
a third parameter, implicitly added when you use the binary operators - the
rounding mode. The IEEE754 spec supports multiple rounding modes
(round-to-nearest, round-to-zero, round-to-positive, etc), so z3 has to support
them. If you want to specify the rounding mode for an operation, use the fp
operation explicitly (``solver.fpAdd`` for example) with a rounding mode (one of
``solver.fp.RM_*``) as the first argument.

Constraints and solving work in the same way, but with ``eval`` returning a floating point number:

.. code-block:: python

   >>> state.solver.add(b + 2 < 0)
   >>> state.solver.add(b + 2 > -1)
   >>> state.solver.eval(b)
   -2.4999999999999996

This is nice, but sometimes we need to be able to work directly with the
representation of the float as a bitvector. You can interpret bitvectors as
floats and vice versa, with the methods ``raw_to_bv`` and ``raw_to_fp``:

.. code-block:: python

   >>> a.raw_to_bv()
   <BV64 0x400999999999999a>
   >>> b.raw_to_bv()
   <BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>

   >>> state.solver.BVV(0, 64).raw_to_fp()
   <FP64 FPV(0.0, DOUBLE)>
   >>> state.solver.BVS('x', 64).raw_to_fp()
   <FP64 fpToFP(x_1_64, DOUBLE)>

These conversions preserve the bit-pattern, as if you casted a float pointer to
an int pointer or vice versa. However, if you want to preserve the value as
closely as possible, as if you casted a float to an int (or vice versa), you can
use a different set of methods, ``val_to_fp`` and ``val_to_bv``. These methods
must take the size or sort of the target value as a parameter, due to the
floating-point nature of floats.

.. code-block:: python

   >>> a
   <FP64 FPV(3.2, DOUBLE)>
   >>> a.val_to_bv(12)
   <BV12 0x3>
   >>> a.val_to_bv(12).val_to_fp(state.solver.fp.FSORT_FLOAT)
   <FP32 FPV(3.0, FLOAT)>

These methods can also take a ``signed`` parameter, designating the signedness of the source or target bitvector.

More Solving Methods
--------------------

``eval`` will give you one possible solution to an expression, but what if you want several?
What if you want to ensure that the solution is unique?
The solver provides you with several methods for common solving patterns:


* ``solver.eval(expression)`` will give you one possible solution to the given
  expression.
* ``solver.eval_one(expression)`` will give you the solution to the given
  expression, or throw an error if more than one solution is possible.
* ``solver.eval_upto(expression, n)`` will give you up to n solutions to the
  given expression, returning fewer than n if fewer than n are possible.
* ``solver.eval_atleast(expression, n)`` will give you n solutions to the given
  expression, throwing an error if fewer than n are possible.
* ``solver.eval_exact(expression, n)`` will give you n solutions to the given
  expression, throwing an error if fewer or more than are possible.
* ``solver.min(expression)`` will give you the minimum possible solution to the
  given expression.
* ``solver.max(expression)`` will give you the maximum possible solution to the
  given expression.

Additionally, all of these methods can take the following keyword arguments:


* ``extra_constraints`` can be passed as a tuple of constraints. These
  constraints will be taken into account for this evaluation, but will not be
  added to the state.
* ``cast_to`` can be passed a data type to cast the result to. Currently, this
  can only be ``int`` and ``bytes``, which will cause the method to return the
  corresponding representation of the underlying data. For example,
  ``state.solver.eval(state.solver.BVV(0x41424344, 32), cast_to=bytes)`` will
  return ``b'ABCD'``.

Summary
-------

That was a lot!! After reading this, you should be able to create and manipulate
bitvectors, booleans, and floating point values to form trees of operations, and
then query the constraint solver attached to a state for possible solutions
under a set of constraints. Hopefully by this point you understand the power of
using ASTs to represent computations, and the power of a constraint solver.

`In the appendix <List of Claripy Operations>`_, you can find a reference for
all the additional operations you can apply to ASTs, in case you ever need a
quick table to look at.
