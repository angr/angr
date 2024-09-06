What's Up With Mixins, Anyway?
==============================

If you are trying to work more intently with the deeper parts of angr, you will
need to understand one of the design patterns we use frequently: the mixin
pattern.

In brief, the mixin pattern is where Python's subclassing features is used not
to implement IS-A relationships (a Child is a kind of Person) but instead to
implement pieces of functionality for a type in different classes to make more
modular and maintainable code. Here's an example of the mixin pattern in action:

.. code-block:: python

   class Base:
       def add_one(self, v):
           return v + 1

   class StringsMixin(Base):
       def add_one(self, v):
           coerce = type(v) is str
           if coerce:
               v = int(v)
           result = super().add_one(v)
           if coerce:
               result = str(result)
           return result

   class ArraysMixin(Base):
       def add_one(self, v):
           if type(v) is list:
               return [super().add_one(v_x) for v_x in v]
           else:
               return super().add_one(v)

   class FinalClass(ArraysMixin, StringsMixin, Base):
       pass

With this construction, we are able to define a very simple interface in the
``Base`` class, and by "mixing in" two mixins, we can create the ``FinalClass``
which has the same interface but with additional features. This is accomplished
through Python's powerful multiple inheritance model, which handles method
dispatch by creating a *method resolution order*, or MRO, which is unsurprisingly
a list which determines the order in which methods are called as execution
proceeds through ``super()`` calls. You can view a class' MRO as such:

.. code-block:: python

   FinalClass.__mro__

   (FinalClass, ArraysMixin, StringsMixin, Base, object)

This means that when we take an instance of ``FinalClass`` and call
``add_one()``, Python first checks to see if ``FinalClass`` defines an
``add_one``, and then ``ArraysMixin``, and so on and so forth. Furthermore, when
``ArraysMixin`` calls ``super().add_one()``, Python will skip past
``ArraysMixin`` in the MRO, first checking if ``StringsMixin`` defines an
``add_one``, and so forth.

Because multiple inheritance can create strange dependency graphs in the
subclass relationship, there are rules for generating the MRO and for
determining if a given mix of mixins is even allowed. This is important to
understand when building complex classes with many mixins which have
dependencies on each other. In short: left-to-right, depth-first, but deferring
any base classes which are shared by multiple subclasses (the merge point of a
diamond pattern in the inheritance graph) until the last point where they would
be encountered in this depth-first search. For example, if you have classes A,
B(A), C(B), D(A), E(C, D), then the method resolution order will be E, C, B, D,
A. If there is any case in which the MRO would be ambiguous, the class
construction is illegal and will throw an exception at import time.

This is complicated! If you find yourself confused, the canonical document
explaining the rationale, history, and mechanics of Python's multiple
inheritance can be found `here
<https://www.python.org/download/releases/2.3/mro/>`_.

Mixins in Claripy Solvers
-------------------------

.. todo:: Write this section

Mixins in angr Engines
----------------------

The main entry point to a SimEngine is ``process()``, but how do we determine
what that does?

The mixin model is used in SimEngine and friends in order to allow pieces of
functionality to be reused between static and symbolic analyses. The default
engine, ``UberEngine``, is defined as follows:

.. code-block:: python

   class UberEngine(SimEngineFailure,
      SimEngineSyscall,
      HooksMixin,
      SimEngineUnicorn,
      SuperFastpathMixin,
      TrackActionsMixin,
      SimInspectMixin,
      HeavyResilienceMixin,
      SootMixin,
      HeavyVEXMixin
   ):
       pass

Each of these mixins provides either execution through a different medium or
some additional instrumentation feature. Though they are not listed here
explicitly, there are some base classes implicit to this hierarchy which set up
the way this class is traversed. Most of these mixins inherit from
``SuccessorsMixin``, which is what provides the basic ``process()``
implementation. This function sets up the ``SimSuccessors`` for the rest of the
mixins to fill in, and then calls ``process_successors()``, which each of the
mixins which provide some mode of execution implement. If the mixin can handle
the step, it does so and returns, otherwise it calls
``super().process_successors()``. In this way, the MRO for the engine class
determines what the order of precedence for the engine's pieces is.

HeavyVEXMixin and friends
^^^^^^^^^^^^^^^^^^^^^^^^^

Let's take a closer look at the last mixin, ``HeavyVEXMixin``. If you look at
the module hierarchy of the angr ``engines`` submodule, you will see that the
``vex`` submodule has a lot of pieces in it which are organized by how tightly
tied to particular state types or data types they are. The heavy VEX mixin is
one version of the culmination of all of these. Let's look at its definition:

.. code-block:: python

   class HeavyVEXMixin(SuccessorsMixin, ClaripyDataMixin, SimStateStorageMixin, VEXMixin, VEXLifter):
       ...
       # a WHOLE lot of implementation

So, the heavy VEX mixin is meant to provide fully instrumented symbolic
execution on a SimState. What does this entail? The mixins tell the tale.

First, the plain ``VEXMixin``. This mixin is designed to provide the
barest-bones framework for processing a VEX block. Take a look at its `source
code
<https://github.com/angr/angr/blob/master/angr/engines/vex/light/light.py>`_.
Its main purpose is to perform the preliminary digestion of the VEX IRSB and
dispatch processing of it to methods which are provided by mixins - look at the
methods which are either ``pass`` or ``return NotImplemented``. Notice that
absolutely none of its code makes any assumption whatsoever of what the type of
``state`` is or even what the type of the data words inside ``state`` are. This
job is delegated to other mixins, making the ``VEXMixin`` an appropriate base
class for literally any analysis on VEX blocks.

The next-most interesting mixin is the ``ClaripyDataMixin``, whose source code
is `here
<https://github.com/angr/angr/blob/master/angr/engines/vex/claripy/datalayer.py>`_.
This mixin actually integrates the fact that we are executing over the domain of
Claripy ASTs. It does this by implementing some of the methods which are
unimplemented in the ``VEXMixin``, most importantly the ``ITE`` expression, all
the operations, and the clean helpers.

In terms of what it looks like to actually touch the SimState, the
``SimStateStorageMixin`` provides the glue between the ``VEXMixin``'s interface
for memory writes et al and SimState's interface for memory writes and such. It
is unremarkable, except for a small interaction between it and the
``ClaripyDataMixin``. The Claripy mixin also overrides the memory/register
read/write functions, for the purpose of converting between the bitvector and
floating-point types, since the vex interface expects to be able to load and
store floats, but the SimState interface wants to load and store only
bitvectors. Because of this, *the claripy mixin must come before the storage
mixin in the MRO*. This is very much an interaction like the one in the add_one
example at the start of this page - one mixin serves as a data filtering layer
for another mixin.

Instrumenting the data layer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Let's turn our attention to a mixin which is not included in the
``HeavyVEXMixin`` but rather mixed into the ``UberEngine`` formula explicitly:
the ``TrackActionsMixin``. This mixin implements "SimActions", which is angr
parlance for dataflow tracking. Again, look at the `source code
<https://github.com/angr/angr/blob/master/angr/engines/vex/heavy/actions.py>`_.
The way it does this is that it *wraps and unwraps the data layer* to pass
around additional information about data flows. Look at how it instruments
``RdTmp``, for instance. It immediately ``super()``-calls to the next method in
the MRO, but instead of returning that data it returns a tuple of the data and
its dependencies, which depending on whether you want temporary variables to be
atoms in the dataflow model, will either be just the tmp which was read or the
dependencies of the value written to that tmp.

This pattern continues for every single method that this mixin touches - any
expression it receives must be unpacked into the expression and its
dependencies, and any result must be packaged with its dependencies before it is
returned. This works because the mixin above it makes no assumptions about what
data it is passing around, and the mixin below it never gets to see any
dependencies whatsoever. In fact, there could be multiple mixins performing this
kind of wrap-unwrap trick and they could all coexist peacefully!

Note that a mixin which instruments the data layer in this way is *obligated* to
override *every single method which takes or returns an expression value*, even
if it doesn't perform any operation on the expression other than doing the
wrapping and unwrapping. To understand why, imagine that the mixin does not
override the ``handle_vex_const`` expression, so immediate value loads are not
annotated with dependencies. The expression value which will be returned from
the mixin which does provide ``handle_vex_const`` will not be a tuple of
(expression, deps), it will just be the expression. Imagine this execution is
taking place in the context of a ``WrTmp(t0, Const(0))``. The const expression
will be passed down to the ``WrTmp`` handler along with the identifier of the
tmp to write to. However, since ``handle_vex_stmt_WrTmp`` *will* be overridden
by our mixin which touches the data layer, it expects to be passed the tuple
including the deps, and so it will crash when trying to unpack the not-a-tuple
value.

In this way, you can sort of imagine that a mixin which instruments the data
layer in this way is actually creating a contract within Python's nonexistent
typesystem - you are guaranteed to receive back any types you return, but you
must pass down any types you receive as return values from below.

Mixins in the memory model
--------------------------

.. todo:: write this section
