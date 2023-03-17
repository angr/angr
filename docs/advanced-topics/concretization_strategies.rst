Symbolic memory addressing
==========================

angr supports *symbolic memory addressing*, meaning that offsets into memory may
be symbolic. Our implementation of this is inspired by "Mayhem". Specifically,
this means that angr concretizes symbolic addresses when they are used as the
target of a write. This causes some surprises, as users tend to expect symbolic
writes to be treated purely symbolically, or "as symbolically" as we treat
symbolic reads, but that is not the default behavior. However, like most things
in angr, this is configurable.

The address resolution behavior is governed by *concretization strategies*,
which are subclasses of
``angr.concretization_strategies.SimConcretizationStrategy``. Concretization
strategies for reads are set in ``state.memory.read_strategies`` and for writes
in ``state.memory.write_strategies``. These strategies are called, in order,
until one of them is able to resolve addresses for the symbolic index. By
setting your own concretization strategies (or through the use of SimInspect
``address_concretization`` breakpoints, described above), you can change the way
angr resolves symbolic addresses.

For example, angr's default concretization strategies for writes are:


#. A conditional concretization strategy that allows symbolic writes (with a
   maximum range of 128 possible solutions) for any indices that are annotated
   with ``angr.plugins.symbolic_memory.MultiwriteAnnotation``.
#. A concretization strategy that simply selects the maximum possible solution
   of the symbolic index.

To enable symbolic writes for all indices, you can either add the
``SYMBOLIC_WRITE_ADDRESSES`` state option at state creation time or manually
insert a ``angr.concretization_strategies.SimConcretizationStrategyRange``
object into ``state.memory.write_strategies``. The strategy object takes a
single argument, which is the maximum range of possible solutions that it allows
before giving up and moving on to the next (presumably non-symbolic) strategy.

Writing concretization strategies
---------------------------------

.. todo:: Write this section
