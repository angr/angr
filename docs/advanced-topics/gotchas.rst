Gotchas when using angr
=======================

This section contains a list of gotchas that users/victims of angr frequently
run into.

SimProcedure inaccuracy
-----------------------

To make symbolic execution more tractable, angr replaces common library
functions with summaries written in Python. We call these summaries
SimProcedures. SimProcedures allow us to mitigate path explosion that would
otherwise be introduced by, for example, ``strlen`` running on a symbolic
string.

Unfortunately, our SimProcedures are far from perfect. If angr is displaying
unexpected behavior, it might be caused by a buggy/incomplete SimProcedure.
There are several things that you can do:


#. Disable the SimProcedure (you can exclude specific SimProcedures by passing
   options to the :py:class:`angr.Project` class. This has the drawback of
   likely leading to a path explosion, unless you are very careful about
   constraining the input to the function in question. The path explosion can be
   partially mitigated with other angr capabilities (such as Veritesting).
#. Replace the SimProcedure with something written directly to the situation in
   question. For example, our ``scanf`` implementation is not complete, but if
   you just need to support a single, known format string, you can write a hook
   to do exactly that.
#. Fix the SimProcedure.

Unsupported syscalls
--------------------

System calls are also implemented as SimProcedures. Unfortunately, there are
system calls that we have not yet implemented in angr. There are several
workarounds for an unsupported system call:


#. Implement the system call.

   .. todo:: document this process
#. Hook the callsite of the system call (using ``project.hook``) to make the
   required modifications to the state in an ad-hoc way.
#. Use the ``state.posix.queued_syscall_returns`` list to queue syscall return
   values. If a return value is queued, the system call will not be executed,
   and the value will be used instead. Furthermore, a function can be queued
   instead as the "return value", which will result in that function being
   applied to the state when the system call is triggered.

Symbolic memory model
---------------------

The default memory model used by angr is inspired by `Mayhem
<https://users.ece.cmu.edu/~dbrumley/pdf/Cha%20et%20al._2012_Unleashing%20Mayhem%20on%20Binary%20Code.pdf>`_.
This memory model supports limited symbolic reads and writes. If the memory
index of a read is symbolic and the range of possible values of this index is
too wide, the index is concretized to a single value. If the memory index of a
write is symbolic at all, the index is concretized to a single value. This is
configurable by changing the memory concretization strategies of
``state.memory``.

Symbolic lengths
----------------

SimProcedures, and especially system calls such as ``read()`` and ``write()``
might run into a situation where the *length* of a buffer is symbolic. In
general, this is handled very poorly: in many cases, this length will end up
being concretized outright or retroactively concretized in later steps of
execution. Even in cases when it is not, the source or destination file might
end up looking a bit "weird".

Division by Zero
----------------

Z3 has some issues with divisions by zero. For example:

.. code-block::

   >>> z = z3.Solver()
   >>> a = z3.BitVec('a', 32)
   >>> b = z3.BitVec('b', 32)
   >>> c = z3.BitVec('c', 32)
   >>> z.add(a/b == c)
   >>> z.add(b == 0)
   >>> z.check()
   >>> print(z.model().eval(b), z.model().eval(a/b))
   0 4294967295

This makes it very difficult to handle certain situations in Claripy. We
post-process the VEX IR itself to explicitly check for zero-divisions and create
IRSB side-exits corresponding to the exceptional case, but SimProcedures and
custom analysis code may let occurrences of zero divisions split through, which
will then cause weird issues in your analysis. Be safe --- when dividing, add a
constraint against the denominator being zero.
