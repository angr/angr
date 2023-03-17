Frequently Asked Questions
==========================

This is a collection of commonly-asked "how do I do X?" questions and other
general questions about angr, for those too lazy to read this whole document.

If your question is of the form "how do I fix X issue after installing", see
also the Troubleshooting section of the :ref:`install instructions <Installing
angr>`_.

Why is it named angr?
---------------------

The core of angr's analysis is on VEX IR, and when something is vexing, it makes
you angry.

How should "angr" be stylized?
------------------------------

All lowercase, even at the beginning of sentences. It's an anti-proper noun.

Why isn't symbolic execution doing the thing I want?
----------------------------------------------------

The universal debugging technique for symbolic execution is as follows:


* Check your simulation manager for errored states. ``print(simgr)`` is a good
  place to start, and if you see anything to do with "errored", go for
  ``print(simgr.errored)``.
* If you have any errored states and it's not immediately obvious what you did
  wrong, you can get a `pdb <https://docs.python.org/3/library/pdb.html>`_ shell
  at the crash site by going ``simgr.errored[n].debug()``.
* If no state has reached an address you care about, you should check the path
  each state has gone down: ``import pprint;
  pprint.pprint(state.history.descriptions.hardcopy)``. This will show you a
  high-level summary of what the symbolic execution engine did at each step
  along the state's history. You will be able to see from this a basic block
  trace and also a list of executed simprocedures. If you're using unicorn
  engine, you can check ``state.history.bbl_addrs.hardcopy`` to see what blocks
  were executed in each invocation of unicorn.
* If a state is going down the wrong path, you can check what constraints caused
  it to go that way: ``print(state.solver.constraints)``. If a state has just
  gone past a branch, you can check the most recent branch condition with
  ``state.history.events[-1]``.

How can I get diagnostic information about what angr is doing?
--------------------------------------------------------------

angr uses the standard ``logging`` module for logging, with every package and
submodule creating a new logger.

The simplest way to get debug output is the following:

.. code-block:: python

   import logging
   logging.getLogger('angr').setLevel('DEBUG')

You may want to use ``INFO`` or whatever else instead. By default, angr will
enable logging at the ``WARNING`` level.

Each angr module has its own logger string, usually all the Python modules above
it in the hierarchy, plus itself, joined with dots. For example,
``angr.analyses.cfg``. Because of the way the Python logging module works, you
can set the verbosity for all submodules in a module by setting a verbosity
level for the parent module. For example,
``logging.getLogger('angr.analyses').setLevel('INFO')`` will make the CFG, as
well as all other analyses, log at the INFO level.

Why is angr so slow?
--------------------

It's complicated! :ref:`Optimization considerations`

How do I find bugs using angr?
------------------------------

It's complicated! The easiest way to do this is to define a "bug condition", for
example, "the instruction pointer has become a symbolic variable", and run
symbolic exploration until you find a state matching that condition, then dump
the input as a testcase. However, you will quickly run into the state explosion
problem. How you address this is up to you. Your solution may be as simple as
adding an ``avoid`` condition or as complicated as implementing CMU's MAYHEM
system as an Exploration Technique.

Why did you choose VEX instead of another IR (such as LLVM, REIL, BAP, etc)?
----------------------------------------------------------------------------

We had two design goals in angr that influenced this choice:


#. angr needed to be able to analyze binaries from multiple architectures. This
   mandated the use of an IR to preserve our sanity, and required the IR to
   support many architectures.
#. We wanted to implement a binary analysis engine, not a binary lifter. Many
   projects start and end with the implementation of a lifter, which is a time
   consuming process. We needed to take something that existed and already
   supported the lifting of multiple architectures.

Searching around the internet, the major choices were:


* LLVM is an obvious first candidate, but lifting binary code to LLVM cleanly is
  a pain. The two solutions are either lifting to LLVM through QEMU, which is
  hackish (and the only implementation of it seems very tightly integrated into
  S2E), or McSema, which only supported x86 at the time but has since gone
  through a rewrite and gotten support for x86-64 and aarch64.
* TCG is QEMU's IR, but extracting it seems very daunting as well and
  documentation is very scarce.
* REIL seems promising, but there is no standard reference implementation that
  supports all the architectures that we wanted. It seems like a nice academic
  work, but to use it, we would have to implement our own lifters, which we
  wanted to avoid.
* BAP was another possibility. When we started work on angr, BAP only supported
  lifting x86 code, and up-to-date versions of BAP were only available to
  academic collaborators of the BAP authors. These were two deal-breakers. BAP
  has since become open, but it still only supports x86_64, x86, and ARM.
* VEX was the only choice that offered an open library and support for many
  architectures. As a bonus, it is very well documented and designed
  specifically for program analysis, making it very easy to use in angr.

While angr uses VEX now, there's no fundamental reason that multiple IRs cannot
be used. There are two parts of angr, outside of the ``angr.engines.vex``
package, that are VEX-specific:


* the jump labels (i.e., the ``Ijk_Ret`` for returns, ``Ijk_Call`` for calls,
  and so forth) are VEX enums.
* VEX treats registers as a memory space, and so does angr. While we provide
  accesses to ``state.regs.rax`` and friends, on the backend, this does
  ``state.registers.load(8, 8)``, where the first ``8`` is a VEX-defined offset
  for ``rax`` to the register file.

To support multiple IRs, we'll either want to abstract these things or translate
their labels to VEX analogues.

Why are some ARM addresses off-by-one?
--------------------------------------

In order to encode THUMB-ness of an ARM code address, we set the lowest bit to
one. This convention comes from LibVEX, and is not entirely our choice! If you
see an odd ARM address, that just means the code at ``address - 1`` is in THUMB
mode.

How do I serialize angr objects?
--------------------------------

`Pickle <https://docs.python.org/2/library/pickle.html>`_ will work. However,
Python will default to using an extremely old pickle protocol that does not
support more complex Python data structures, so you must specify a `more
advanced data stream format
<https://docs.python.org/2/library/pickle.html#data-stream-format>`_. The
easiest way to do this is ``pickle.dumps(obj, -1)``.

What does ``UnsupportedIROpError("floating point support disabled")`` mean?
-------------------------------------------------------------------------------

This might crop up if you're using a CGC analysis such as driller or rex.
Floating point support in angr has been disabled in the CGC analyses for a
tight-knit nebula of reasons:


* Libvex's representation of floating point numbers is imprecise - it converts
  the 80-bit extended precision format used by the x87 for computation to 64-bit
  doubles, making it impossible to get precise results
* There is very limited implementation support in angr for the actual primitive
  operations themselves as reported by libvex, so you will often get a less
  friendly "unsupported operation" error if you go too much further
* For what operations are implemented, the basic optimizations that allow
  tractability during symbolic computation (AST deduplication, operation
  collapsing) are not implemented for floating point ops, leading to gigantic
  ASTs
* There are memory corruption bugs in z3 that get triggered frighteningly easily
  when you're using huge workloads of mixed floating point and bitvector ops. We
  haven't been able to get a testcase that doesn't involve "just run angr" for
  the z3 guys to investigate.

Instead of trying to cope with all of these, we have simply disabled floating
point support in the symbolic execution engine. To allow for execution in the
presence of floating point ops, we have enabled an exploration technique called
the
`https://github.com/angr/angr/blob/master/angr/exploration_techniques/oppologist.py
<oppologist>` that is supposed to catch these issues, concretize their inputs,
and run the problematic instructions through qemu via unicorn engine, allowing
execution to continue. The intuition is that the specific values of floating
point operations don't typically affect the exploitation process.

If you're seeing this error and it's terminating the analysis, it's probably
because you don't have unicorn installed or configured correctly. If you're
seeing this issue just in a log somewhere, it's just the oppologist kicking in
and you have nothing to worry about.

Why is angr's CFG different from IDA's?
---------------------------------------

Two main reasons:


* IDA does not split basic blocks at function calls. angr will, because they are
  a form of control flow and basic blocks end at control flow instructions. You
  generally do not need the supergraph for performing automated analyses.
* IDA will split basic blocks if another block jumps into the middle of it. This
  is called basic block normalization, and angr does not do it by default since
  it is unnecessary for most static analyses. You may enable it by passing
  ``normalize=True`` to the CFG analysis.

Why do I get incorrect register values when reading from a state during a SimInspect breakpoint?
------------------------------------------------------------------------------------------------

libVEX will eliminate duplicate register writes within a single basic block when
optimizations are enabled. Turn off IR optimization to make everything look
right at all times.

In the case of the instruction pointer, libVEX will frequently omit mid-block
writes even when optimizations are disabled. In this case, you should use
``state.scratch.ins_addr`` to get the current instruction pointer.
