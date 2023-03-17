Optimization considerations
===========================

The performance of angr as an analysis tool or emulator is greatly handicapped
by the fact that lots of it is written in Python. Regardless, there are a lot of
optimizations and tweaks you can use to make angr faster and lighter.

General speed tips
------------------


* *Use pypy*. `Pypy <http://pypy.org/>`_ is an alternate Python interpreter that
  performs optimized jitting of Python code. In our tests, it's a 10x speedup
  out of the box.
* *Only use the SimEngine mixins that you need*. SimEngine uses a mixin model
  which allows you to add and remove features by constructing new classes. The
  default engine mixes in every possible features, and the consequence of that
  is that it is slower than it needs to be. Look at the definition for
  ``UberEngine`` (the default SimEngine), copy its declaration, and remove all
  the base classes which provide features you don't need.
* *Don't load shared libraries unless you need them*. The default setting in
  angr is to try at all costs to find shared libraries that are compatible with
  the binary you've loaded, including loading them straight out of your OS
  libraries. This can complicate things in a lot of scenarios. If you're
  performing an analysis that's anything more abstract than bare-bones symbolic
  execution, ESPECIALLY control-flow graph construction, you might want to make
  the tradeoff of sacrificing accuracy for tractability. angr does a reasonable
  job of making sane things happen when library calls to functions that don't
  exist try to happen.
* *Use hooking and SimProcedures*. If you're enabling shared libraries, then you
  definitely want to have SimProcedures written for any complicated library
  function you're jumping into. If there's no autonomy requirement for this
  project, you can often isolate individual problem spots where analysis hangs
  up and summarize them with a hook.
* *Use SimInspect*. :ref:`SimInspect <Breakpoints>` is the most underused and
  one of the most powerful features of angr. You can hook and modify almost any
  behavior of angr, including memory index resolution (which is often the
  slowest part of any angr analysis).
* *Write a concretization strategy*. A more powerful solution to the problem of
  memory index resolution is a `concretization strategy
  <https://github.com/angr/angr/tree/master/angr/concretization_strategies>`_.
* *Use the Replacement Solver*. You can enable it with the
  ``angr.options.REPLACEMENT_SOLVER`` state option. The replacement solver
  allows you to specify AST replacements that are applied at solve-time. If you
  add replacements so that all symbolic data is replaced with concrete data when
  it comes time to do the solve, the runtime is greatly reduced. The API for
  adding a replacement is ``state.se._solver.add_replacement(old, new)``. The
  replacement solver is a bit finicky, so there are some gotchas, but it'll
  definitely help.

If you're performing lots of concrete or partially-concrete execution
---------------------------------------------------------------------

* *Use the unicorn engine*. If you have `unicorn engine
  <https://github.com/unicorn-engine/unicorn/>`_ installed, angr can be built to
  take advantage of it for concrete emulation. To enable it, add the options in
  the set ``angr.options.unicorn`` to your state. Keep in mind that while most
  items under ``angr.options`` are individual options, ``angr.options.unicorn``
  is a bundle of options, and is thus a set. *NOTE*: At time of writing the
  official version of unicorn engine will not work with angr - we have a lot of
  patches to it to make it work well with angr. They're all pending pull
  requests at this time, so sit tight. If you're really impatient, ping us about
  uploading our fork!
* *Enable fast memory and fast registers*. The state options
  ``angr.options.FAST_MEMORY`` and ``angr.options.FAST_REGISTERS`` will do this.
  These will switch the memory/registers over to a less intensive memory model
  that sacrifices accuracy for speed. TODO: document the specific sacrifices.
  Should be safe for mostly concrete access though. NOTE: not compatible with
  concretization strategies.
* *Concretize your input ahead of time*. This is the approach taken by `driller
  <https://www.internetsociety.org/sites/default/files/blogs-media/driller-augmenting-fuzzing-through-selective-symbolic-execution.pdf>`_.
  When creating a state with ``entry_state`` or the like, you can create a
  SimFile filled with symbolic data, pass it to the initialization function as
  an argument ``entry_state(..., stdin=my_simfile)``, and then constrain the
  symbolic data in the SimFile to what you want the input to be. If you don't
  require any tracking of the data coming from stdin, you can forego the
  symbolic part and just fill it with concrete data. If there are other sources
  of input besides standard input, do the same for those.
* *Use the afterburner*. While using unicorn, if you add the
  ``UNICORN_THRESHOLD_CONCRETIZATION`` state option, angr will accept thresholds
  after which it causes symbolic values to be concretized so that execution can
  spend more time in Unicorn. Specifically, the following thresholds exist:


  * ``state.unicorn.concretization_threshold_memory`` - this is the number of
    times a symbolic variable, stored in memory, is allowed to kick execution
    out of Unicorn before it is forcefully concretized and forced into Unicorn
    anyways.
  * ``state.unicorn.concretization_threshold_registers`` - this is the number of
    times a symbolic variable, stored in a register, is allowed to kick
    execution out of Unicorn before it is forcefully concretized and forced into
    Unicorn anyways.
  * ``state.unicorn.concretization_threshold_instruction`` - this is the number
    of times that any given instruction can force execution out of Unicorn (by
    running into symbolic data) before any symbolic data encountered at that
    instruction is concretized to force execution into Unicorn.

  You can get further control of what is and isn't concretized with the
  following sets:


  * ``state.unicorn.always_concretize`` - a set of variable names that will
    always be concretized to force execution into unicorn (in fact, the memory
    and register thresholds just end up causing variables to be added to this
    list).
  * ``state.unicorn.never_concretize`` - a set of variable names that will never
    be concretized and forced into Unicorn under any condition.
  * ``state.unicorn.concretize_at`` - a set of instruction addresses at which
    data should be concretized and forced into Unicorn. The instruction
    threshold causes addresses to be added to this set.

  Once something is concretized with the afterburner, you will lose track of
  that variable. The state will still be consistent, but you'll lose
  dependencies, as the stuff that comes out of Unicorn is just concrete bits
  with no memory of what variables they came from. Still, this might be worth it
  for the speed in some cases, if you know what you want to (or do not want to)
  concretize.

Memory optimization
-------------------

The golden rule for memory optimization is to make sure you're not keeping any
references to data you don't care about anymore, especially related to states
which have been left behind. If you find yourself running out of memory during
analysis, the first thing you want to do is make sure you haven't caused a state
explosion, meaning that the analysis is accumulating program states too quickly.
If the state count is in control, then you can start looking for reference
leaks. A good tool to do this with is https://github.com/rhelmot/dumpsterdiver,
which gives you an interactive prompt for exploring the reference graph of a
Python process.

One specific consideration that should be made when analyzing programs with very
long paths is that the state history is designed to accumulate data infinitely.
This is less of a problem than it could be because the data is stored in a smart
tree structure and never copied, but it will accumulate infinitely. To downsize
a state's history and free all data related to old steps, call
``state.history.trim()``.

One *particularly* problematic member of the history dataset is the basic block
trace and the stack pointer trace. When using unicorn engine, these lists of
ints can become huge very very quickly. To disable unicorn's capture of ip and
sp data, remove the state options ``UNICORN_TRACK_BBL_ADDRS`` and
``UNICORN_TRACK_STACK_POINTERS``.
