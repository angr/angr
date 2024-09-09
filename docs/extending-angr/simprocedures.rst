Hooks and SimProcedures
=======================

Hooks in angr are very powerful! You can use them to modify a program's behavior
in any way you could imagine. However, the exact way you might want to program a
specific hook may be non-obvious. This chapter should serve as a guide when
programming SimProcedures.

Quick Start
-----------

Here's an example that will remove all bugs from any program:

.. code-block:: python

   >>> from angr import Project, SimProcedure
   >>> project = Project('examples/fauxware/fauxware')

   >>> class BugFree(SimProcedure):
   ...    def run(self, argc, argv):
   ...        print('Program running with argc=%s and argv=%s' % (argc, argv))
   ...        return 0

   # this assumes we have symbols for the binary
   >>> project.hook_symbol('main', BugFree())

   # Run a quick execution!
   >>> simgr = project.factory.simulation_manager()
   >>> simgr.run()  # step until no more active states
   Program running with argc=<SAO <BV64 0x0>> and argv=<SAO <BV64 0x7fffffffffeffa0>>
   <SimulationManager with 1 deadended>

Now, whenever program execution reaches the main function, instead of executing
the actual main function, it will execute this procedure! It just prints out a
message, and returns.

Now, let's talk about what happens on the edge of this function! When entering
the function, where do the values that go into the arguments come from? You can
define your ``run()`` function with however many arguments you like, and the
SimProcedure runtime will automatically extract from the program state those
arguments for you, via a :ref:`calling convention <Working with Calling
Conventions>`, and call your run function with them. Similarly, when you return
a value from the run function, it is placed into the state (again, according to
the calling convention), and the actual control-flow action of returning from a
function is performed, which depending on the architecture may involve jumping
to the link register or jumping to the result of a stack pop.

It should be clear at this point that the SimProcedure we just wrote is meant to
totally replace whatever function it is hooked over top of. In fact, the
original use case for SimProcedures was replacing library functions. More on
that later.

Implementation Context
----------------------

On a ``Project`` class, the dict ``project._sim_procedures`` is a mapping from
address to ``SimProcedure`` instances. When the :ref:`execution pipeline
<Understanding the Execution Pipeline>` reaches an address that is present in
that dict, that is, an address that is hooked, it will execute
``project._sim_procedures[address].execute(state)``. This will consult the
calling convention to extract the arguments, make a copy of itself in order to
preserve thread safety, and run the ``run()`` method. It is important to produce
a new instance of the SimProcedure for each time it is run, since the process of
running a SimProcedure necessarily involves mutating state on the SimProcedure
instance, so we need separate ones for each step, lest we run into race
conditions in multithreaded environments.

kwargs
^^^^^^

This hierarchy implies that you might want to reuse a single SimProcedure in
multiple hooks. What if you want to hook the same SimProcedure in several
places, but tweaked slightly each time? angr's support for this is that any
additional keyword arguments you pass to the constructor of your SimProcedure
will end up getting passed as keyword args to your SimProcedure's ``run()``
method. Pretty cool!

Data Types
----------

If you were paying attention to the example earlier, you noticed that when we
printed out the arguments to the ``run()`` function, they came out as a weird
``<SAO <BV64 0xSTUFF>>`` class. This is a ``SimActionObject``. Basically, you
don't need to worry about it too much, it's just a thin wrapper over a normal
bitvector. It does a bit of tracking of what exactly you do with it inside the
SimProcedure---this is helpful for static analysis.

You may also have noticed that we directly returned the Python int ``0`` from
the procedure. This will automatically be promoted to a word-sized bitvector!
You can return a native number, a bitvector, or a SimActionObject.

When you want to write a procedure that deals with floating point numbers, you
will need to specify the calling convention manually. It's not too hard, just
provide a cc to the hook: ```cc = project.factory.cc_from_arg_kinds((True,
True), ret_fp=True)`` and ``project.hook(address, ProcedureClass(cc=mycc))``
This method for passing in a calling convention works for all calling
conventions, so if angr's autodetected one isn't right, you can fix that.

Control Flow
------------

How can you exit a SimProcedure? We've already gone over the simplest way to do
this, returning a value from ``run()``. This is actually shorthand for calling
``self.ret(value)``. ``self.ret()`` is the function which knows how to perform
the specific action of returning from a function.

SimProcedures can use lots of different functions like this!


* ``ret(expr)``: Return from a function
* ``jump(addr)``: Jump to an address in the binary
* ``exit(code)``: Terminate the program
* ``call(addr, args, continue_at)``: Call a function in the binary
* ``inline_call(procedure, *args)``: Call another SimProcedure in-line and
  return the results

That second-last one deserves some looking-at. We'll get there after a quick
detour...

Conditional Exits
^^^^^^^^^^^^^^^^^

What if we want to add a conditional branch out of a SimProcedure? In order to
do that, you'll need to work directly with the SimSuccessors object for the
current execution step.

The interface for this is ```self.successors.add_successor(state, addr, guard,
jumpkind)``. All of these parameters should have an obvious meaning if you've
followed along so far. Keep in mind that the state you pass in will NOT be
copied and WILL be mutated, so be sure to make a copy beforehand if there will
be more work to do!

SimProcedure Continuations
^^^^^^^^^^^^^^^^^^^^^^^^^^

How can we call a function in the binary and have execution resume within our
SimProcedure? There is a whole bunch of infrastructure called the "SimProcedure
Continuation" that will let you do this. When you use ``self.call(addr, args,
continue_at)``, ``addr`` is expected to be the address you'd like to call,
``args`` is the tuple of arguments you'd like to call it with, and
``continue_at`` is the name of another method in your SimProcedure class that
you'd like execution to continue at when it returns. This method must have the
same signature as the ``run()`` method. Furthermore, you can pass the keyword
argument ``cc`` as the calling convention that ought to be used to communicate
with the callee.

When you do this, you finish your current step, and execution will start again
at the next step at the function you've specified. When that function returns,
it has to return to some concrete address! That address is specified by the
SimProcedure runtime: an address is allocated in angr's externs segment to be
used as the return site for returning to the given method call. It is then
hooked with a copy of the procedure instance tweaked to run the specified
``continue_at`` function instead of ``run()``, with the same args and kwargs as
the first time.

There are two pieces of metadata you need to attach to your SimProcedure class
in order to use the continuation subsystem correctly:


* Set the class variable ``IS_FUNCTION = True``
* Set the class variable ``local_vars`` to a tuple of strings, where each string
  is the name of an instance variable on your SimProcedure whose value you would
  like to persist to when you return. Local variables can be any type so long as
  you don't mutate their instances.

You may have guessed by now that there exists some sort of auxiliary storage in
order to hold on to all this data. You would be right! The state plugin
``state.callstack`` has an entry called ``.procedure_data`` which is used by the
SimProcedure runtime to store information local to the current call frame. angr
tracks the stack pointer in order to make the current top of the
``state.callstack`` a meaningful local data store. It's stuff that ought to be
stored in memory in a stack frame, but the data can't be serialized and/or
memory allocation is hard.

As an example, let's look at the SimProcedure that angr uses internally to run
all the shared library initializers for a ``full_init_state`` for a linux
program:

.. code-block:: python

   class LinuxLoader(angr.SimProcedure):
       NO_RET = True
       IS_FUNCTION = True
       local_vars = ('initializers',)

       def run(self):
           self.initializers = self.project.loader.initializers
           self.run_initializer()

       def run_initializer(self):
           if len(self.initializers) == 0:
               self.project._simos.set_entry_register_values(self.state)
               self.jump(self.project.entry)
           else:
               addr = self.initializers[0]
               self.initializers = self.initializers[1:]
               self.call(addr, (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')

This is a particularly clever usage of the SimProcedure continuations. First,
notice that the current project is available for use on the procedure instance.
This is some powerful stuff you can get yourself into; for safety you generally
only want to use the project as a read-only or append-only data structure. Here
we're just getting the list of dynamic initializers from the loader. Then, for as
long as the list isn't empty, we pop a single function pointer out of the list,
being careful not to mutate the list, since the list object is shared across
states, and then call it, returning to the ``run_initializer`` function again.
When we run out of initializers, we set up the entry state and jump to the
program entry point.

Very cool!

Global Variables
----------------

As a brief aside, you can store global variables in ``state.globals``. This is a
dictionary that just gets shallow-copied from state to successor state. Because
it's only a shallow copy, its members are the same instances, so the same rules
as local variables in SimProcedure continuations apply. You need to be careful
not to mutate any item that is used as a global variable unless you know exactly
what you're doing.

Helping out static analysis
---------------------------

We've already looked at the class variable ``IS_FUNCTION``, which allows you to
use the SimProcedure continuation. There are a few more class variables you can
set, though these ones have no direct benefit to you - they merely mark
attributes of your function so that static analysis knows what it's doing.


* ``NO_RET``: Set this to true if control flow will never return from this
  function
* ``ADDS_EXITS``: Set this to true if you do any control flow other than
  returning
* ``IS_SYSCALL``: Self-explanatory

Furthermore, if you set ``ADDS_EXITS = True``, you'll need to define the method
``static_exits()``. This function takes a single parameter, a list of IRSBs that
would be executed in the run-up to your function, and asks you to return a list
of all the exits that you know would be produced by your function in that case.
The return value is expected to be a list of tuples of (address (int), jumpkind
(str)). This is meant to be a quick, best-effort analysis, and you shouldn't try
to do anything crazy or intensive to get your answer.

User Hooks
----------

The process of writing and using a SimProcedure makes a lot of assumptions that
you want to hook over a whole function. What if you don't? There's an alternate
interface for hooking, a *user hook*, that lets you streamline the process of
hooking sections of code.

.. code-block:: python

   >>> @project.hook(0x1234, length=5)
   ... def set_rax(state):
   ...     state.regs.rax = 1

This is a lot simpler! The idea is to use a single function instead of an entire
SimProcedure subclass. No extraction of arguments is performed, no complex
control flow happens.

Control flow is controlled by the length argument. After the function finishes
executing in this example, the next step will start at 5 bytes after the hooked
address. If the length argument is omitted or set to zero, execution will resume
executing the binary code at exactly the hooked address, without re-triggering
the hook. The ``Ijk_NoHook`` jumpkind allows this to happen.

If you want more control over control flow coming out of a user hook, you can
return a list of successor states. Each successor will be expected to have
``state.regs.ip``, ``state.scratch.guard``, and ``state.scratch.jumpkind`` set.
The IP is the target instruction pointer, the guard is a symbolic boolean
representing a constraint to add to the state related to it being taken as
opposed to the others, and the jumpkind is a VEX enum string, like
``Ijk_Boring``, representing the nature of the branch.

The general rule is, if you want your SimProcedure to either be able to extract
function arguments or cause a program return, write a full SimProcedure class.
Otherwise, use a user hook.

Hooking Symbols
---------------

As you should recall from the :ref:`section on loading a binary <Loading a
Binary>`, dynamically linked programs have a list of symbols that they must
import from the libraries they have listed as dependencies, and angr will make
sure, rain or shine, that every import symbol gets resolved by *some* address,
whether it's a real implementation of the function or just a dummy address hooked
with a do-nothing stub. As a result, you can just use the
``Project.hook_symbol`` API to hook the address referred to by a symbol!

This means that you can replace library functions with your own code. For
instance, to replace ``rand()`` with a function that always returns a consistent
sequence of values:

.. code-block:: python

   >>> class NotVeryRand(SimProcedure):
   ...     def run(self, return_values=None):
   ...         rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
   ...         out = return_values[rand_idx]
   ...         self.state.globals['rand_idx'] = rand_idx + 1
   ...         return out

   >>> project.hook_symbol('rand', NotVeryRand(return_values=[413, 612, 1025, 1111]))

Now, whenever the program tries to call ``rand()``, it'll return the integers
from the ``return_values`` array in a loop.
