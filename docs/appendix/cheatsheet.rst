Cheatsheet
==========

The following cheatsheet aims to give an overview of various things you can do
with angr and act as a quick reference to check the syntax for something without
having to dig through the deeper docs.

General getting started
-----------------------

Some useful imports

.. code-block:: python

   import angr #the main framework
   import claripy #the solver engine

Loading the binary

.. code-block:: python

   proj = angr.Project("/path/to/binary", auto_load_libs=False) # auto_load_libs False for improved performance

States
------

Create a SimState object

.. code-block:: python

   state = proj.factory.entry_state()

Simulation Managers
-------------------

Generate a simulation manager object

.. code-block:: python

   simgr = proj.factory.simulation_manager(state)

Exploring and analysing states
------------------------------

Choosing a different Exploring strategy

.. code-block:: python

   simgr.use_technique(angr.exploration_techniques.DFS())

Symbolically execute until we find a state satisfying our ``find=`` and ``avoid=`` parameters

.. code-block:: python

   avoid_addr = [0x400c06, 0x400bc7]
   find_addr = 0x400c10d
   simgr.explore(find=find_addr, avoid=avoid_addr)

.. code-block:: python

   found = simgr.found[0] # A state that reached the find condition from explore
   found.solver.eval(sym_arg, cast_to=bytes) # Return a concrete string value for the sym arg to reach this state

Symbolically execute until lambda expression is ``True``

.. code-block:: python

   simgr.step(until=lambda sm: sm.active[0].addr >= first_jmp)

This is especially useful with the ability to access the current STDOUT or
STDERR (1 here is the File Descriptor for STDOUT)

.. code-block:: python

   simgr.explore(find=lambda s: "correct" in s.posix.dumps(1))

Memory Management on big searches (Auto Drop Stashes):

.. code-block:: python


   simgr.explore(find=find_addr, avoid=avoid_addr, step_func=lambda lsm: lsm.drop(stash='avoid'))

Manually Exploring
^^^^^^^^^^^^^^^^^^

.. code-block:: python

   simgr.step(step_func=step_func, until=lambda lsm: len(sm.found) > 0)

   def step_func(lsm):
       lsm.stash(filter_func=lambda state: state.addr == 0x400c06, from_stash='active', to_stash='avoid')
       lsm.stash(filter_func=lambda state: state.addr == 0x400bc7, from_stash='active', to_stash='avoid')
       lsm.stash(filter_func=lambda state: state.addr == 0x400c10, from_stash='active', to_stash='found')
       return lsm

Enable Logging output from Simulation Manager:

.. code-block:: python

   import logging
   logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

Stashes
^^^^^^^

Move Stash:

.. code-block:: python

   simgr.stash(from_stash="found", to_stash="active")

Drop Stashes:

.. code-block:: python

   simgr.drop(stash="avoid")

Constraint Solver (claripy)
---------------------------

Create symbolic object

.. code-block:: python

   sym_arg_size = 15 #Length in Bytes because we will multiply with 8 later
   sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)

Restrict sym_arg to typical char range

.. code-block:: python

   for byte in sym_arg.chop(8):
       initial_state.add_constraints(byte >= '\x20') # ' '
       initial_state.add_constraints(byte <= '\x7e') # '~'

Create a state with a symbolic argument

.. code-block:: python

   argv = [proj.filename]
   argv.append(sym_arg)
   state = proj.factory.entry_state(args=argv)

Use argument for solving:

.. code-block:: python

   sym_arg = angr.claripy.BVS("sym_arg", flag_size * 8)
   argv = [proj.filename]
   argv.append(sym_arg)
   initial_state = proj.factory.full_init_state(args=argv, add_options=angr.options.unicorn, remove_options={angr.options.LAZY_SOLVES})

FFI and Hooking
---------------

Calling a function from ipython

.. code-block:: python

   f = proj.factory.callable(address)
   f(10)
   x=claripy.BVS('x', 64)
   f(x) #TODO: Find out how to make that result readable

If what you are interested in is not directly returned because for example the
function returns the pointer to a buffer you can access the state after the
function returns with

.. code-block:: python

   >>> f.result_state
   <SimState @ 0x1000550>

Hooking

There are already predefined hooks for libc functions (useful for statically
compiled libraries)

.. code-block:: python

   proj = angr.Project('/path/to/binary', use_sim_procedures=True)
   proj.hook(addr, angr.SIM_PROCEDURES['libc']['atoi']())

Hooking with Simprocedure:

.. code-block:: python

   class fixpid(angr.SimProcedure):
       def run(self):
               return 0x30

   proj.hook(0x4008cd, fixpid())

Other useful tricks
-------------------

Drop into an ipython if a ctr+c is received (useful for debugging scripts that
are running forever)

.. code-block:: python

   import signal
   def killmyself():
       os.system('kill %d' % os.getpid())
   def sigint_handler(signum, frame):
       print 'Stopping Execution for Debug. If you want to kill the program issue: killmyself()'
       if not "IPython" in sys.modules:
           import IPython
           IPython.embed()

   signal.signal(signal.SIGINT, sigint_handler)

Get the calltrace of a state to find out where we got stuck

.. code-block:: python

   state = simgr.active[0]
   print state.callstack

Get a basic block

.. code-block:: python

   block = proj.factory.block(address)
   block.capstone.pp() # Capstone object has pretty print and other data about the disassembly
   block.vex.pp()      # Print vex representation

State manipulation
------------------

Write to state:

.. code-block:: python

   aaaa = claripy.BVV(0x41414141, 32) # 32 = Bits
   state.memory.store(0x6021f2, aaaa)

Read Pointer to Pointer from Frame:

.. code-block:: python

   poi1 = new_state.solver.eval(new_state.regs.rbp)-0x10
   poi1 = new_state.mem[poi1].long.concrete
   poi1 += 0x8
   ptr1 = new_state.mem[poi1].long.concrete

Read from State:

.. code-block:: python

   key = []
   for i in range(38):
       key.append(extractkey.mem[0x602140 + i*4].int.concrete)

Alternatively, the below expression is equivalent

.. code-block:: python

   key = extractkey.mem[0x602140].int.array(38).concrete

Debugging angr
--------------

Set Breakpoint at every Memory read/write:

.. code-block:: python

   new_state.inspect.b('mem_read', when=angr.BP_AFTER, action=debug_funcRead)
   def debug_funcRead(state):
       print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address

Set Breakpoint at specific Memory location:

.. code-block:: python

   new_state.inspect.b('mem_write', mem_write_address=0x6021f1, when=angr.BP_AFTER, action=debug_funcWrite)
