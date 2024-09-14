Debug variable resolution
=========================

angr now support resolve source level variable (debug variable) in
binary with debug information. This article will introduce you how to
use it.

Setting up
----------

To use it you need binary that is compiled with dwarf debugging
information (ex: ``gcc -g``) and load in angr with the option
``load_debug_info``. After that you need to run
``project.kb.dvars.load_from_dwarf()`` to set up the feature and we’re
set.

Overall it looks like this:

.. code-block::

   # compile your binary with debug information
   gcc -g -o debug_var debug_var.c

.. code-block:: python

   >>> import angr
   >>> project = angr.Project('./examples/debug_var/simple_var', load_debug_info = True)
   >>> project.kb.dvars.load_from_dwarf()

Core feature
------------

With things now set up you can view the value in the angr memory view of
the debug variable within a state with:
``state.dvars['variable_name'].mem`` or the value that it point to if it
is a pointer with: ``state.dvars['pointer_name'].deref.mem``. Here are
some example:

Given the source code in ``examples/debug_var/simple_var.c``

.. code-block:: c

   #include<stdio.h>

   int global_var = 100;
   int main(void){
      int a = 10;
      int* b = &a;
      printf("%d\n", *b);
      {
         int a = 24;
         *b = *b + a;
         int c[] = {5, 6, 7, 8};
         printf("%d\n", a);
      }
      return 0;
   }

.. code-block:: python

   # Get a state before executing printf(%d\n", *b) (line 7)
   # the addr to line 7 is 0x401193 you can search for it with
   >>> project.loader.main_object.addr_to_line
   {...}
   >>> addr = 0x401193
   # Create an simulation manager and run to that addr
   >>> simgr = project.factory.simgr()
   >>> simgr.explore(find = addr)
   <SimulationManager with 1 found>
   >>> state = simgr.found[0]
   # Resolve 'a' in state
   >>> state.dvars['a'].mem
   <int (32 bits) <BV32 0xa> at 0x7fffffffffeff30>
   # Dereference pointer b
   >>> state.dvars['b'].deref.mem
   <int (32 bits) <BV32 0xa> at 0x7fffffffffeff30>
   # It works as expected when resolving the value of b gives the address of a
   >>> state.dvars['b'].mem
   <reg64_t <BV64 0x7fffffffffeff30> at 0x7fffffffffeff38>

Side-note: For string type you can use ``.string`` instead of ``.mem``
to resolve it. For struct type you can resolve its member by
``.member("member_name").mem``. For array type you can use
``.array(index).mem`` to access the element in array.

Variable visibility
===================

If you have many variable with the same name but in different scope,
calling ``state.dvars['var_name']`` would resolve the variable with the
nearest scope.

Example:

.. code-block:: python

   # Find the addr before executing printf("%d\n", a) (line 12)
   # with the same method to find addr
   >>> addr = 0x4011e0
   # Explore until find state
   >>> simgr.move(from_stash='found', to_stash='active')
   <SimulationManager with 1 active>
   >>> simgr.explore(find = addr)
   <SimulationManager with 1 found>
   >>> state = simgr.found[0]
   # Resolve 'a' in state before execute line 10
   >>> state.dvars['a'].mem
   <int (32 bits) <BV32 0x18> at 0x7fffffffffeff34>

Congratulation, you’ve now know how to resolve debug variable using
angr, for more info check out the api-doc.
