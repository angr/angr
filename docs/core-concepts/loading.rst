Loading a Binary
================

Previously, you saw just the barest taste of angr's loading facilities - you
loaded ``/bin/true``, and then loaded it again without its shared libraries. You
also saw ``proj.loader`` and a few things it could do. Now, we'll dive into the
nuances of these interfaces and the things they can tell you.

We briefly mentioned angr's binary loading component, CLE. CLE stands for "CLE
Loads Everything", and is responsible for taking a binary (and any libraries
that it depends on) and presenting it to the rest of angr in a way that is easy
to work with.

The Loader
----------

Let's load ``examples/fauxware/fauxware`` and take a deeper look at how to
interact with the loader.

.. code-block:: python

   >>> import angr, monkeyhex
   >>> proj = angr.Project('examples/fauxware/fauxware')
   >>> proj.loader
   <Loaded fauxware, maps [0x400000:0x5008000]>

Loaded Objects
^^^^^^^^^^^^^^

The CLE loader (``cle.Loader``) represents an entire conglomerate of loaded
*binary objects*, loaded and mapped into a single memory space. Each binary
object is loaded by a loader backend that can handle its filetype (a subclass of
``cle.Backend``). For example, ``cle.ELF`` is used to load ELF binaries.

There will also be objects in memory that don't correspond to any loaded binary.
For example, an object used to provide thread-local storage support, and an
externs object used to provide unresolved symbols.

You can get the full list of objects that CLE has loaded with
``loader.all_objects``, as well as several more targeted classifications:

.. code-block:: python

   # All loaded objects
   >>> proj.loader.all_objects
   [<ELF Object fauxware, maps [0x400000:0x60105f]>,
    <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
    <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>,
    <ELFTLSObject Object cle##tls, maps [0x3000000:0x3015010]>,
    <ExternObject Object cle##externs, maps [0x4000000:0x4008000]>,
    <KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>]

   # This is the "main" object, the one that you directly specified when loading the project
   >>> proj.loader.main_object
   <ELF Object fauxware, maps [0x400000:0x60105f]>

   # This is a dictionary mapping from shared object name to object
   >>> proj.loader.shared_objects
   { 'fauxware': <ELF Object fauxware, maps [0x400000:0x60105f]>,
     'libc.so.6': <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
     'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]> }

   # Here's all the objects that were loaded from ELF files
   # If this were a windows program we'd use all_pe_objects!
   >>> proj.loader.all_elf_objects
   [<ELF Object fauxware, maps [0x400000:0x60105f]>,
    <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
    <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>]

   # Here's the "externs object", which we use to provide addresses for unresolved imports and angr internals
   >>> proj.loader.extern_object
   <ExternObject Object cle##externs, maps [0x4000000:0x4008000]>

   # This object is used to provide addresses for emulated syscalls
   >>> proj.loader.kernel_object
   <KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>

   # Finally, you can to get a reference to an object given an address in it
   >>> proj.loader.find_object_containing(0x400000)
   <ELF Object fauxware, maps [0x400000:0x60105f]>

You can interact directly with these objects to extract metadata from them:

.. code-block:: python

   >>> obj = proj.loader.main_object

   # The entry point of the object
   >>> obj.entry
   0x400580

   >>> obj.min_addr, obj.max_addr
   (0x400000, 0x60105f)

   # Retrieve this ELF's segments and sections
   >>> obj.segments
   <Regions: [<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>,
              <ELFSegment memsize=0x238, filesize=0x228, vaddr=0x600e28, flags=0x6, offset=0xe28>]>
   >>> obj.sections
   <Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
              <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
              <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
               ...etc

   # You can get an individual segment or section by an address it contains:
   >>> obj.find_segment_containing(obj.entry)
   <ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>
   >>> obj.find_section_containing(obj.entry)
   <.text | offset 0x580, vaddr 0x400580, size 0x338>

   # Get the address of the PLT stub for a symbol
   >>> addr = obj.plt['strcmp']
   >>> addr
   0x400550
   >>> obj.reverse_plt[addr]
   'strcmp'

   # Show the prelinked base of the object and the location it was actually mapped into memory by CLE
   >>> obj.linked_base
   0x400000
   >>> obj.mapped_base
   0x400000

Symbols and Relocations
^^^^^^^^^^^^^^^^^^^^^^^

You can also work with symbols while using CLE. A symbol is a fundamental
concept in the world of executable formats, effectively mapping a name to an
address.

The easiest way to get a symbol from CLE is to use ``loader.find_symbol``, which
takes either a name or an address and returns a Symbol object.

.. code-block:: python

   >>> strcmp = proj.loader.find_symbol('strcmp')
   >>> strcmp
   <Symbol "strcmp" in libc.so.6 at 0x1089cd0>

The most useful attributes on a symbol are its name, its owner, and its address,
but the "address" of a symbol can be ambiguous. The Symbol object has three ways
of reporting its address:


* ``.rebased_addr`` is its address in the global address space. This is what is
  shown in the print output.
* ``.linked_addr`` is its address relative to the prelinked base of the binary.
  This is the address reported in, for example, ``readelf(1)``.
* ``.relative_addr`` is its address relative to the object base. This is known
  in the literature (particularly the Windows literature) as an RVA (relative
  virtual address).

.. code-block:: python

   >>> strcmp.name
   'strcmp'

   >>> strcmp.owner
   <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>

   >>> strcmp.rebased_addr
   0x1089cd0
   >>> strcmp.linked_addr
   0x89cd0
   >>> strcmp.relative_addr
   0x89cd0

In addition to providing debug information, symbols also support the notion of
dynamic linking. libc provides the strcmp symbol as an export, and the main
binary depends on it. If we ask CLE to give us a strcmp symbol from the main
object directly, it'll tell us that this is an *import symbol*. Import symbols
do not have meaningful addresses associated with them, but they do provide a
reference to the symbol that was used to resolve them, as ``.resolvedby``.

.. code-block:: python

   >>> strcmp.is_export
   True
   >>> strcmp.is_import
   False

   # On Loader, the method is find_symbol because it performs a search operation to find the symbol.
   # On an individual object, the method is get_symbol because there can only be one symbol with a given name.
   >>> main_strcmp = proj.loader.main_object.get_symbol('strcmp')
   >>> main_strcmp
   <Symbol "strcmp" in fauxware (import)>
   >>> main_strcmp.is_export
   False
   >>> main_strcmp.is_import
   True
   >>> main_strcmp.resolvedby
   <Symbol "strcmp" in libc.so.6 at 0x1089cd0>

The specific ways that the links between imports and exports should be
registered in memory are handled by another notion called *relocations*. A
relocation says, "when you match *[import]* up with an export symbol, please
write the export's address to *[location]*, formatted as *[format]*." We can see
the full list of relocations for an object (as ``Relocation`` instances) as
``obj.relocs``, or just a mapping from symbol name to Relocation as
``obj.imports``. There is no corresponding list of export symbols.

A relocation's corresponding import symbol can be accessed as ``.symbol``. The
address the relocation will write to is accessible through any of the address
identifiers you can use for Symbol, and you can get a reference to the object
requesting the relocation with ``.owner`` as well.

.. code-block:: python

   # Relocations don't have a good pretty-printing, so those addresses are Python-internal, unrelated to our program
   >>> proj.loader.shared_objects['libc.so.6'].imports
   {'__libc_enable_secure': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce780>,
    '__tls_get_addr': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018358>,
    '_dl_argv': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2e48>,
    '_dl_find_dso_for_object': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018588>,
    '_dl_starting_up': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2550>,
    '_rtld_global': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce4e0>,
    '_rtld_global_ro': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fcea20>}

If an import cannot be resolved to any export, for example, because a shared
library could not be found, CLE will automatically update the externs object
(``loader.extern_obj``) to claim it provides the symbol as an export.

Loading Options
---------------

If you are loading something with ``angr.Project`` and you want to pass an
option to the ``cle.Loader`` instance that Project implicitly creates, you can
just pass the keyword argument directly to the Project constructor, and it will
be passed on to CLE. You should look at the `CLE API docs.
<https://docs.angr.io/projects/cle/en/latest/api.html>`_ if you want to know
everything that could possibly be passed in as an option, but we will go over
some important and frequently used options here.

Basic Options
~~~~~~~~~~~~~

We've discussed ``auto_load_libs`` already - it enables or disables CLE's
attempt to automatically resolve shared library dependencies, and is on by
default. Additionally, there is the opposite, ``except_missing_libs``, which, if
set to true, will cause an exception to be thrown whenever a binary has a shared
library dependency that cannot be resolved.

You can pass a list of strings to ``force_load_libs`` and anything listed will
be treated as an unresolved shared library dependency right out of the gate, or
you can pass a list of strings to ``skip_libs`` to prevent any library of that
name from being resolved as a dependency. Additionally, you can pass a list of
strings (or a single string) to ``ld_path``, which will be used as an additional
search path for shared libraries, before any of the defaults: the same directory
as the loaded program, the current working directory, and your system libraries.

Per-Binary Options
~~~~~~~~~~~~~~~~~~

If you want to specify some options that only apply to a specific binary object,
CLE will let you do that too. The parameters ``main_opts`` and ``lib_opts`` do
this by taking dictionaries of options. ``main_opts`` is a mapping from option
names to option values, while ``lib_opts`` is a mapping from library name to
dictionaries mapping option names to option values.

The options that you can use vary from backend to backend, but some common ones
are:


* ``backend`` - which backend to use, as either a class or a name
* ``base_addr`` - a base address to use
* ``entry_point`` - an entry point to use
* ``arch`` - the name of an architecture to use

Example:

.. code-block:: python

   >>> angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
   <Project examples/fauxware/fauxware>

Backends
^^^^^^^^

CLE currently has backends for statically loading ELF, PE, CGC, Mach-O and ELF
core dump files, as well as loading files into a flat address space. CLE will
automatically detect the correct backend to use in most cases, so you shouldn't
need to specify which backend you're using unless you're doing some pretty weird
stuff.

You can force CLE to use a specific backend for an object by including a key in
its options dictionary, as described above. Some backends cannot autodetect
which architecture to use and *must* have a ``arch`` specified. The key doesn't
need to match any list of architectures; angr will identify which architecture
you mean given almost any common identifier for any supported arch.

To refer to a backend, use the name from this table:

.. list-table::
   :header-rows: 1

   * - backend name
     - description
     - requires ``arch``?
   * - elf
     - Static loader for ELF files based on PyELFTools
     - no
   * - pe
     - Static loader for PE files based on PEFile
     - no
   * - mach-o
     - Static loader for Mach-O files. Does not support dynamic linking or rebasing.
     - no
   * - cgc
     - Static loader for Cyber Grand Challenge binaries
     - no
   * - backedcgc
     - Static loader for CGC binaries that allows specifying memory and register backers
     - no
   * - elfcore
     - Static loader for ELF core dumps
     - no
   * - blob
     - Loads the file into memory as a flat image
     - yes


Symbolic Function Summaries
---------------------------

By default, Project tries to replace external calls to library functions by
using symbolic summaries termed *SimProcedures* - effectively just Python
functions that imitate the library function's effect on the state. We've
implemented `a whole bunch of functions
<https://github.com/angr/angr/tree/master/angr/procedures>`_ as SimProcedures.
These builtin procedures are available in the ``angr.SIM_PROCEDURES``
dictionary, which is two-leveled, keyed first on the package name (libc, posix,
win32, stubs) and then on the name of the library function. Executing a
SimProcedure instead of the actual library function that gets loaded from your
system makes analysis a LOT more tractable, at the cost of `some potential
inaccuracies <Gotchas when using angr>`.

When no such summary is available for a given function:


* if ``auto_load_libs`` is ``True`` (this is the default), then the *real*
  library function is executed instead. This may or may not be what you want,
  depending on the actual function. For example, some of libc's functions are
  extremely complex to analyze and will most likely cause an explosion of the
  number of states for the path trying to execute them.
* if ``auto_load_libs`` is ``False``, then external functions are unresolved,
  and Project will resolve them to a generic "stub" SimProcedure called
  ``ReturnUnconstrained``. It does what its name says: it returns a unique
  unconstrained symbolic value each time it is called.
* if ``use_sim_procedures`` (this is a parameter to ``angr.Project``, not
  ``cle.Loader``) is ``False`` (it is ``True`` by default), then only symbols
  provided by the extern object will be replaced with SimProcedures, and they
  will be replaced by a stub ``ReturnUnconstrained``, which does nothing but
  return a symbolic value.
* you may specify specific symbols to exclude from being replaced with
  SimProcedures with the parameters to ``angr.Project``:
  ``exclude_sim_procedures_list`` and ``exclude_sim_procedures_func``.
* Look at the code for ``angr.Project._register_object`` for the exact
  algorithm.

Hooking
~~~~~~~

The mechanism by which angr replaces library code with a Python summary is
called hooking, and you can do it too! When performing simulation, at every step
angr checks if the current address has been hooked, and if so, runs the hook
instead of the binary code at that address. The API to let you do this is
``proj.hook(addr, hook)``, where ``hook`` is a SimProcedure instance. You can
manage your project's hooks with ``.is_hooked``, ``.unhook``, and
``.hooked_by``, which should hopefully not require explanation.

There is an alternate API for hooking an address that lets you specify your own
off-the-cuff function to use as a hook, by using ``proj.hook(addr)`` as a
function decorator. If you do this, you can also optionally specify a ``length``
keyword argument to make execution jump some number of bytes forward after your
hook finishes.

.. code-block:: python

   >>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
   >>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

   >>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
   True
   >>> proj.hooked_by(0x10000)
   <ReturnUnconstrained>
   >>> proj.unhook(0x10000)

   >>> @proj.hook(0x20000, length=5)
   ... def my_hook(state):
   ...     state.regs.rax = 1

   >>> proj.is_hooked(0x20000)
   True

Furthermore, you can use ``proj.hook_symbol(name, hook)``, providing the name of
a symbol as the first argument, to hook the address where the symbol lives. One
very important usage of this is to extend the behavior of angr's built-in
library SimProcedures. Since these library functions are just classes, you can
subclass them, overriding pieces of their behavior, and then use your subclass
in a hook.

So far so good!
---------------

By now, you should have a reasonable understanding of how to control the
environment in which your analysis happens, on the level of the CLE loader and
the angr Project. You should also understand that angr makes a reasonable
attempt to simplify its analysis by hooking complex library functions with
SimProcedures that summarize the effects of the functions.

In order to see all the things you can do with the CLE loader and its backends,
look at the `CLE API docs.
<https://docs.angr.io/projects/cle/en/latest/api.html>`_
