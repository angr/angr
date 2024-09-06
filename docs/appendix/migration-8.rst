Migrating to angr 8
===================

angr has moved from Python 2 to Python 3!
We took this opportunity of a major version bump to make a few breaking API changes that improve quality-of-life.

What do I need to know for migrating my scripts to Python 3?
------------------------------------------------------------

To begin, just the standard py3k changes, the relevant parts of which we'll rehash here as a reference guide:


* Strings and bytestrings

  * Strings are now unicode by default, a new ``bytes`` type holds bytestrings
  * Bytestring literals can be constructed with the b prefix, like ``b'ABCD'``
  * Conversion between strings and bytestrings happens with ``.encode()`` and ``.decode()``, which use utf-8 as a default. The ``latin-1`` codec will map byte values to their equivalent unicode codepoints
  * The ``ord()`` and ``chr()`` functions operate on strings, not bytestrings
  * Enumerating over or indexing into bytestrings produces an unsigned 8 bit integer, not a 1-byte bytestring
  * Bytestrings have all the string manipulation functions present on strings, including ``join``, ``upper``/``lower``, ``translate``, etc
  * ``hex`` and ``base64`` are no longer string encoding codecs. For hex, use ``bytes.fromhex()`` and ``bytes.hex()``. For base64 use the ``base64`` module.

* Builtin functions

  * ``print`` and ``exec`` are now builtin functions instead of statements
  * Many builtin functions previously returning lists now return iterators, such as ``map``, ``filter``, and ``zip``. ``reduce`` is no longer a builtin; you have to import it from ``functools``.

* Numbers

  * The ``/`` operator is explicitly floating-point division, the ``//`` operator is expliclty integer division. The magic functions for overriding these ops are ``truediv__`` and ``floordiv__``
  * The int and long types have been merged, there is only int now

* Dictionary objects have had their ``.iterkeys``, ``.itervalues``, and ``.iteritems`` methods removed, and then non-iter versions have been made to return efficient iterators
* Comparisons between objects of very different types (such as between strings and ints) will raise an exception

In terms of how this has affected angr, any string that represents data from the emulated program will be a bytestring.
This means that where you previously said ``state.solver.eval(x, cast_to=str)`` you should now say ``cast_to=bytes``.
When creating concrete bitvectors from strings (including implicitly by just making a comparison against a string) these should be bytestrings. If they are not they will be utf-8 converted and a warning will be printed.
Symbol names should be unicode strings.

For division, however, ASTs are strongly typed so they will treat both division operators as the kind of division that makes sense for their type.

Clemory API changes
-------------------

The memory object in CLE (project.loader.memory, not state.memory) has had a few breaking API changes since the bytes type is much nicer to work with than the py2 string for this specific case, and the old API was an inconsistent mess.

.. list-table::
   :header-rows: 1

   * - Before
     - After
   * - ``memory.read_bytes(addr, n) -> list[str]``
     - ``memory.load(addr, n) -> bytes``
   * - ``memory.write_bytes(addr, list[str])``
     - ``memory.store(addr, bytes)``
   * - ``memory.get_byte(addr) -> str``
     - ``memory[addr] -> int``
   * - ``memory.read_addr_at(addr) -> int``
     - ``memory.unpack_word(addr) -> int``
   * - ``memory.write_addr_at(addr, value) -> int``
     - ``memory.pack_word(addr, value)``
   * - ``memory.stride_repr -> list[(start, end, str)]``
     - ``memory.backers() -> iter[(start, bytearray)]``


Additionally, ``pack_word`` and ``unpack_word`` now take optional ``size``, ``endness``, and ``signed`` parameters.
We have also added ``memory.pack(addr, fmt, *data)`` and ``memory.unpack(addr, fmt)``, which take format strings for use with the ``struct`` module.

If you were using the ``cbackers`` or ``read_bytes_c`` functions, the conversion is a little more complicated - we were able to remove the split notion of "backers" and "updates" and replaced all backers with bytearrays that we mutate, so we can work directly with the backer objects.
The ``backers()`` function iterates through all bottom-level backer objects and their start addresses. You can provide an optional address to the function, and it will skip over all backers that end before that address.

Here is some sample code for producing a C-pointer to a given address:

.. code-block:: python

   import cffi, cle
   ffi = cffi.FFI()
   ld = cle.Loader('/bin/true')

   addr = ld.main_object.entry
   try:
       backer_start, backer = next(ld.memory.backers(addr))
   except StopIteration:
       raise Exception("not mapped")

   if backer_start > addr:
       raise Exception("not mapped")

   cbacker = ffi.from_buffer(backer)
   addr_pointer = cbacker + (addr - backer_start)

You should not have to use this if you aren't passing the data to a native library - the normal load methods should now be more than fast enough for intensive use.

CLE symbols changes
-------------------

Previously, your mechanisms for looking up symbols by their address were ``loader.find_symbol()`` and ``object.symbols_by_addr``, where there was clearly some overlap.
However, ``symbols_by_addr`` stayed because it was the only way to enumerate symbols in an object.
This has changed! ``symbols_by_addr`` is deprecated and here is now ``object.symbols``, a sorted list of Symbol objects, to enumerate symbols in a binary.

Additionally, you can now enumerate all symbols in the entire project with ``loader.symbols``.
This change has also enabled us to add a ``fuzzy`` parameter to ``find_symbol`` (returns the first symbol before the given address) and make the output of ``loader.describe_addr`` much nicer (shows offset from closest symbol).

Deprecations and name changes
-----------------------------


* All parameters in cle that started with ``custom_`` - so, ``custom_base_addr``, ``custom_entry_point``, ``custom_offset``, ``custom_arch``, and ``custom_ld_path`` - have had the ``custom_`` removed from the beginning of their names.
* All the functions that were deprecated more than a year ago (at or before the angr 7 release) have been removed.
* ``state.se`` has been deprecated.
  You should have been using ``state.solver`` for the past few years.
* Support for immutable simulation managers has been removed.
  So far as we're aware, nobody was actually using this, and it was making debugging a pain.
