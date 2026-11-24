Unpacking Windows Executables
=============================

Many Windows programs, and most Windows malware, are *packed*: the program's
real code is stored compressed or encrypted inside the file, and a small piece
of start-up code restores it in memory each time the program starts. Looking at
such a file with a disassembler or decompiler shows only the start-up code and
a block of unreadable data.

*Unpacking* means getting the real code back. angr does this by running the
program inside an emulator, waiting until the start-up code has restored the
real code and jumps to it, and then saving the program's memory as a new
executable file that other analyses can load.

The program is never run on your processor or your operating system. It runs
only inside angr's emulator, against a simulated Windows 7 process that angr
builds for it, so it cannot touch your files, your network or your machine.

The analyses on this page work on 32-bit and 64-bit Windows executables (PE
files) that were loaded from a file on disk.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Analysis
     - What it does
   * - ``Unpacker``
     - Finds out how the file is protected and runs the matching unpacker
       below. Start here.
   * - ``PackerIdentifier``
     - Only reports which protection tool was used and whether the real code
       is packed. It does not run the program.
   * - ``GenericUnpacker``
     - Unpacks a file without knowing which tool packed it.
   * - ``VMProtectUnpacker``
     - Unpacks files protected with VMProtect.
   * - ``ThemidaUnpacker``
     - Unpacks files protected with Themida or WinLicense.
   * - ``VMProtectStaticUnpacker``
     - Decompresses a VMProtect-packed file without running it.

A Few Terms
-----------

Original entry point (OEP)
   The address where the real program starts. The start-up code jumps there
   once it has restored the real code.

Section
   A named region of an executable file, such as ``.text`` (code) or ``.data``
   (data).

Import table
   The list of Windows functions a program uses. Windows fills it in with the
   functions' addresses when the program starts. Packers usually remove this
   list and look the functions up themselves, so an unpacker has to rebuild
   it.

Unpacking a File
----------------

``Unpacker`` is the analysis to use when you do not know, or do not care, how
a file is protected. The analysis runs as soon as you create it.

.. code-block:: python

   >>> import angr
   >>> p = angr.Project("../binaries/tests/i386/windows/unpacker/xor_packed.exe", auto_load_libs=False)
   >>> unpacker = p.analyses.Unpacker()

   # the address where the real program starts
   >>> hex(unpacker.oep)
   '0x401800'

   # the unpacked program, as the bytes of a new executable file
   >>> with open("xor_packed.unpacked.exe", "wb") as f:
   ...     f.write(unpacker.unpacked)
   16384

   # the unpacked file can be loaded like any other program
   >>> unpacked = angr.Project("xor_packed.unpacked.exe", auto_load_libs=False)
   >>> hex(unpacked.entry)
   '0x401800'

The saved file is meant for analysis: its code is readable, its entry point is
the original entry point, and its import table is rebuilt where angr could
recover it. It is not guaranteed to run on a real Windows machine.

Results
^^^^^^^

``unpacked``
   The bytes of the unpacked executable file, or ``None`` if nothing was
   unpacked.

``oep``
   The original entry point, or ``None`` if the program never jumped into
   restored code.

``info``
   What ``Unpacker`` found out about the file's protection before running it.
   See `Identifying the Protection`_.

``unpacker``
   The analysis that did the actual work (a ``GenericUnpacker``,
   ``VMProtectUnpacker`` or ``ThemidaUnpacker``), or ``None`` if the file is
   not packed. Only ``Unpacker`` has this attribute.

``stop``
   Why the emulated program stopped running. ``stop.reason`` is one of the
   values in the table below, ``stop.addr`` is the address where it stopped,
   and ``stop.detail`` is a short description.

``layers``
   Every snapshot of the program's memory that was taken during the run. See
   `Programs Packed More Than Once`_.

``unlisted_exports``
   Functions the program asked Windows for that angr's lists of Windows
   functions do not contain. See `Choosing the Lists of Windows Functions`_.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - ``stop.reason``
     - Meaning
   * - ``StopReason.EXITED``
     - The program ended itself, for example by calling ``ExitProcess``.
   * - ``StopReason.RETURNED``
     - The program's entry function returned.
   * - ``StopReason.BUDGET``
     - The time limit ran out.
   * - ``StopReason.ERROR``
     - The program crashed, or it did something the emulator cannot handle.
       ``stop.detail`` says what.
   * - ``StopReason.EXEC_TRAP``
     - The program was stopped right after it jumped into restored code.

When a File Is Not Packed
^^^^^^^^^^^^^^^^^^^^^^^^^

If ``Unpacker`` can tell from the file alone that the real code is already
readable, it does not run the program at all:

.. code-block:: python

   >>> p = angr.Project("../binaries/tests/i386/windows/unpacker/not_packed.exe", auto_load_libs=False)
   >>> unpacker = p.analyses.Unpacker()
   >>> unpacker.info.packed
   False
   >>> unpacker.info.reason
   'original code is readable on disk (30 repeated call targets)'
   >>> unpacker.unpacked is None
   True

Options
-------

All of the unpackers that run the program accept these options.

``timeout``
   The longest time, in seconds, the program may run. The default depends on
   the unpacker: 300 seconds for ``GenericUnpacker``, 600 for
   ``VMProtectUnpacker`` and 1800 for ``ThemidaUnpacker``. ``Unpacker`` uses
   the default of the unpacker it picks unless you give a value.

``engine``
   Which emulator runs the program: ``"unicorn"`` (the default) or
   ``"icicle"``. See `Choosing the Emulator`_.

``exports_dir``
   A directory with your own lists of Windows functions. See
   `Choosing the Lists of Windows Functions`_.

``icicle_jit``, ``icicle_jit_threshold``, ``icicle_thread_slice``
   Settings of the Icicle emulator. See `Choosing the Emulator`_.

``GenericUnpacker`` also accepts ``settle_timeout``, and ``VMProtectUnpacker``
also accepts ``static_only``. Both are described with their unpacker below.

.. code-block:: python

   >>> unpacker = p.analyses.Unpacker(timeout=120, engine="icicle")

Choosing the Emulator
---------------------

angr can run the program on one of two emulators.

``"unicorn"``
   The default. It uses `Unicorn <https://www.unicorn-engine.org/>`_, the
   emulator that the rest of angr uses for fast concrete execution.

``"icicle"``
   It uses `Icicle <https://github.com/icicle-emu/icicle-emu>`_. On packed
   programs it is usually between 10 and 30 times faster than Unicorn, which
   decides whether a heavily protected program can be unpacked within the time
   limit at all.

   Icicle takes its description of x86 instructions from the ``pypcode``
   package. Until ``pypcode`` includes a number of corrections to that
   description, Icicle computes a few uncommon instructions incorrectly. This
   is why it is not the default yet.

Three options only have an effect with ``engine="icicle"``:

``icicle_jit`` (default ``True``)
   Whether Icicle translates code that runs often into native machine code.
   Turning it off makes Icicle interpret every instruction, which is slower
   but can help when you suspect a problem in the translation.

``icicle_jit_threshold`` (default ``32``)
   How many times a piece of code must run before Icicle translates it. A
   packed program runs most of its start-up code only a few times, so
   translating all of it would cost more time than it saves.

``icicle_thread_slice`` (default ``4000000``)
   When the program has more than one thread, how many instructions one
   thread runs before the next thread gets its turn.

Identifying the Protection
--------------------------

``PackerIdentifier`` reads the file and reports how it is protected. It does
not run the program, so it finishes in a fraction of a second.

.. code-block:: python

   >>> p = angr.Project("../binaries/tests/x86_64/windows/Project1.vmp.exe", auto_load_libs=False)
   >>> identifier = p.analyses.PackerIdentifier()
   >>> identifier.protector
   'VMProtect'
   >>> identifier.packed
   False
   >>> identifier.info.reason
   'original code is readable on disk (35 repeated call targets)'

``protector``
   ``"VMProtect"``, ``"Themida"``, ``"Themida+VMProtect"``, or ``None`` if
   neither was recognized.

``packed``
   ``True`` if the real code is packed, ``False`` if it is readable in the
   file, and ``None`` if the file does not give a clear answer.

``info``
   A ``PackerInfo`` object with the details. Besides ``protector`` and
   ``packed`` it has:

   * ``outer_packer``: the name of a common compression tool (UPX, MPRESS,
     ASPack, PECompact, Petite, NsPack, Enigma or MEW) if the file was
     compressed with one, possibly on top of VMProtect or Themida.
   * ``reason``: one sentence that explains the value of ``packed``.
   * ``evidence``: the signs that led to the value of ``protector``.
   * ``sections``: measurements of each section of the file, such as its
     size and how random its bytes look.

The example above shows that a protected file is not always a packed file.
VMProtect and Themida can also rewrite chosen functions into a private
instruction set that only their own interpreter understands, and leave the
rest of the program readable. Unpacking does not undo that rewriting. For such
a file ``packed`` is ``False`` and ``Unpacker`` returns nothing.

The Individual Unpackers
------------------------

You can also create an unpacker directly instead of letting ``Unpacker``
choose. All three have the results described under `Results`_, except
``info`` and ``unpacker``.

GenericUnpacker
^^^^^^^^^^^^^^^

``GenericUnpacker`` makes no assumption about the tool that packed the file.
It runs the program and watches every section that the start-up code might
restore. When the program jumps into a section whose contents changed since
the program started, the unpacker saves the program's memory and reports the
target of the jump as the original entry point.

Its extra option ``settle_timeout`` (default 20 seconds) is how long the
program keeps running after that moment, in case it was packed more than
once.

.. code-block:: python

   >>> unpacker = p.analyses.GenericUnpacker(timeout=60, settle_timeout=5)

VMProtectUnpacker
^^^^^^^^^^^^^^^^^

``VMProtectUnpacker`` knows which sections of a VMProtect-protected file
belong to the real program and watches only those. If running the program
does not reach the original entry point, it falls back to decompressing the
file without running it, as ``VMProtectStaticUnpacker`` does.

``method``
   ``"emulation"`` if running the program worked, ``"static"`` if the
   fallback was used, or ``None`` if both failed.

``static_only``
   Pass ``static_only=True`` to skip running the program and use only the
   fallback.

.. code-block:: python

   >>> p = angr.Project(
   ...     "../binaries/tests/i386/windows/unpacker/vmprotect_like_plain_table.exe", auto_load_libs=False
   ... )
   >>> unpacker = p.analyses.VMProtectUnpacker(timeout=30)
   >>> unpacker.method
   'static'

ThemidaUnpacker
^^^^^^^^^^^^^^^

``ThemidaUnpacker`` handles files protected with Themida or WinLicense. It
watches only the sections of the real program, so Themida's long start-up
(checks for debuggers, helper threads, several rounds of decryption) is not
mistaken for the real program. This start-up can take minutes even on the
faster emulator, which is why the default time limit is 30 minutes.

VMProtectStaticUnpacker
^^^^^^^^^^^^^^^^^^^^^^^

``VMProtectStaticUnpacker`` does not run the program. VMProtect keeps a table
in the file that says where each compressed section is stored; this analysis
finds the table and decompresses the sections.

It is fast and cannot be stopped by the tricks VMProtect uses against
emulators, but it gives a less complete result: the code is readable, yet the
file's entry point still points at VMProtect's start-up code and the import
table is not rebuilt. It raises ``VMProtectStaticError`` if it cannot find the
table.

.. code-block:: python

   >>> static = p.analyses.VMProtectStaticUnpacker()

   # the number of bytes decompressed into each section
   >>> static.result.blocks
   {'.text': 6144, '.rdata': 1984, '.vmp0': 1024}
   >>> len(static.unpacked)
   24576

Programs Packed More Than Once
------------------------------

A program can be packed several times, for example compressed first and then
protected with another tool. Running it then restores the code in several
steps. Each time the program jumps into newly restored code, the unpacker
saves the program's memory. Each of these snapshots is called a *layer*, and
``layers`` lists them in the order they were taken.

``unpacked`` and ``oep`` come from the layer that is most likely the real
program. You can look at the others yourself:

.. code-block:: python

   >>> p = angr.Project("../binaries/tests/i386/windows/unpacker/xor_packed.exe", auto_load_libs=False)
   >>> unpacker = p.analyses.GenericUnpacker()
   >>> for layer in unpacker.layers:
   ...     print(hex(layer.oep), layer.section, layer.seconds < 60)
   0x401800 .text True

   # build an executable file from any layer
   >>> data = unpacker.layers[0].rebuild(p.loader.main_object.mapped_base)

Each layer has these attributes:

* ``oep``: the address the program jumped to. It is ``None`` for a snapshot
  that was taken at the end of a run in which the program restored its code
  but never jumped into it.
* ``section``: the name of the section that contains that address.
* ``seconds``: how long the program had been running when the snapshot was
  taken.
* ``image``: the program's memory at that moment.
* ``imports``: the Windows functions that were recovered for the import
  table.
* ``entropy``: how random the bytes of the section look, from 0 to 8.
  Readable code is usually below 7; compressed or encrypted data is close
  to 8.

Choosing the Lists of Windows Functions
---------------------------------------

A packed program looks up the Windows functions it needs while it runs, and
some programs check that a system library offers exactly the functions the
real Windows library offers. For this reason the emulator needs to know which
functions each Windows library contains. The ``angr-data`` package ships these
lists, one JSON file per library.

Pass ``exports_dir`` to use a directory with your own lists instead, for
example lists taken from a different version of Windows:

.. code-block:: python

   >>> unpacker = p.analyses.Unpacker(exports_dir="/path/to/my/lists")

After a run, ``unlisted_exports`` names the functions the program asked for
that the lists did not contain. An entry there is not always a mistake in the
lists: some programs ask for functions that do not exist to find out whether
they are being analyzed.

Limitations
-----------

* The emulator imitates Windows; it is not Windows. It implements the Windows
  functions that packed programs commonly call, but a program can call one
  that is missing or behaves slightly differently. When that happens,
  ``stop.reason`` is usually ``StopReason.ERROR`` and ``stop.detail`` names
  the problem.
* Protection tools try to detect emulators and debuggers. angr answers the
  checks it knows about, but a program may still notice and quit early. In
  that case ``stop.reason`` is ``StopReason.EXITED`` and ``oep`` is ``None``.
* Functions that a protection tool rewrote into its private instruction set
  stay rewritten in the unpacked file.
* The rebuilt import table can be incomplete, because protection tools hide
  the calls to Windows functions in several ways and not all of them can be
  traced back.
* Only Windows executables for x86 and x86-64 processors are supported.
