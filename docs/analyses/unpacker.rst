Unpacking Windows Executables
=============================

Many Windows programs and most Windows malware are *packed*. A packed program
stores the real code compressed or encrypted inside the file. A small piece of
start-up code restores the real code in memory each time the program starts.
A disassembler or a decompiler only shows the start-up code and a block of
unreadable data when we open a packed file.

*Unpacking* means getting the real code back. angr unpacks a program in three
steps. First, angr runs the program inside an emulator. Second, angr waits
until the start-up code has restored the real code and jumps to the real code.
Third, angr saves the memory of the program as a new executable file that
other analyses can load.

angr never runs the program on your processor or your operating system. The
program only runs inside the emulator of angr, in a simulated Windows 7
process that angr builds for the program. The program cannot touch your files,
your network or your machine.

The analyses on this page work on 32-bit and 64-bit Windows executables, which
are also called PE files. The executable must be loaded from a file on disk.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Analysis
     - What the analysis does
   * - ``Unpacker``
     - This analysis finds out how the file is protected and runs the matching
       unpacker. Start with this analysis.
   * - ``PackerIdentifier``
     - This analysis reports which protection tool was used and whether the
       real code is packed. This analysis does not run the program.
   * - ``GenericUnpacker``
     - This analysis unpacks a file without knowing which tool packed the
       file.
   * - ``VMProtectUnpacker``
     - This analysis unpacks files that are protected with VMProtect.
   * - ``ThemidaUnpacker``
     - This analysis unpacks files that are protected with Themida or
       WinLicense.
   * - ``VMProtectStaticUnpacker``
     - This analysis decompresses a VMProtect-packed file without running the
       program.

A Few Terms
-----------

Original entry point
   The original entry point is the address where the real program starts. The
   start-up code jumps to the original entry point after the start-up code
   has restored the real code. This page and the code also call the original
   entry point the OEP.

Section
   A section is a named region of an executable file. For example, ``.text``
   holds code and ``.data`` holds data.

Import table
   The import table is the list of Windows functions that a program uses.
   Windows writes the addresses of these functions into the import table when
   the program starts. Packers usually remove the import table and look the
   functions up themselves, so an unpacker has to rebuild the import table.

Unpacking a File
----------------

Use ``Unpacker`` when you do not know how a file is protected. The analysis
runs when you create the analysis.

.. code-block:: python

   >>> import angr
   >>> p = angr.Project("../binaries/tests/i386/windows/unpacker/xor_packed.exe", auto_load_libs=False)
   >>> unpacker = p.analyses.Unpacker()

   # the address where the real program starts
   >>> hex(unpacker.oep)
   '0x401800'

   # the bytes of the unpacked executable file
   >>> with open("xor_packed.unpacked.exe", "wb") as f:
   ...     f.write(unpacker.unpacked)
   16384

   # we can load the unpacked file like any other program
   >>> unpacked = angr.Project("xor_packed.unpacked.exe", auto_load_libs=False)
   >>> hex(unpacked.entry)
   '0x401800'

The saved file is meant for analysis. The code of the saved file is readable.
The entry point of the saved file is the original entry point. The import
table is rebuilt where angr could recover the imported functions. The saved
file is not guaranteed to run on a real Windows machine.

Results
^^^^^^^

``unpacked``
   The bytes of the unpacked executable file. ``unpacked`` is ``None`` if
   nothing was unpacked.

``oep``
   The original entry point. ``oep`` is ``None`` if the program never jumped
   into restored code.

``info``
   What ``Unpacker`` found out about the protection of the file before running
   the program. See `Identifying the Protection`_.

``unpacker``
   The analysis that did the work, which is a ``GenericUnpacker``, a
   ``VMProtectUnpacker`` or a ``ThemidaUnpacker``. ``unpacker`` is ``None`` if
   the file is not packed. Only ``Unpacker`` has this attribute.

``stop``
   Why the emulated program stopped running. ``stop.reason`` is one of the
   values in the table below. ``stop.addr`` is the address where the program
   stopped. ``stop.detail`` is a short description.

``layers``
   Every copy of the memory of the program that the unpacker saved during the
   run. See `Programs Packed More Than Once`_.

``unlisted_exports``
   The functions that the program asked Windows for and that the lists of
   Windows functions do not contain. See
   `Choosing the Lists of Windows Functions`_.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - ``stop.reason``
     - Meaning
   * - ``StopReason.EXITED``
     - The program ended itself, for example by calling ``ExitProcess``.
   * - ``StopReason.RETURNED``
     - The entry function of the program returned.
   * - ``StopReason.BUDGET``
     - The time limit ran out.
   * - ``StopReason.ERROR``
     - The program crashed, or the program did something that the emulator
       cannot handle. ``stop.detail`` says what happened.
   * - ``StopReason.EXEC_TRAP``
     - The unpacker stopped the program right after the program jumped into
       restored code.

When a File Is Not Packed
^^^^^^^^^^^^^^^^^^^^^^^^^

If ``Unpacker`` can tell from the file alone that the real code is already
readable, ``Unpacker`` does not run the program.

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
   The longest time in seconds that the program may run. The default is 300
   seconds for ``GenericUnpacker``, 600 seconds for ``VMProtectUnpacker`` and
   1800 seconds for ``ThemidaUnpacker``. ``Unpacker`` uses the default of the
   unpacker that ``Unpacker`` picks unless you give a value.

``engine``
   The emulator that runs the program. The value is ``"unicorn"``, which is
   the default, or ``"icicle"``. See `Choosing the Emulator`_.

``exports_dir``
   A directory with your own lists of Windows functions. See
   `Choosing the Lists of Windows Functions`_.

``icicle_jit``, ``icicle_jit_threshold``, ``icicle_thread_slice``
   The settings of the Icicle emulator. See `Choosing the Emulator`_.

``GenericUnpacker`` also accepts ``settle_timeout``, and ``VMProtectUnpacker``
also accepts ``static_only``. The sections about these two unpackers describe
the two options.

.. code-block:: python

   >>> unpacker = p.analyses.Unpacker(timeout=120, engine="icicle")

Choosing the Emulator
---------------------

angr can run the program on one of two emulators.

``"unicorn"``
   This emulator is `Unicorn <https://www.unicorn-engine.org/>`_, which the
   rest of angr uses for fast concrete execution. Unicorn is the default
   emulator.

``"icicle"``
   This emulator is `Icicle <https://github.com/icicle-emu/icicle-emu>`_. On
   packed programs, Icicle is usually between 10 and 30 times faster than
   Unicorn. This speed decides whether angr can unpack a heavily protected
   program within the time limit.

   Icicle takes the description of x86 instructions from the ``pypcode``
   package. This description needs a number of corrections that ``pypcode``
   does not include yet. Without these corrections, Icicle computes a few
   uncommon instructions incorrectly, so Icicle is not the default emulator.

The following three options only have an effect with ``engine="icicle"``.

``icicle_jit``
   Whether Icicle translates code that runs often into native machine code.
   The default is ``True``. When ``icicle_jit`` is ``False``, Icicle
   interprets every instruction. Interpreting is slower, but turning
   ``icicle_jit`` off can help when you suspect a problem in the translation.

``icicle_jit_threshold``
   How many times a piece of code must run before Icicle translates the piece
   of code. The default is ``32``. A packed program runs most of the start-up
   code only a few times, so translating all of the start-up code would cost
   more time than the translation saves.

``icicle_thread_slice``
   How many instructions one thread runs before the next thread gets a turn.
   The default is ``4000000``. This option only matters when the program has
   more than one thread.

Identifying the Protection
--------------------------

``PackerIdentifier`` reads the file and reports how the file is protected.
``PackerIdentifier`` does not run the program, so the analysis finishes in a
fraction of a second.

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
   ``"VMProtect"``, ``"Themida"`` or ``"Themida+VMProtect"``. ``protector`` is
   ``None`` if ``PackerIdentifier`` recognized neither tool.

``packed``
   ``True`` if the real code is packed, and ``False`` if the real code is
   readable in the file. ``packed`` is ``None`` if the file does not give a
   clear answer.

``info``
   A ``PackerInfo`` object with the details. ``PackerInfo`` has ``protector``,
   ``packed`` and the four attributes below.

``info.outer_packer``
   The name of a common compression tool if the file was compressed with one.
   The file may be compressed on top of VMProtect or Themida. The tools that
   ``PackerIdentifier`` recognizes are UPX, MPRESS, ASPack, PECompact, Petite,
   NsPack, Enigma and MEW.

``info.reason``
   One sentence that explains the value of ``packed``.

``info.evidence``
   The signs that led to the value of ``protector``.

``info.sections``
   Measurements of each section of the file, such as the size of the section
   and how random the bytes of the section look.

The example above shows that a protected file is not always a packed file.
VMProtect and Themida can also rewrite chosen functions into a private
instruction set that only the interpreter of the protection tool understands.
The rest of the program stays readable. Unpacking does not undo this
rewriting. For a file that is protected in this way, ``packed`` is ``False``
and ``Unpacker`` returns nothing.

The Individual Unpackers
------------------------

You can also create an unpacker directly instead of letting ``Unpacker``
choose. All three unpackers have the results that `Results`_ describes, except
``info`` and ``unpacker``.

GenericUnpacker
^^^^^^^^^^^^^^^

``GenericUnpacker`` makes no assumption about the tool that packed the file.
``GenericUnpacker`` runs the program and watches every section that the
start-up code might restore. When the program jumps into a section whose
contents changed since the program started, ``GenericUnpacker`` saves the
memory of the program and reports the target of the jump as the original
entry point.

The extra option ``settle_timeout`` is how long the program keeps running
after this jump, in case the program was packed more than once. The default is
20 seconds.

.. code-block:: python

   >>> unpacker = p.analyses.GenericUnpacker(timeout=60, settle_timeout=5)

VMProtectUnpacker
^^^^^^^^^^^^^^^^^

``VMProtectUnpacker`` knows which sections of a VMProtect-protected file
belong to the real program and only watches these sections. If running the
program does not reach the original entry point, ``VMProtectUnpacker``
decompresses the file without running the program, as
``VMProtectStaticUnpacker`` does.

``method``
   ``"emulation"`` if running the program worked, and ``"static"`` if
   ``VMProtectUnpacker`` decompressed the file without running the program.
   ``method`` is ``None`` if both failed.

``static_only``
   Pass ``static_only=True`` to skip running the program.

.. code-block:: python

   >>> p = angr.Project(
   ...     "../binaries/tests/i386/windows/unpacker/vmprotect_like_plain_table.exe", auto_load_libs=False
   ... )
   >>> unpacker = p.analyses.VMProtectUnpacker(timeout=30)
   >>> unpacker.method
   'static'

ThemidaUnpacker
^^^^^^^^^^^^^^^

``ThemidaUnpacker`` unpacks files that are protected with Themida or
WinLicense. The start-up code of Themida is long. The start-up code checks for
debuggers, starts helper threads and decrypts in several rounds.
``ThemidaUnpacker`` only watches the sections of the real program, so the
unpacker does not mistake the start-up code of Themida for the real program.
The start-up code can take minutes even on the faster emulator, so the default
time limit is 30 minutes.

VMProtectStaticUnpacker
^^^^^^^^^^^^^^^^^^^^^^^

``VMProtectStaticUnpacker`` does not run the program. VMProtect keeps a table
in the file that says where each compressed section is stored.
``VMProtectStaticUnpacker`` finds this table and decompresses the sections.

``VMProtectStaticUnpacker`` is fast, and the tricks that VMProtect uses
against emulators cannot stop ``VMProtectStaticUnpacker``. The result is less
complete. The code is readable, but the entry point of the file still points
at the start-up code of VMProtect and the import table is not rebuilt.
``VMProtectStaticUnpacker`` raises ``VMProtectStaticError`` if the analysis
cannot find the table.

.. code-block:: python

   >>> static = p.analyses.VMProtectStaticUnpacker()

   # the number of bytes decompressed into each section
   >>> static.result.blocks
   {'.text': 6144, '.rdata': 1984, '.vmp0': 1024}
   >>> len(static.unpacked)
   24576

Programs Packed More Than Once
------------------------------

A program can be packed several times. For example, a program is compressed
first and then protected with another tool. Running a program that is packed
several times restores the code in several steps. Each time the program jumps
into newly restored code, the unpacker saves the memory of the program. Each
saved copy of the memory is called a *layer*. ``layers`` lists the layers in
the order in which the unpacker saved the layers.

``unpacked`` and ``oep`` come from the layer that is most likely the real
program. You can look at the other layers yourself.

.. code-block:: python

   >>> p = angr.Project("../binaries/tests/i386/windows/unpacker/xor_packed.exe", auto_load_libs=False)
   >>> unpacker = p.analyses.GenericUnpacker()
   >>> for layer in unpacker.layers:
   ...     print(hex(layer.oep), layer.section, layer.seconds < 60)
   0x401800 .text True

   # we can build an executable file from any layer
   >>> data = unpacker.layers[0].rebuild(p.loader.main_object.mapped_base)

Each layer has these attributes.

``oep``
   The address that the program jumped to. ``oep`` is ``None`` for a layer
   that the unpacker saved at the end of a run in which the program restored
   the code but never jumped into the restored code.

``section``
   The name of the section that contains the address in ``oep``.

``seconds``
   How long the program had been running when the unpacker saved the layer.

``image``
   The memory of the program when the unpacker saved the layer.

``imports``
   The Windows functions that the unpacker recovered for the import table.

``entropy``
   How random the bytes of the section look, from 0 to 8. Readable code is
   usually below 7. Compressed or encrypted data is close to 8.

Choosing the Lists of Windows Functions
---------------------------------------

A packed program looks up the Windows functions that the program needs while
the program runs. Some programs check that a system library offers exactly the
functions that the real Windows library offers. For this reason, the emulator
needs to know which functions each Windows library contains. The ``angr-data``
package ships these lists as one JSON file per library.

Pass ``exports_dir`` to use a directory with your own lists. For example, you
can use lists that were taken from a different version of Windows.

.. code-block:: python

   >>> unpacker = p.analyses.Unpacker(exports_dir="/path/to/my/lists")

After a run, ``unlisted_exports`` names the functions that the program asked
for and that the lists did not contain. An entry in ``unlisted_exports`` is
not always a mistake in the lists. Some programs ask for functions that do not
exist to find out whether the programs are being analyzed.

Limitations
-----------

* The emulator imitates Windows, but the emulator is not Windows. The emulator
  implements the Windows functions that packed programs commonly call. A
  program can call a function that is missing or that behaves slightly
  differently. When this happens, ``stop.reason`` is usually
  ``StopReason.ERROR`` and ``stop.detail`` names the problem.
* Protection tools try to detect emulators and debuggers. angr answers the
  checks that angr knows about, but a program may still notice the emulator
  and quit early. In this case, ``stop.reason`` is ``StopReason.EXITED`` and
  ``oep`` is ``None``.
* Functions that a protection tool rewrote into a private instruction set stay
  rewritten in the unpacked file.
* The rebuilt import table can be incomplete. Protection tools hide the calls
  to Windows functions in several ways, and angr cannot trace every hidden
  call back to a Windows function.
* angr only supports Windows executables for x86 and x86-64 processors.
