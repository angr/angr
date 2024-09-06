Intermediate Representation
===========================

In order to be able to analyze and execute machine code from different CPU
architectures, such as MIPS, ARM, and PowerPC in addition to the classic x86,
angr performs most of its analysis on an *intermediate representation*, a
structured description of the fundamental actions performed by each CPU
instruction. By understanding angr's IR, VEX (which we borrowed from Valgrind),
you will be able to write very quick static analyses and have a better
understanding of how angr works.

The VEX IR abstracts away several architecture differences when dealing with
different architectures, allowing a single analysis to be run on all of them:


* **Register names.** The quantity and names of registers differ between
  architectures, but modern CPU designs hold to a common theme: each CPU
  contains several general purpose registers, a register to hold the stack
  pointer, a set of registers to store condition flags, and so forth. The IR
  provides a consistent, abstracted interface to registers on different
  platforms. Specifically, VEX models the registers as a separate memory space,
  with integer offsets (e.g., AMD64's ``rax`` is stored starting at address 16
  in this memory space).
* **Memory access.** Different architectures access memory in different ways.
  For example, ARM can access memory in both little-endian and big-endian modes.
  The IR abstracts away these differences.
* **Memory segmentation.** Some architectures, such as x86, support memory
  segmentation through the use of special segment registers. The IR understands
  such memory access mechanisms.
* **Instruction side-effects.** Most instructions have side-effects. For
  example, most operations in Thumb mode on ARM update the condition flags, and
  stack push/pop instructions update the stack pointer. Tracking these
  side-effects in an *ad hoc* manner in the analysis would be crazy, so the IR
  makes these effects explicit.

There are lots of choices for an IR. We use VEX, since the uplifting of binary
code into VEX is quite well supported. VEX is an architecture-agnostic,
side-effects-free representation of a number of target machine languages. It
abstracts machine code into a representation designed to make program analysis
easier. This representation has four main classes of objects:


* **Expressions.** IR Expressions represent a calculated or constant value. This
  includes memory loads, register reads, and results of arithmetic operations.
* **Operations.** IR Operations describe a *modification* of IR Expressions.
  This includes integer arithmetic, floating-point arithmetic, bit operations,
  and so forth. An IR Operation applied to IR Expressions yields an IR
  Expression as a result.
* **Temporary variables.** VEX uses temporary variables as internal registers:
  IR Expressions are stored in temporary variables between use. The content of a
  temporary variable can be retrieved using an IR Expression. These temporaries
  are numbered, starting at ``t0``. These temporaries are strongly typed (e.g.,
  "64-bit integer" or "32-bit float").
* **Statements.** IR Statements model changes in the state of the target
  machine, such as the effect of memory stores and register writes. IR
  Statements use IR Expressions for values they may need. For example, a memory
  store *IR Statement* uses an *IR Expression* for the target address of the
  write, and another *IR Expression* for the content.
* **Blocks.** An IR Block is a collection of IR Statements, representing an
  extended basic block (termed "IR Super Block" or "IRSB") in the target
  architecture. A block can have several exits. For conditional exits from the
  middle of a basic block, a special *Exit* IR Statement is used. An IR
  Expression is used to represent the target of the unconditional exit at the
  end of the block.

VEX IR is actually quite well documented in the ``libvex_ir.h`` file
(https://github.com/angr/vex/blob/master/pub/libvex_ir.h) in the VEX repository.
For the lazy, we'll detail some parts of VEX that you'll likely interact with
fairly frequently. To begin with, here are some IR Expressions:

.. list-table::
   :header-rows: 1

   * - IR Expression
     - Evaluated Value
     - VEX Output Example
   * - Constant
     - A constant value.
     - 0x4:I32
   * - Read Temp
     - The value stored in a VEX temporary variable.
     - RdTmp(t10)
   * - Get Register
     - The value stored in a register.
     - GET:I32(16)
   * - Load Memory
     - The value stored at a memory address, with the address specified by
       another IR Expression.
     - LDle:I32 / LDbe:I64
   * - Operation
     - A result of a specified IR Operation, applied to specified IR Expression
       arguments.
     - Add32
   * - If-Then-Else
     - If a given IR Expression evaluates to 0, return one IR Expression.
       Otherwise, return another.
     - ITE
   * - Helper Function
     - VEX uses C helper functions for certain operations, such as computing the
       conditional flags registers of certain architectures. These functions
       return IR Expressions.
     - function_name()


These expressions are then, in turn, used in IR Statements. Here are some common ones:

.. list-table::
   :header-rows: 1

   * - IR Statement
     - Meaning
     - VEX Output Example
   * - Write Temp
     - Set a VEX temporary variable to the value of the given IR Expression.
     - WrTmp(t1) = (IR Expression)
   * - Put Register
     - Update a register with the value of the given IR Expression.
     - PUT(16) = (IR Expression)
   * - Store Memory
     - Update a location in memory, given as an IR Expression, with a value,
       also given as an IR Expression.
     - STle(0x1000) = (IR Expression)
   * - Exit
     - A conditional exit from a basic block, with the jump target specified by
       an IR Expression. The condition is specified by an IR Expression.
     - if (condition) goto (Boring) 0x4000A00:I32


An example of an IR translation, on ARM, is produced below. In the example, the
subtraction operation is translated into a single IR block comprising 5 IR
Statements, each of which contains at least one IR Expression (although, in real
life, an IR block would typically consist of more than one instruction).
Register names are translated into numerical indices given to the *GET*
Expression and *PUT* Statement. The astute reader will observe that the actual
subtraction is modeled by the first 4 IR Statements of the block, and the
incrementing of the program counter to point to the next instruction (which, in
this case, is located at ``0x59FC8``) is modeled by the last statement.

The following ARM instruction:

.. code-block::

   subs R2, R2, #8


Becomes this VEX IR:

.. code-block::

   t0 = GET:I32(16)
   t1 = 0x8:I32
   t3 = Sub32(t0,t1)
   PUT(16) = t3
   PUT(68) = 0x59FC8:I32


Now that you understand VEX, you can actually play with some VEX in angr: We use
a library called `PyVEX <https://github.com/angr/pyvex>`_ that exposes VEX into
Python. In addition, PyVEX implements its own pretty-printing so that it can
show register names instead of register offsets in PUT and GET instructions.

PyVEX is accessible through angr through the ``Project.factory.block``
interface. There are many different representations you could use to access
syntactic properties of a block of code, but they all have in common the trait
of analyzing a particular sequence of bytes. Through the ``factory.block``
constructor, you get a ``Block`` object that can be easily turned into several
different representations. Try ``.vex`` for a PyVEX IRSB, or ``.capstone`` for a
Capstone block.

Let's play with PyVEX:

.. code-block:: python

   >>> import angr

   # load the program binary
   >>> proj = angr.Project("/bin/true")

   # translate the starting basic block
   >>> irsb = proj.factory.block(proj.entry).vex
   # and then pretty-print it
   >>> irsb.pp()

   # translate and pretty-print a basic block starting at an address
   >>> irsb = proj.factory.block(0x401340).vex
   >>> irsb.pp()

   # this is the IR Expression of the jump target of the unconditional exit at the end of the basic block
   >>> print(irsb.next)

   # this is the type of the unconditional exit (e.g., a call, ret, syscall, etc)
   >>> print(irsb.jumpkind)

   # you can also pretty-print it
   >>> irsb.next.pp()

   # iterate through each statement and print all the statements
   >>> for stmt in irsb.statements:
   ...     stmt.pp()

   # pretty-print the IR expression representing the data, and the *type* of that IR expression written by every store statement
   >>> import pyvex
   >>> for stmt in irsb.statements:
   ...     if isinstance(stmt, pyvex.IRStmt.Store):
   ...         print("Data:",)
   ...         stmt.data.pp()
   ...         print("")
   ...         print("Type:",)
   ...         print(stmt.data.result_type)
   ...         print("")

   # pretty-print the condition and jump target of every conditional exit from the basic block
   >>> for stmt in irsb.statements:
   ...     if isinstance(stmt, pyvex.IRStmt.Exit):
   ...         print("Condition:",)
   ...         stmt.guard.pp()
   ...         print("")
   ...         print("Target:",)
   ...         stmt.dst.pp()
   ...         print("")

   # these are the types of every temp in the IRSB
   >>> print(irsb.tyenv.types)

   # here is one way to get the type of temp 0
   >>> print(irsb.tyenv.types[0])

Condition flags computation (for x86 and ARM)
---------------------------------------------

One of the most common instruction side-effects on x86 and ARM CPUs is updating
condition flags, such as the zero flag, the carry flag, or the overflow flag.
Computer architects usually put the concatenation of these flags (yes,
concatenation of the flags, since each condition flag is 1 bit wide) into a
special register (i.e. ``EFLAGS``/``RFLAGS`` on x86, ``APSR``/``CPSR`` on ARM).
This special register stores important information about the program state, and
is critical for correct emulation of the CPU.

VEX uses 4 registers as its "Flag thunk descriptors" to record details of the
latest flag-setting operation. VEX has a lazy strategy to compute the flags:
when an operation that would update the flags happens, instead of computing the
flags, VEX stores a code representing this operation to the ``cc_op``
pseudo-register, and the arguments to the operation in ``cc_dep1`` and
``cc_dep2``. Then, whenever VEX needs to get the actual flag values, it can
figure out what the one bit corresponding to the flag in question actually is,
based on its flag thunk descriptors. This is an optimization in the flags
computation, as VEX can now just directly perform the relevant operation in the
IR without bothering to compute and update the flags' value.

Amongst different operations that can be placed in ``cc_op``, there is a special
value 0 which corresponds to ``OP_COPY`` operation. This operation is supposed
to copy the value in ``cc_dep1`` to the flags. It simply means that ``cc_dep1``
contains the flags' value. angr uses this fact to let us efficiently retrieve
the flags' value: whenever we ask for the actual flags, angr computes their
value, then dumps them back into ``cc_dep1`` and sets ``cc_op = OP_COPY`` in
order to cache the computation. We can also use this operation to allow the user
to write to the flags: we just set ``cc_op = OP_COPY`` to say that a new value
being set to the flags, then set ``cc_dep1`` to that new value.
