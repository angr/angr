Working with File System, Sockets, and Pipes
============================================

It's very important to be able to control the environment that emulated programs
see, including how symbolic data is introduced from the environment! angr has a
robust series of abstractions to help you set up the environment you want.

The root of any interaction with the filesystem, sockets, pipes, or terminals is
a SimFile object. A SimFile is a *storage* abstraction that defines a sequence
of bytes, symbolic or otherwise. There are several kinds of SimFiles which store
their data very differently - the two easiest examples are ``SimFile`` (the base
class is actually called ``SimFileBase``), which stores files as a flat
address-space of data, and ``SimPackets``, which stores a sequence of
variable-sized reads. The former is best for modeling programs that need to
perform seeks on their files, and is the default storage for opened files, while
the latter is best for modeling programs that depend on short-reads or use
scanf, and is the default storage for stdin/stdout/stderr.

Because SimFiles can have such diverse storage mechanisms, the interface for
interacting with them is *very* abstracted. You can read from the file from some
position, you can write to the file at some position, you can ask how many bytes
are currently stored in the file, and you can concretize the file, generating a
testcase for it. If you know specifically which SimFile class you're working
with, you can take much more powerful control over it, and as a result you're
encouraged to manually create any files you want to work with when you create
your initial state.

Specifically, each SimFile class creates its own abstraction of a "position"
within the file - each read and write takes a position and returns a new
position that you should use to continue from where you left off. If you're
working with SimFiles of unknown type you have to treat this position as a
totally opaque object with no semantics other than the contract with the
read/write functions.

However! This is a very poor match to how programs generally interact with
files, so angr also has a SimFileDescriptor abstraction, which provides the
familiar read/write/seek/tell interfaces but will also return error conditions
when the underlying storage don't support the appropriate operations - just like
normal file descriptors!

You may access the mapping from file descriptor number to file descriptor object
in ``state.posix.fd``. The file descriptor API may be found `here
<http://angr.io/api-doc/angr.html#angr.storage.file.SimFileDescriptorBase>`_.

Just tell me how to do what I want to do!
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Okay okay!!

To create a SimFile, you should just create an instance of the class you want to
use. Refer to the `API docs
<http://angr.io/api-doc/angr.html#module-angr.storage.file>`_ for the full
instructions.

Let's go through a few illustrative examples, which cover how you can work with
a concrete file, a symbolic file, a file with mixed concrete and symbolic
content, or streams.

Example 1: Create a file with concrete content
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   >>> import angr
   >>> simfile = angr.SimFile('myconcretefile', content='hello world!\n')

Here's a nuance - you can't use SimFiles without a state attached, because
reasons. You'll **never** have to do this in a real scenario (this operation
happens automatically when you pass a SimFile into a constructor or the
filesystem) but let's mock it up:

.. code-block:: python

   >>> proj = angr.Project('/bin/true')
   >>> state = proj.factory.blank_state()
   >>> simfile.set_state(state)

To demonstrate the behavior of these files we're going to use the fact that the
default SimFile position is just the number of bytes from the start of the file.
``SimFile.read`` returns a tuple (bitvector data, actual size, new pos):

.. code-block:: python

   >>> data, actual_size, new_pos = simfile.read(0, 5)
   >>> import claripy
   >>> assert claripy.is_true(data == 'hello')
   >>> assert claripy.is_true(actual_size == 5)
   >>> assert claripy.is_true(new_pos == 5)

Continue the read, trying to read way too much:

.. code-block:: python

   >>> data, actual_size, new_pos = simfile.read(new_pos, 1000)

angr doesn't try to sanitize the data returned, only the size - we returned 1000
bytes! The intent is that you're only allowed to use up to actual_size of them.

.. code-block:: python

   >>> assert len(data) == 1000*8  # bitvector sizes are in bits
   >>> assert claripy.is_true(actual_size == 8)
   >>> assert claripy.is_true(data.get_bytes(0, 8) == ' world!\n')
   >>> assert claripy.is_true(new_pos == 13)

Example 2: Create a file with symbolic content and a defined size
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   >>> simfile = angr.SimFile('mysymbolicfile', size=0x20)
   >>> simfile.set_state(state)

   >>> data, actual_size, new_pos = simfile.read(0, 0x30)
   >>> assert data.symbolic
   >>> assert claripy.is_true(actual_size == 0x20)

The basic SimFile provides the same interface as ``state.memory``, so you can load data directly:

.. code-block:: python

   >>> assert simfile.load(0, actual_size) is data.get_bytes(0, 0x20)

Example 3: Create a file with constrained symbolic content
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   >>> bytes_list = [claripy.BVS('byte_%d' % i, 8) for i in range(32)]
   >>> bytes_ast = claripy.Concat(*bytes_list)
   >>> mystate = proj.factory.entry_state(stdin=angr.SimFile('/dev/stdin', content=bytes_ast))
   >>> for byte in bytes_list:
   ...     mystate.solver.add(byte >= 0x20)
   ...     mystate.solver.add(byte <= 0x7e)

Example 4: Create a file with some mixed concrete and symbolic content, but no EOF
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   >>> variable = claripy.BVS('myvar', 10*8)
   >>> simfile = angr.SimFile('mymixedfile', content=variable.concat(claripy.BVV('\n')), has_end=False)
   >>> simfile.set_state(state)

We can always query the number of bytes stored in the file:

.. code-block:: python

   >>> assert claripy.is_true(simfile.size == 11)

Reads will generate additional symbolic data past the current frontier:

.. code-block:: python

   >>> data, actual_size, new_pos = simfile.read(0, 15)
   >>> assert claripy.is_true(actual_size == 15)
   >>> assert claripy.is_true(new_pos == 15)

   >>> assert claripy.is_true(data.get_bytes(0, 10) == variable)
   >>> assert claripy.is_true(data.get_bytes(10, 1) == '\n')
   >>> assert data.get_bytes(11, 4).symbolic

Example 5: Create a file with a symbolic size (``has_end`` is implicitly true here)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   >>> symsize = claripy.BVS('mysize', 64)
   >>> state.solver.add(symsize >= 10)
   >>> state.solver.add(symsize < 20)
   >>> simfile = angr.SimFile('mysymsizefile', size=symsize)
   >>> simfile.set_state(state)

Reads will encode all possibilities:

.. code-block:: python

   >>> data, actual_size, new_pos = simfile.read(0, 30)
   >>> assert set(state.solver.eval_upto(actual_size, 30)) == set(range(10, 20))

The maximum size can't be easily resolved, so the data returned is 30 bytes long, and we're supposed to use it conjunction with actual_size.

.. code-block:: python

   >>> assert len(data) == 30*8

Symbolic read sizes work too!

.. code-block:: python

   >>> symreadsize = claripy.BVS('myreadsize', 64)
   >>> state.solver.add(symreadsize >= 5)
   >>> state.solver.add(symreadsize < 30)
   >>> data, actual_size, new_pos = simfile.read(0, symreadsize)

All sizes between 5 and 20 should be possible:

.. code-block:: python

   >>> assert set(state.solver.eval_upto(actual_size, 30)) == set(range(5, 20))

Example 6: Working with streams (``SimPackets``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

So far, we've only used the SimFile class, which models a random-accessible file
object. However, in real life, files are not everything. Streams (standard I/O,
TCP, etc.) are a great example: While they hold data like a normal file does,
they do not support random accesses, e.g., you cannot read out the second byte
of stdin if you have already read passed that position, and you cannot modify
any byte that has been previously sent out to a network endpoint. This allows us
to design a simpler abstraction for streams in angr.

Believe it or not, this simpler abstraction for streams will benefit symbolic
execution. Consider an example program that calls ``scanf`` N times to read in N
strings. With a traditional SimFile, as we do not know the length of each input
string, there does not exist any clear boundary in the file between these
symbolic input strings. In this case, angr will perform N symbolic reads where
each read will generate a gigantic tree of claripy ASTs, with string lengths
being symbolic. This is a nightmare for constraint solving. Nevertheless, the
fact that ``scanf`` is used on a stream (stdin) dictates that there will be zero
overlap between individual reads, regardless of the sizes of each symbolic input
string. We may as well model stdin as a stream that comprises of *consecutive
packets*, instead of a file containing a sequence of bytes. Each of the packet
can be of a fixed length or a symbolic length. Since there will be absolutely no
byte overlap between packets, the constraints that angr will produce after
executing this example program will be a lot simpler.

The key concept involved is "short reads", i.e. when you ask for ``n`` bytes but
actually get back fewer bytes than that. We use a different class implementing
SimFileBase, ``SimPackets``, to automatically enable support for short reads. By
default, stdin, stdout, and stderr are all SimPackets objects.

.. code-block:: python

   >>> simfile = angr.SimPackets('mypackets')
   >>> simfile.set_state(state)

This'll just generate a single packet. For SimPackets, the position is just a
packet number! If left unspecified, short_reads is determined from a state
option.

.. code-block:: python

   >>> data, actual_size, new_pos = simfile.read(0, 20, short_reads=True)
   >>> assert len(data) == 20*8
   >>> assert set(state.solver.eval_upto(actual_size, 30)) == set(range(21))

Data in a SimPackets is stored as tuples of (packet data, packet size) in
``.content``.

.. code-block:: python

   >>> print(simfile.content)
   [(<BV160 packet_0_mypackets>, <BV64 packetsize_0_mypackets>)]

   >>> simfile.read(0, 1, short_reads=False)
   >>> print(simfile.content)
   [(<BV160 packet_0_mypackets>, <BV64 packetsize_0_mypackets>), (<BV8 packet_1_mypackets>, <BV64 0x1>)]

So hopefully you understand sort of the kind of data that a SimFile can store
and what'll happen when a program tries to interact with it with various
combinations of symbolic and concrete data. Those examples only covered reads,
but writes are pretty similar.

The filesystem, for real now
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you want to make a SimFile available to the program, we need to either stick
it in the filesystem or serve stdin/stdout from it.

The simulated filesystem is the ``state.fs`` plugin. You can store, load, and
delete files from the filesystem, with the ``insert``, ``get``, and ``delete``
methods. Refer to the `api docs
<http://angr.io/api-doc/angr.html#module-angr.state_plugins.filesystem>`_ for
details.

So to make our file available as ``/tmp/myfile``:

.. code-block:: python

   >>> state.fs.insert('/tmp/myfile', simfile)
   >>> assert state.fs.get('/tmp/myfile') is simfile

Then, after execution, we would extract the file from the result state and use
``simfile.concretize()`` to generate a testcase to reach that state. Keep in
mind that ``concretize()`` returns different types depending on the file type -
for a SimFile it's a bytestring and for SimPackets it's a list of bytestrings.

The simulated filesystem supports a fun concept of "mounts", where you can
designate a subtree as instrumented by a particular provider. The most common
mount is to expose a part of the host filesystem to the guest, lazily importing
file data when the program asks for it:

.. code-block:: python

   >>> state.fs.mount('/', angr.SimHostFilesystem('./guest_chroot'))

You can write whatever kind of mount you want to instrument filesystem access by
subclassing ``angr.SimMount``!

Stdio streams
^^^^^^^^^^^^^

For stdin and friends, it's a little more complicated. The relevant plugin is
``state.posix``, which stores all abstractions relevant to a POSIX-compliant
environment. You can always get a state's stdin SimFile with
``state.posix.stdin``, but you can't just replace it - as soon as the state is
created, references to this file are created in the file descriptors. Because of
this you need to specify it at the time the POSIX plugin is created:

.. code-block:: python

   >>> state.register_plugin('posix', angr.state_plugins.posix.SimSystemPosix(stdin=simfile, stdout=simfile, stderr=simfile))
   >>> assert state.posix.stdin is simfile
   >>> assert state.posix.stdout is simfile
   >>> assert state.posix.stderr is simfile

Or, there's a nice shortcut while creating the state if you only need to specify
stdin:

.. code-block:: python

   >>> state = proj.factory.entry_state(stdin=simfile)
   >>> assert state.posix.stdin is simfile

Any of those places you can specify a SimFileBase, you can also specify a string
or a bitvector (a flat SimFile with fixed size will be created to hold it) or a
SimFile type (it'll be instantiated for you).
