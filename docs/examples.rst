angr examples
=============

To help you get started with `angr <https://github.com/angr/angr>`_, we've
created several examples. We've tried to organize them into major categories,
and briefly summarize that each example will expose you to. Enjoy!

If you want a high-level cheatsheet of the "techniques" used in the examples,
see `the angr strategies cheatsheet
<https://github.com/bordig-f/angr-strategies/blob/master/angr_strategies.md>`_
by `Florent Bordignon <https://github.com/bordig-f>`_.

To jump to a specific category:

* :ref:`Introduction` - examples showing off the very basics of angr's functionality
* :ref:`Reversing` - examples showing angr being used in reverse engineering tasks
* :ref:`Vulnerability Discovery` - examples of angr being used to search for vulnerabilities
* :ref:`Exploitation` - examples of angr being used as an exploitation assistance tool

Introduction
------------

These are some introductory examples to give an idea of how to use angr's API.

Fauxware
^^^^^^^^

This is a basic script that explains how to use angr to symbolically execute a
program and produce concrete input satisfying certain conditions.

Binary, source, and script are found `here.
<https://github.com/angr/angr-examples/tree/master/examples/fauxware>`_

Reversing
---------

These are examples that use angr to solve reverse engineering challenges.
There are a lot of these.
We've chosen the most unique ones, and relegated the rest to the CTF Challenges section below.

Beginner reversing example: little_engine
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Michael Reeves (github: @mastermjr)
   Script runtime: 3 min 26 seconds (206 seconds)
   Concepts presented:
   stdin constraining, concrete optimization with Unicorn

This challenge is similar to the csaw challenge below, however the reversing is
much more simple. The original code, solution, and writeup for the challenge can
be found at the b01lers github `here
<https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_little_engine>`_.

The angr solution script is `here
<https://github.com/angr/angr-examples/tree/master/examples/b01lersctf2020_little_engine/solve.py>`_
and the binary is `here
<https://github.com/angr/angr-examples/tree/master/examples/b01lersctf2020_little_engine/engine>`_.

Whitehat CTF 2015 - Crypto 400
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Yan Shoshitaishvili (github: @Zardus)
   Script runtime: 30 seconds
   Concepts presented: statically linked binary (manually hooking with function summaries), commandline argument, partial solutions

We solved this crackme with angr's help. The resulting script will help you
understand how angr can be used for crackme *assistance*, not a full-out solve.
Since angr cannot solve the actual crypto part of the challenge, we use it just
to reduce the keyspace, and brute-force the rest.

You can find this script `here
<https://github.com/angr/angr-examples/tree/master/examples/whitehat_crypto400/solve.py>`_
and the binary `here
<https://github.com/angr/angr-examples/tree/master/examples/whitehat_crypto400/whitehat_crypto400>`_.

CSAW CTF 2015 Quals - Reversing 500, "wyvern"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Audrey Dutcher (github: @rhelmot)
   Script runtime: 15 mins
   Concepts presented: stdin constraining, concrete optimization with Unicorn

angr can outright solve this challenge with very little assistance from the
user. The script to do so is `here
<https://github.com/angr/angr-examples/tree/master/examples/csaw_wyvern/solve.py>_`
and the binary is `here
<https://github.com/angr/angr-examples/tree/master/examples/csaw_wyvern/wyvern>`_.

TUMCTF 2016 - zwiebel
^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Fish
   Script runtime: 2 hours 31 minutes with pypy and Unicorn - expect much longer with CPython only
   Concepts presented: self-modifying code support, concrete optimization with Unicorn

This example is of a self-unpacking reversing challenge. This example shows how
to enable Unicorn support and self-modification support in angr. Unicorn support
is essential to solve this challenge within a reasonable amount of time -
simulating the unpacking code symbolically is *very* slow. Thus, we execute it
concretely in unicorn/qemu and only switch into symbolic execution when needed.

You may refer to other writeup about the internals of this binary. I didn't
reverse too much since I was pretty confident that angr is able to solve it :-)

The long-term goal of optimizing angr is to execute this script within 10
minutes. Pretty ambitious :P

Here is the `binary
<https://github.com/angr/angr-examples/tree/master/examples/tumctf2016_zwiebel/zwiebel>`_
and the `script
<https://github.com/angr/angr-examples/tree/master/examples/tumctf2016_zwiebel/solve.py>`_.

FlareOn 2015 - Challenge 5
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Adrian Tang (github: @tangabc)
   Script runtime: 2 mins 10 secs
   Concepts presented: Windows support

This is another `reversing challenge
<https://github.com/angr/angr-examples/tree/master/examples/flareon2015_5/sender>`_
from the FlareOn challenges.

"The challenge is designed to teach you about PCAP file parsing and traffic
decryption by reverse engineering an executable used to generate it. This is a
typical scenario in our malware analysis practice where we need to figure out
precisely what the malware was doing on the network"

For this challenge, the author used angr to represent the desired encoded output
as a series of constraints for the SAT solver to solve for the input.

For a detailed write-up please visit the author's post `here
<http://0x0atang.github.io/reversing/2015/09/18/flareon5-concolic.html>`_ and
you can also find the solution from the FireEye `here
<https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution5.pdf>`_

0ctf quals 2016 - trace
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: WGH (wgh@bushwhackers.ru)
   Script runtime: 1 min 50 secs (CPython 2.7.10), 1 min 12 secs (PyPy 4.0.1)
   Concepts presented: guided symbolic tracing

In this challenge we're given a text file with trace of a program execution. The
file has two columns, address and instruction executed. So we know all the
instructions being executed, and which branches were taken. But the initial data
is not known.

Reversing reveals that a buffer on the stack is initialized with known constant
string first, then an unknown string is appended to it (the flag), and finally
it's sorted with some variant of quicksort. And we need to find the flag
somehow.

angr easily solves this problem. We only have to direct it to the right
direction at every branch, and the solver finds the flag at a glance.

Files are `here <https://github.com/angr/angr-examples/tree/master/examples/0ctf_trace>`_.

ASIS CTF Finals 2015 - license
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Fish Wang (github: @ltfish)
   Script runtime: 3.6 sec
   Concepts presented: using the filesystem, manual symbolic summary execution

This is a crackme challenge that reads a license file. Rather than hooking the
read operations of the flag file, we actually pass in a filesystem with the
correct file created.

Here is the `binary
<https://github.com/angr/angr-examples/tree/master/examples/asisctffinals2015_license/license>`_
and the `script
<https://github.com/angr/angr-examples/tree/master/examples/asisctffinals2015_license/solve.py>`_.

DEFCON Quals 2017 - Crackme2000
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Shellphish
   Script runtime: varies, but on the order of seconds
   Concepts presented: automated reverse engineering

DEFCON Quals had a whole category for automatic reversing in 2017. Our scripts
are `here
<https:////github.com/angr/angr-examples/tree/master/examples/defcon2017quals_crackme2000>`_.

Vulnerability Discovery
-----------------------

These are examples of angr being used to identify vulnerabilities in binaries.

Beginner vulnerability discovery example: strcpy_find
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Kyle Ossinger (github: @k0ss)
   Concepts presented: exploration to vulnerability, programmatic find condition

This is the first in a series of "tutorial scripts" I'll be making which use
angr to find exploitable conditions in binaries. The first example is a very
simple program. The script finds a path from the main entry point to ``strcpy``,
but **only** when we control the source buffer of the ``strcpy`` operation. To
hit the right path, angr has to solve for a password argument, but angr solved
this in less than 2 seconds on my machine using the standard Python interpreter.
The script might look large, but that's only because I've heavily commented it
to be more helpful to beginners. The challenge binary is `here
<https://github.com/angr/angr-examples/tree/master/examples/strcpy_find/strcpy_test>`_
and the script is `here
<https://github.com/angr/angr-examples/tree/master/examples/strcpy_find/solve.py>`_.

CGC crash identification
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Antonio Bianchi, Jacopo Corbetta
   Concepts presented: exploration to vulnerability

This is a very easy binary containing a stack buffer overflow and an easter egg.
CADET_00001 is one of the challenge released by DARPA for the Cyber Grand
Challenge: `link
<https://github.com/CyberGrandChallenge/samples/tree/master/examples/CADET_00001>`_
The binary can run in the DECREE VM: `link
<http://repo.cybergrandchallenge.com/boxes/>`_ A copy of the original challenge
and the angr solution is provided `here
<https://github.com/angr/angr-examples/tree/master/examples/CADET_00001>`_
CADET_00001.adapted (by Jacopo Corbetta) is the same program, modified to be
runnable in an Intel x86 Linux machine.

Grub "back to 28" bug
^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Audrey Dutcher (github: @rhelmot)
   Concepts presented: unusual target (custom function hooking required), use of exploration techniques to categorize and prune the program's state space

This is the demonstration presented at 32c3. The script uses angr to discover
the input to crash grub's password entry prompt.

`script <https://github.com/angr/angr-examples/tree/master/examples/grub/solve.py>`_ -
`vulnerable module
<https://github.com/angr/angr-examples/tree/master/examples/grub/crypto.mod>`_

Exploitation
------------

These are examples of angr's use as an exploitation assistance engine.

Insomnihack Simple AEG
^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Nick Stephens (github: @NickStephens)
   Concepts presented: automatic exploit generation, global symbolic data tracking

Demonstration for Insomni'hack 2016.  The script is a very simple implementation
of AEG.

`script <https://github.com/angr/angr-examples/tree/master/examples/insomnihack_aeg/solve.py>`_

SecuInside 2016 Quals - mbrainfuzz - symbolic exploration for exploitability conditions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: nsr (nsr@tasteless.eu)
   Script runtime: ~15 seconds per binary
   Concepts presented: symbolic exploration guided by static analysis, using the CFG

Originally, a binary was given to the ctf-player by the challenge-service, and
an exploit had to be crafted automatically. Four sample binaries, obtained
during the ctf, are included in the example. All binaries follow the same
format; the command-line argument is validated in a bunch of functions, and when
every check succeeds, a memcpy() resulting into a stack-based buffer overflow is
executed. angr is used to find the way through the binary to the memcpy() and to
generate valid inputs to every checking function individually.

The sample binaries and the script are located `here
<https://github.com/angr/angr-examples/tree/master/examples/secuinside2016mbrainfuzz>`_
and additional information be found at the author's `Write-Up
<https://tasteless.eu/post/2016/07/secuinside-mbrainfuzz/>`_.

SECCON 2016 Quals - ropsynth
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block::

   Script author: Yan Shoshitaishvili (github @zardus) and Nilo Redini
   Script runtime: 2 minutes
   Concepts presented: automatic ROP chain generation, binary modification, reasoning over constraints, reasoning over action history

This challenge required the automatic generation of ropchains, with the twist
that every ropchain was succeeded by an input check that, if not passed, would
terminate the application. We used symbolic execution to recover those checks,
removed the checks from the binary, used angrop to build the ropchains, and
instrumented them with the inputs to pass the checks.

The various challenge files are located `here
<https://github.com/angr/angr-examples/tree/master/examples/secconquals2016_ropsynth>`_,
with the actual solve script `here
<https://github.com/angr/angr-examples/tree/master/examples/secconquals2016_ropsynth/solve.py>`_.
