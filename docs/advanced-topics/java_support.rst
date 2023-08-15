Java Support
============

``angr`` also supports symbolically executing Java code and Android apps! This
also includes Android apps using a combination of compiled Java and native
(C/C++) code.

.. warning::
   Java support is experimental! Contribution from the community is highly
   encouraged! Pull requests are very welcomed!

We implemented Java support by lifting the compiled Java code, both Java and DEX
bytecode, leveraging our Soot Python wrapper: `pysoot
<https://github.com/angr/pysoot>`_. ``pysoot`` extracts a fully serializable
interface from Android apps and Java code (unfortunately, as of now, it only
works on Linux). For every class of the generated IR (for instance,
``SootMethod``), you can nicely print its instructions (in a format similar to
``Soot`` ``shimple``) using ``print()`` or ``str()``.

We then leverage the generated IR in a new angr engine able to run code in Soot
IR: `angr/engines/soot/engine.py
<https://github.com/angr/angr/blob/master/angr/engines/soot/engine.py>`_. This
engine is also able to automatically switch to executing native code if the Java
code calls any native method using the JNI interface.

Together with the symbolic execution, we also implemented some basic static
analysis, specifically a basic CFG reconstruction analysis. Moreover, we added
support for string constraint solving, modifying claripy and using the CVC4
solver.

How to install
--------------

Enabling Java support requires few more steps than typical angr installation.
Assuming you installed `angr-dev <https://github.com/angr/angr-dev>`_, activate
the virtualenv and run:

.. code-block:: bash

   pip install -e ./claripy[cvc4-solver]
   ./setup.sh pysoot

Analyzing Android apps.
~~~~~~~~~~~~~~~~~~~~~~~

Analyzing Android apps (``.APK`` files, containing Java code compiled to the
``DEX`` format) requires the Android SDK. Typically, it is installed in
``<HOME>/Android/SDK/platforms/platform-XX/android.jar``, where ``XX`` is the
Android SDK version used by the app you want to analyze (you may want to install
all the platforms required by the Android apps you want to analyze).

Examples
--------

There are multiple examples available:


* Easy Java crackmes: `java_crackme1
  <https://github.com/angr/angr-examples/tree/master/examples/java_crackme1>`_,
  `java_simple3
  <https://github.com/angr/angr-examples/tree/master/examples/java_simple3>`_,
  `java_simple4
  <https://github.com/angr/angr-examples/tree/master/examples/java_simple4>`_
* A more complex example (solving a CTF challenge): `ictf2017_javaisnotfun
  <https://github.com/angr/angr-examples/tree/master/examples/ictf2017_javaisnotfun>`_,
  `blogpost <https://angr.io/blog/java_angr/>`_
* Symbolically executing an Android app (using a mix of Java and native code):
  `java_androidnative1
  <https://github.com/angr/angr-examples/tree/master/examples/java_androidnative1>`_
* Many other low-level tests: `test_java
  <https://github.com/angr/angr/blob/master/tests/test_java.py>`_
