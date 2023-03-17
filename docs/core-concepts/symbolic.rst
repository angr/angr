Symbolic Execution
==================

Symbolic execution allows at a time in emulation to determine for a branch all
conditions necessary to take a branch or not. Every variable is represented as a
symbolic value, and each branch as a constraint. Thus, symbolic execution allows
us to see which conditions allows the program to go from a point A to a point B,
by resolving the constraints.

If you've read this far, you can see how the components of angr work together to
make this possible. Read on to learn about how to make the leap from tools to
results.

.. todo:: A real introduction to the concept of symbolic execution.
