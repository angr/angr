angr
====

[![Latest Release](https://img.shields.io/pypi/v/angr.svg)](https://pypi.python.org/pypi/angr/)
[![PyPI](https://img.shields.io/pypi/dm/angr.svg)](https://pypi.python.org/pypi/angr/)
[![License](https://img.shields.io/github/license/angr/angr.svg)](https://github.com/angr/angr/blob/master/LICENSE)

angr is a platform-agnostic binary analysis framework developed by the Computer Security Lab at UC Santa Barbara and their associated CTF team, Shellphish.

# What?

angr is a suite of python libraries that let you load a binary and do a lot of cool things to it:

- Disassembly and intermediate-representation lifting
- Program instrumentation
- Symbolic execution
- Control-flow analysis
- Data-dependency analysis
- Value-set analysis (VSA)

The most common angr operation is loading a binary: `p = angr.Project('/bin/bash')` If you do this in IPython, you can use tab-autocomplete to browse the top-level-accessable methods and their docstrings.

For installation instructions, support information, and lots of words about how to use angr, consult the [angr-doc](https://github.com/angr/angr-doc) repository.
Several examples of using angr to solve CTF challenges can be found [here](https://github.com/angr/angr-doc/blob/master/examples.md).

The short version of "how to install angr" is `mkvirtualenv angr && pip install angr`.
