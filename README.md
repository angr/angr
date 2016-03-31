angr
====

[![Latest Release](https://img.shields.io/pypi/v/angr.svg)](https://pypi.python.org/pypi/angr/)
[![PyPI](https://img.shields.io/pypi/dm/angr.svg)](https://pypi.python.org/pypi/angr/)
[![License](https://img.shields.io/github/license/angr/angr.svg)](https://github.com/angr/angr/blob/master/LICENSE)
[![Gitbook](https://img.shields.io/badge/docs-gitbook-green.svg)](http://docs.angr.io)
[![API Docs](https://img.shields.io/badge/docs-api-green.svg)](http://angr.io/api-doc)

angr is a platform-agnostic binary analysis framework developed by the Computer Security Lab at UC Santa Barbara and their associated CTF team, Shellphish.

# What?

angr is a suite of python libraries that let you load a binary and do a lot of cool things to it:

- Disassembly and intermediate-representation lifting
- Program instrumentation
- Symbolic execution
- Control-flow analysis
- Data-dependency analysis
- Value-set analysis (VSA)

The most common angr operation is loading a binary: `p = angr.Project('/bin/bash')` If you do this in IPython, you can use tab-autocomplete to browse the [top-level-accessible methods](http://docs.angr.io/docs/toplevel.html) and their docstrings.

The short version of "how to install angr" is `mkvirtualenv angr && pip install angr`.

# Quick Start

- [Install Instructions](http://docs.angr.io/INSTALL.html)
- Documentation as [HTML](http://docs.angr.io/) and as a [Github repository](https://github.com/angr/angr-doc)
- Dive right in: [top-level-accessible methods](http://docs.angr.io/docs/toplevel.html)
- [Examples using angr to solve CTF challenges](http://docs.angr.io/docs/examples.html).
- [API Reference](http://angr.io/api-doc/)
