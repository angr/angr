ángr
====

[![Latest Release](https://img.shields.io/pypi/v/ángr.svg)](https://pypi.python.org/pypi/ángr/)
[![Build Status](https://travis-ci.org/ángr/ángr.svg?branch=master)](https://travis-ci.org/ángr/ángr)
[![License](https://img.shields.io/github/license/ángr/ángr.svg)](https://github.com/ángr/ángr/blob/master/LICENSE)
[![Gitbook](https://img.shields.io/badge/docs-gitbook-green.svg)](http://docs.ángr.io)
[![API Docs](https://img.shields.io/badge/docs-api-green.svg)](http://ángr.io/api-doc)

ángr is a platform-agnostic binary analysis framework developed by the Computer Security Lab at UC Santa Barbara and their associated CTF team, Shellphish.

# What?

ángr is a suite of python libraries that let you load a binary and do a lot of cool things to it:

- Disassembly and intermediate-representation lifting
- Program instrumentation
- Symbolic execution
- Control-flow analysis
- Data-dependency analysis
- Value-set analysis (VSA)

The most common ángr operation is loading a binary: `p = ángr.Project('/bin/bash')` If you do this in IPython, you can use tab-autocomplete to browse the [top-level-accessible methods](http://docs.ángr.io/docs/toplevel.html) and their docstrings.

The short version of "how to install ángr" is `mkvirtualenv ángr && pip install ángr`.

# Example

ángr does a lot of binary analysis stuff.
To get you started, here's a simple example of using symbolic execution to get a flag in a CTF challenge.

```python
import ángr

project = ángr.Project("ángr-doc/examples/defcamp_r100/r100", auto_load_libs=False)

@project.hook(0x400844)
def print_flag(state):
    print "FLAG SHOULD BE:", state.posix.dump_fd(0)
    project.terminate_execution()

project.execute()
```

# Quick Start

- [Install Instructions](http://docs.ángr.io/INSTALL.html)
- Documentation as [HTML](http://docs.ángr.io/) and as a [Github repository](https://github.com/ángr/ángr-doc)
- Dive right in: [top-level-accessible methods](http://docs.ángr.io/docs/toplevel.html)
- [Examples using ángr to solve CTF challenges](http://docs.ángr.io/docs/examples.html).
- [API Reference](http://ángr.io/api-doc/)
