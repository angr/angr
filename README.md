angr
====

[![Latest Release](https://img.shields.io/pypi/v/angr.svg)](https://pypi.python.org/pypi/angr/)
[![PyPI Statistics](https://img.shields.io/pypi/dm/angr.svg)](https://pypistats.org/packages/angr)
[![Build Status](https://dev.azure.com/angr/angr/_apis/build/status/angr?branchName=master)](https://dev.azure.com/angr/angr/_build/latest?definitionId=18&branchName=master)
[![License](https://img.shields.io/github/license/angr/angr.svg)](https://github.com/angr/angr/blob/master/LICENSE)
[![Gitbook](https://img.shields.io/badge/docs-gitbook-green.svg)](http://docs.angr.io)
[![API Docs](https://img.shields.io/badge/docs-api-green.svg)](http://angr.io/api-doc)

angr is a platform-agnostic binary analysis framework.
It is brought to you by [the Computer Security Lab at UC Santa Barbara](https://seclab.cs.ucsb.edu), [SEFCOM at Arizona State University](http://sefcom.asu.edu),  their associated CTF team, [Shellphish](http://shellphish.net), the open source community, and **[@rhelmot](https://github.com/rhelmot)**.

# What?

angr is a suite of Python 3 libraries that let you load a binary and do a lot of cool things to it:

- Disassembly and intermediate-representation lifting
- Program instrumentation
- Symbolic execution
- Control-flow analysis
- Data-dependency analysis
- Value-set analysis (VSA)
- Decompilation

The most common angr operation is loading a binary: `p = angr.Project('/bin/bash')` If you do this in an enhanced REPL like IPython, you can use tab-autocomplete to browse the [top-level-accessible methods](http://docs.angr.io/docs/toplevel.html) and their docstrings.

The short version of "how to install angr" is `mkvirtualenv --python=$(which python3) angr && python -m pip install angr`.

# Example

angr does a lot of binary analysis stuff.
To get you started, here's a simple example of using symbolic execution to get a flag in a CTF challenge.

```python
import angr

project = angr.Project("angr-doc/examples/defcamp_r100/r100", auto_load_libs=False)

@project.hook(0x400844)
def print_flag(state):
    print("FLAG SHOULD BE:", state.posix.dumps(0))
    project.terminate_execution()

project.execute()
```

# Quick Start

- [Install Instructions](http://docs.angr.io/INSTALL.html)
- Documentation as [HTML](http://docs.angr.io/) and as a [Github repository](https://github.com/angr/angr-doc)
- Dive right in: [top-level-accessible methods](http://docs.angr.io/docs/toplevel.html)
- [Examples using angr to solve CTF challenges](http://docs.angr.io/docs/examples.html).
- [API Reference](http://angr.io/api-doc/)
