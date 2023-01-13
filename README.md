angr
====

[![Latest Release](https://img.shields.io/pypi/v/angr.svg)](https://pypi.python.org/pypi/angr/)
[![PyPI Statistics](https://img.shields.io/pypi/dm/angr.svg)](https://pypistats.org/packages/angr)
[![Build Status](https://github.com/angr/angr/actions/workflows/.github/workflows/ci.yml/badge.svg)](https://github.com/angr/angr/actions/workflows/.github/workflows/ci.yml/badge.svg)
[![License](https://img.shields.io/github/license/angr/angr.svg)](https://github.com/angr/angr/blob/master/LICENSE)
[![Gitbook](https://img.shields.io/badge/docs-gitbook-green.svg)](https://docs.angr.io)
[![API Docs](https://img.shields.io/badge/docs-api-green.svg)](https://angr.io/api-doc)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)

angr is a platform-agnostic binary analysis framework.
It is brought to you by [the Computer Security Lab at UC Santa Barbara](https://seclab.cs.ucsb.edu), [SEFCOM at Arizona State University](https://sefcom.asu.edu),  their associated CTF team, [Shellphish](https://shellphish.net), the open source community, and **[@rhelmot](https://github.com/rhelmot)**.

# What?

angr is a suite of Python 3 libraries that let you load a binary and do a lot of cool things to it:

- Disassembly and intermediate-representation lifting
- Program instrumentation
- Symbolic execution
- Control-flow analysis
- Data-dependency analysis
- Value-set analysis (VSA)
- Decompilation

The most common angr operation is loading a binary: `p = angr.Project('/bin/bash')` If you do this in an enhanced REPL like IPython, you can use tab-autocomplete to browse the [top-level-accessible methods](https://docs.angr.io/docs/toplevel) and their docstrings.

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

- [Install Instructions](https://docs.angr.io/introductory-errata/install)
- Documentation as [HTML](https://docs.angr.io/) and as a [Github repository](https://github.com/angr/angr-doc)
- Dive right in: [top-level-accessible methods](https://docs.angr.io/core-concepts/toplevel)
- [Examples using angr to solve CTF challenges](https://docs.angr.io/examples).
- [API Reference](https://angr.io/api-doc/)
- [awesome-angr repo](https://github.com/degrigis/awesome-angr)
