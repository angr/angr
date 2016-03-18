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

The most common angr operation is loading a binary: `p = angr.Program('/bin/bash')` If you do this in IPython, you can use tab-autocomplete to browse the top-level-accessable methods and their docstrings.

For more information about how to use angr, consult the
[angr-doc](https://github.com/angr/angr-doc) repository.
Several examples of using angr to solve CTF challenges can be found [here](https://github.com/angr/angr-doc/blob/master/examples.md).

# Installation

Installing angr is quite simple!

## Dependencies

angr is built for Python 2.
Python 3 support is feasable somewhere out in the future, but we are a little hesitant to make that commitment right now (pull requests welcome!).

All of the python dependencies should be handled by pip and/or the setup.py scripts.
You will, however, need to build some C to get from here to the end, so you'll need whatever base compiler package your OS wants to use, as well as the python development package (for the right headers).
At some point in the dependency install process, you'll install the python library cffi, but it won't run unless you install libffi.

You will also need to use the [python virtual environments](https://virtualenvwrapper.readthedocs.org/en/latest/) in the build (and usage) process.

On Ubuntu, you will want:

```bash
sudo apt-get install python-dev libffi-dev build-essential virtualenvwrapper
```

## Production install

angr is meant (and tested) to be installed in a virtualenv. `mkvirtualenv angr` will do the trick.
To install, do:

```
mkvirtualenv angr
pip install angr
```

To switch to the virtualenv later (and use angr), do `workon angr`.

## Development install

We created a repo with scripts to make life easier for angr developers.
You can set up angr in development mode by doing:

```bash
git clone https://github.com/angr/angr-dev
cd angr-dev
mkvirtualenv angr
./setup.sh
```

This clones all of the repositories and installs them in editable mode.
`setup.sh` can even create a PyPy virtualenv for you, resulting in significantly faster performance and lower memory usage.

You can branch/edit/recompile the various modules in-place, and it will automatically reflect in your virtual environment.

## Docker install

For convenience, we ship a Dockerfile that is 99% guaranteed to work.
You can install via docker by doing:

```bash
# install docker
curl -sSL https://get.docker.com/ | sudo sh

# clone the repo
git clone https://github.com/angr/angr-dev

# create the docker image
sudo docker build -t angr - < angr-dev/Dockerfile

# run it
sudo docker run -it angr
```

Synchronization of files in and out of docker is left as an excercize to the user (hint: check out `docker -v`).

# Troubleshooting

## libgomp.so.1: version `GOMP_4.0' not found
This error represents an incompatibility between the pre-compiled version of `angr-only-z3-custom` and the installed version of `libgomp`. A Z3 recompile is required. You can do this by executing:

```bash
pip install -I --no-use-wheel angr-only-z3-custom
```

## Can't import mulpyplexer
There are sometimes issues with installing mulpyplexer. Doing `pip install --upgrade 'git+https://github.com/zardus/mulpyplexer'` should fix this.

## Can't import angr because of capstone
Sometimes capstone isn't installed correctly for use by angr. There's a good chance just reinstalling capstone will solve this issue:

```bash
pip install -I --no-use-wheel capstone
```

## Windows and Capstone
On windows installing capstone can be a bit of a hassle. You might need to
manually specify a wheel to install, but sometimes it installs under a name
different from "capstone", so if that happens you want to just remove capstone
from the requirements.txt files in angr and archinfo.

## Claripy and z3
Z3 is a bit weird to compile. Sometimes it just completely fails to build for
no reason, saying that it can't create some object file because some file or
directory doesn't exist. Just retry the build:

```bash
pip install -I --no-use-wheel angr-only-z3-custom
```

## Claripy and z3 on Windows
Z3 might compile on windows if you have a l33t enough build environment. If
this isn't the case for you, you should download a wheel from somewhere on the
internet. One location for pre-built Windows wheel files is <https://github.com/Owlz/angr-Windows>.

If you build z3 from source, make sure you're using the unstable branch of z3,
which includes floating point support. In addition, make sure to have
`Z3PATH=path/to/libz3.dll` in your environment.

## No such file or directory: 'pyvex_c'

Are you running 12.04? If so, please upgrade!

You can also try upgrading pip (`pip install -U pip`), which might solve the issue.

# Citing angr

If you use angr in an academic work, please cite the paper for which it was developed:

```bibtex
@article{shoshitaishvili2015firmalice,
  title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  year={2015}
}
```


# Help!

There are two options to get help with angr:

- the mailing list: angr@lists.cs.ucsb.edu
- the IRC channel: **#angr** on [freenode](https://freenode.net/).
