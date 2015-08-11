Angr
====

Angr is a platform-agnostic concolic binary analysis platform developed by the
Seclab at the University of California Santa Barbara and their associated
CTF team, Shellphish.

For information about how to use angr, consult the
[angr-doc](https://github.com/angr/angr-doc) repository.

Installation
============

Dependency libraries
--------------------
You need python 2. Py3k support is feasable somewhere out in the future, but
we are a little hesitant to make that commitment right now.

All the python dependencies should be handled by pip and/or the setup.py scripts.

You'll need to build some C to get from here to the end, so you'll need whatever
base compiler package your OS wants to use, as well as probably the python
development package, with headers and stuff.

At some point in the dependency install process, you'll install the python
library cffi, but it won't run unless you install libffi somehow.

You will use the [python virtualenv](https://virtualenvwrapper.readthedocs.org/en/latest/)
in the build process.

Production install
------------------
First of all, you want to install angr in a virtualenv. `mkvirtualenv angr`
will do the trick.

`pip install angr` will work in the future. Right now there are some issues.

`pip install --allow-all-external 'git+https://github.com/angr/angr.git'` has a
reasonable chance of working. You might run into some issues with claripy, though
those should be resolved very soon.

Development install
-------------------
```bash
mkvirtualenv angr
mkdir angr; cd angr

git clone https://github.com/angr/angr
git clone https://github.com/angr/simuvex
git clone https://github.com/angr/claripy
git clone https://github.com/angr/cle
git clone https://github.com/angr/pyvex
git clone https://github.com/angr/vex
git clone https://github.com/angr/archinfo
git clone https://github.com/zardus/ana
git clone https://github.com/zardus/cooldict

pip install https://github.com/zardus/z3/archive/pypy-and-setup.zip#egg=z3
pip install -e ./cooldict
pip install -e ./ana
pip install -e ./archinfo
pip install -e ./pyvex
pip install -e ./cle
pip install -e ./claripy
pip install -e ./simuvex
pip install -e ./angr
```



B. TROUBLESHOOTING
==================

### Can't import mulpyplexer
`pip install --upgrade 'git+https://github.com/zardus/mulpyplexer'`

### Windows and Capstone
On windows installing capstone can be a bit of a hassle. You might need to
manually specify a wheel to install, but sometimes it installs under a name
different from "capstone", so if that happens you want to just remove capstone
from the requirements.txt files in angr and archinfo.

### Claripy and z3
Z3 is a bit weird to compile. Sometimes it just completely fails to build for
no reason, saying that it can't create some object file because some file or
directory doesn't exist. Just retry the build.

### Claripy and z3 on Windows
Z3 might compile on windows if you have a l33t enough build environment. If
this isn't the case for you, you should download a wheel from somewhere on the
internet. I found one once, but can't seem to find it again while writing this.

If you build z3 from source, make sure you're using the unstable branch of z3,
which includes floating point support. In addition, make sure to have
`Z3PATH=path/to/libz3.dll` in your environment.
