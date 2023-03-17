Installing angr
===============

.. todo::
   This page is out of date. It needs to be updated to reflect the latest
   version of angr.

angr is a library for Python 3.8+, and must be installed into your Python
environment before it can be used.

We highly recommend using a `Python virtual environment
<https://virtualenvwrapper.readthedocs.org/en/latest/>`_ to install and use
angr. Several of angr's dependencies (z3, pyvex) require libraries of native
code that are forked from their originals, and if you already have libz3 or
libVEX installed, you definitely don't want to overwrite the official shared
objects with ours. In general, don't expect support for problems arising from
installing angr outside of a virtualenv.

Dependencies
------------

All of the Python dependencies should be handled by pip and/or the setup.py
scripts. You will, however, need to build some C to get from here to the end, so
you'll need a good build environment as well as the Python development headers.
At some point in the dependency install process, you'll install the Python
library cffi, but (on linux, at least) it won't run unless you install your
operating system's libffi package.

On Ubuntu, you will want: ``sudo apt-get install python3-dev libffi-dev
build-essential virtualenvwrapper``. If you are trying out angr Management, you
will also need the `PySide 2 requirements
<https://wiki.qt.io/Qt_for_Python/GettingStarted>`_.

Most Operating systems, all \*nix systems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``mkvirtualenv --python=$(which python3) angr && pip install angr`` should
usually be sufficient to install angr in most cases, since angr is published on
the Python Package Index.

Fish (shell) users can either use `virtualfish
<https://github.com/adambrenecki/virtualfish>`_ or the `virtualenv
<https://pypi.python.org/pypi/virtualenv>`_ package: ``vf new angr && vf activate
angr && pip install angr``

Failing that, you can install angr by installing the following repositories, in
order, from https://github.com/angr:


* `archinfo <https://github.com/angr/archinfo>`_
* `pyvex <https://github.com/angr/pyvex>`_
* `cle <https://github.com/angr/cle>`_
* `claripy <https://github.com/angr/claripy>`_
* `ailment <https://github.com/angr/ailment>`_
* `angr <https://github.com/angr/angr>`_

Mac OS X
^^^^^^^^

``pip install angr`` should work, but there are some caveats.

angr requires the ``unicorn`` library, which (as of this writing) ``pip`` must
build from source on macOS, even though binary distributions ("wheels") exist on
other platforms. Building ``unicorn`` from source requires Python 2, so will
fail inside a virtualenv where ``python`` gets you Python 3. If you encounter
errors with ``pip install angr``, you may need to first install ``unicorn``
separately, pointing it to your Python 2:

.. code-block:: bash

   UNICORN_QEMU_FLAGS="--python=/path/to/python2" pip install unicorn  # Python 2 is probably /usr/bin/python on your macOS system

Then retry ``pip install angr``.

If this still doesn't work and you run into a broken build script with Clang,
try using GCC.

.. code-block:: bash

   brew install gcc
   CC=/usr/local/bin/gcc-8 UNICORN_QEMU_FLAGS="--python=/path/to/python2" pip install unicorn  # As of this writing, brew install gcc gives you gcc-8
   pip install angr

After installing angr, you will need to fix some shared library paths for the
angr native libraries. Activate your virtual env and execute the following
lines. `A script <https://github.com/angr/angr-dev/blob/master/fix_macOS.sh>`_
is provided in the angr-dev repo.

.. code-block:: bash

   PYVEX=`python3 -c 'import pyvex; print(pyvex.__path__[0])'`
   UNICORN=`python3 -c 'import unicorn; print(unicorn.__path__[0])'`
   ANGR=`python3 -c 'import angr; print(angr.__path__[0])'`

   install_name_tool -change libunicorn.1.dylib "$UNICORN"/lib/libunicorn.dylib "$ANGR"/lib/angr_native.dylib
   install_name_tool -change libpyvex.dylib "$PYVEX"/lib/libpyvex.dylib "$ANGR"/lib/angr_native.dylib

Windows
^^^^^^^

As usual, a virtualenv is very strongly recommended. You can use either the
`virtualenv-win <https://pypi.org/project/virtualenvwrapper-win/>`_ or
`virtualenv <https://pypi.python.org/pypi/virtualenv>`_ packages for this.

angr can be installed from pip on Windows, same as above: ``pip install angr``.
You should not be required to build any C code with this setup, since wheels
(binary distributions) should be automatically pulled down for angr and its
dependencies.

Nix/NixOS
^^^^^^^^^

angr is available via the `Nix <https://nixos.org/nix/>`_ package manager and on
`NixOS <https://nixos.org/nixos/>`_, using the `Nix User Repository
<https://github.com/nix-community/NUR>_`.

First, make NUR available to your user:

.. code-block:: bash

   cat << __EOF__ > ~/.config/nixpkgs/config.nix
   {
     packageOverrides = pkgs: {
       nur = import (builtins.fetchTarball "https://github.com/nix-community/NUR/archive/master.tar.gz") {
         inherit pkgs;
       };
     };
   }
   __EOF__

Then, to obtain a nix-shell with the ``angr`` Python package:

.. code-block:: bash

   nix-shell -p 'python3.withPackages(ps: with ps; [ nur.repos.angr.python3Packages.angr ])'

More information on `angr/nixpkgs <https://github.com/angr/nixpkgs>`_.

Development install
-------------------

There is a special repository ``angr-dev`` with scripts to make life easier for
angr developers. You can set up angr in development mode by running:

.. code-block:: bash

   git clone https://github.com/angr/angr-dev
   cd angr-dev
   ./setup.sh -i -e angr

This creates a virtualenv (``-e angr``), checks for any dependencies you
might need (``-i``), clones all of the repositories and installs them in
editable mode. ``setup.sh`` can even create a PyPy virtualenv for you (replace
``-e`` with ``-p``), resulting in significantly faster performance and lower
memory usage.

You can branch/edit/recompile the various modules in-place, and it will
automatically reflect in your virtual environment.

Development install on windows
------------------------------

The angr-dev repository has a setup.bat script that creates the same setup as
above, though it's not as magical as setup.sh. Since we'll be building C code,
you must be in the visual studio developer command prompt. *Make sure that if
you're using a 64-bit Python interpreter, you're also using the 64-bit build
tools* (``VsDevCmd.bat -arch=x64``)

.. code-block:: bash

   pip install virtualenv
   git clone https://github.com/angr/angr-dev
   cd angr-dev
   virtualenv -p "C:\Path\To\python3\python.exe" env
   env\Scripts\activate
   setup.bat

You may also substitute the use of ``virtualenv`` above with the
``virtualenvwrapper-win`` package for a more streamlined experience.

Docker install
--------------

For convenience, we ship a Docker image that is 99% guaranteed to work.
You can install via docker by doing:

.. code-block:: bash

   # install docker
   curl -sSL https://get.docker.com/ | sudo sh

   # pull the docker image
   sudo docker pull angr/angr

   # run it
   sudo docker run -it angr/angr

Synchronization of files in and out of docker is left as an exercise to the user
(hint: check out ``docker run -v``).

Modifying the angr container
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You might find yourself needing to install additional packages via apt. The
vanilla version of the container does not have the sudo package installed, which
means the default user in the container cannot escalate privilege to install
additional packages.

To over come this hurdle, use the following docker command to grant yourself
root access:

.. code-block:: bash

   # assuming the docker container is running
   # with the name "angr" and the instance is
   # running in the background.
   docker exec -ti -u root angr bash

Troubleshooting
===============

libgomp.so.1: version GOMP_4.0 not found, or other z3 issues
------------------------------------------------------------

This specific error represents an incompatibility between the pre-compiled
version of libz3.so and the installed version of ``libgomp``. A Z3 recompile is
required. You can do this by executing:

.. code-block:: bash

   pip install -I --no-binary z3-solver z3-solver

No such file or directory: 'pyvex_c'
------------------------------------

Are you running Ubuntu 12.04? If so, please stop using a 6 year old operating
system! Upgrading is free!

You can also try upgrading pip (``python -m pip install -U pip``), which
might solve the issue.

AttributeError: 'FFI' object has no attribute 'unpack'
------------------------------------------------------

You have an outdated version of the ``cffi`` Python module.  angr now requires
at least version 1.7 of cffi. Try ``pip install --upgrade cffi``.  If the
problem persists, make sure your operating system hasn't pre-installed an old
version of cffi, which pip may refuse to uninstall. If you're using a Python
virtual environment with the pypy interpreter, ensure you have a recent version
of pypy, as it includes a version of cffi which pip will not upgrade.

angr has no attribute Project, or similar
-----------------------------------------

If you can import angr but it doesn't seem to be the actual angr module... did
you accidentally name your script ``angr.py``? You can't do that. Python does
not work that way.

AttributeError: 'module' object has no attribute 'KS_ARCH_X86'
--------------------------------------------------------------

You have the ``keystone`` package installed, which conflicts with the
``keystone-engine`` package (an optional dependency of angr). Please uninstall
``keystone``. If you would like to install ``keystone-engine``, please do it
with ``pip install --no-binary keystone-engine keystone-engine``, as the
current pip distribution is broken.

No such file or directory: 'libunicorn.dylib'
---------------------------------------------

(alternate error message: ``Cannot use 'python', Python 2.4 or later is
required. Note that Python 3 or later is not yet supported.``)

You need to define the ``UNICORN_QEMU_FLAGS`` environment variable for ``pip``.
See the section above on installing for macOS.

pthread check failed: Make sure to have the pthread libs and headers installed.
-------------------------------------------------------------------------------

(macOS) Try using GCC instead of Clang; see the section above on installing for
macOS.
