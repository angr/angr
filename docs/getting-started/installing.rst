Installing angr
===============

angr is a library for Python 3.8+, and must be installed into a Python
environment before it can be used.

.. tip::
   It is reccomend to use an isolated python environement rather than installing
   angr globally. Doing so reduces dependency conflicts and aids in
   reproducability while debugging. Some popular tools that accomplish this
   include:

   * `venv <https://docs.python.org/3/library/venv.html>`_
   * `pipenv <https://pipenv.pypa.io/en/latest/>`_
   * `virtualenv <https://virtualenv.pypa.io/en/latest/>`_
   * `virtualenvwrapper <https://virtualenvwrapper.readthedocs.io/en/latest/>`_
   * `conda <https://docs.conda.io/en/latest/>`_

Installing from PyPI
--------------------

angr is published on `PyPI <https://pypi.org/>`_, and using this is the easiest
and reccomended way to install angr. It can be installed angr with pip:

.. code-block:: bash

   pip install angr

.. note::
   The PyPI distribution includes binary packages for most popular system
   configurations. If you are using a system that is not supported by the
   binary packages, you will need to build the C dependencies from source. See
   the `Installing from Source`_ section for more information.

Installing from Source
----------------------

angr is a collection of Python packages, each of which is published on GitHub.
The easiest way to install angr from source is to use `angr-dev
<https://github.com/angr/angr-dev>`_.

To set up a development environment manually, first ensure that build
dependencies are installed. These consist of python development headers,
``make``, and a C compiler. On Ubuntu, these can be installed with:

.. code-block:: bash

   sudo apt-get install python3-dev build-essential

Then, checkout and install the following packages, in order:

* `archinfo <https://github.com/angr/archinfo>`_
* `pyvex <https://github.com/angr/pyvex>`_ (clone with ``--recursive``)
* `cle <https://github.com/angr/cle>`_
* `claripy <https://github.com/angr/claripy>`_
* `ailment <https://github.com/angr/ailment>`_
* `angr <https://github.com/angr/angr>`_ (``pip install`` with
  ``--no-build-isolation``)


Troubleshooting
---------------

angr has no attribute Project, or similar
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If angr can be imported but the ``Project`` class is missing, it is likely one
of two problems:

#. There is a script named ``angr.py`` in the working directory. Rename it to
   something else.
#. There is a folder called ``angr`` in your working directory, possibly the
   cloned repository. Change the working directory to somewhere else.

AttributeError: 'module' object has no attribute 'KS_ARCH_X86'
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``keystone`` package is installed, which conflicts with the
``keystone-engine`` package, an optional dependency of angr. Uninstall
``keystone`` and install ``keystone-engine``.
