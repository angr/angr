Reporting Bugs
==============

If you've found something that angr isn't able to solve and appears to be a bug,
please let us know!


#. Create a fork off of angr/binaries and angr/angr
#. Give us a pull request with angr/binaries, with the binaries in question
#. Give us a pull request for angr/angr, with testcases that trigger the
   binaries in ``angr/tests/broken_x.py``, ``angr/tests/broken_y.py``, etc

Please try to follow the testcase format that we have (so the code is in a
test_blah function), that way we can very easily merge that and make the scripts
run.

An example is:

.. code-block:: python

   def test_some_broken_feature():
       p = angr.Project("some_binary")
       result = p.analyses.SomethingThatDoesNotWork()
       assert result == "what it should *actually* be if it worked"

   if __name__ == '__main__':
       test_some_broken_feature()

This will *greatly* help us recreate your bug and fix it faster.

The ideal situation is that, when the bug is fixed, your testcases passes (i.e.,
the assert at the end does not raise an AssertionError).

Then, we can just fix the bug and rename ``broken_x.py`` to ``test_x.py`` and
the testcase will run in our internal CI at every push, ensuring that we do not
break this feature again.

Developing angr
===============

These are some guidelines so that we can keep the codebase in good shape!

pre-commit
----------

Many angr repos contain pre-commit hooks provided by `pre-commit
<https://pre-commit.com/>`_. Installing this is as easy as ``pip install
pre-commit``. After ``git`` cloning an angr repository, if the repo contains a
``.pre-commit-config.yaml``, run ``pre-commit install``. Future ``git``
commits will now invoke these hooks automatically.

Coding style
------------

We format our code with `black <https://github.com/psf/black>`_ and otherwise
try to get as close as the `PEP8 code convention
<http://legacy.python.org/dev/peps/pep-0008/>`_ as is reasonable without being
dumb. If you use Vim, the `python-mode <https://github.com/klen/python-mode>`_
plugin does all you need. You can also `manually configure
<https://wiki.python.org/moin/Vim>`_ vim to adopt this behavior.

Most importantly, please consider the following when writing code as part of angr:


* Try to use attribute access (see the ``@property`` decorator) instead of
  getters and setters wherever you can. This isn't Java, and attributes enable
  tab completion in iPython. That being said, be reasonable: attributes should
  be fast. A rule of thumb is that if something could require a constraint
  solve, it should not be an attribute.

* Use `our pylintrc from the angr-dev repo
  <https://github.com/angr/angr-dev/blob/master/pylintrc>`_. It's fairly
  permissive, but our CI server will fail your builds if pylint complains under
  those settings.

* DO NOT, under ANY circumstances, ``raise Exception`` or ``assert False``.
  **Use the right exception type**. If there isn't a correct exception type,
  subclass the core exception of the module that you're working in (i.e.,
  ``AngrError`` in angr, ``SimError`` in SimuVEX, etc) and raise that. We catch,
  and properly handle, the right types of errors in the right places, but
  ``AssertionError`` and ``Exception`` are not handled anywhere and
  force-terminate analyses.

* Avoid tabs; use space indentation instead. Even though it's wrong, the de
  facto standard is 4 spaces. It is a good idea to adopt this from the
  beginning, as merging code that mixes both tab and space indentation is awful.

* Avoid super long lines. It's okay to have longer lines, but keep in mind that
  long lines are harder to read and should be avoided. Let's try to stick to
  **120 characters**.

* Avoid extremely long functions, it is often better to break them up into
  smaller functions.

* Always use ``_`` instead of ``__`` for private members (so that we can access
  them when debugging). *You* might not think that anyone has a need to call a
  given function, but trust us, you're wrong.

* Format your code with ``black``; config is already defined within
  ``pyproject.toml``.

Documentation
-------------

Document your code. Every *class definition* and *public function definition*
should have some description of:

* What it does.
* What are the type and the meaning of the parameters.
* What it returns.

Class docstrings will be enforced by our linter. Do *not* under any
circumstances write a docstring which doesn't provide more information than the
name of the class. What you should try to write is a description of the
environment that the class should be used in. If the class should not be
instantiated by end-users, write a description of where it will be generated and
how instances can be acquired. If the class should be instantiated by end-users,
explain what kind of object it represents at its core, what behavior is expected
of its parameters, and how to safely manage objects of its type.

We use `Sphinx <http://www.sphinx-doc.org/en/stable/>`_ to generate the API
documentation. Sphinx supports docstrings written in `ReStructured Text
<http://openalea.gforge.inria.fr/doc/openalea/doc/_build/html/source/sphinx/rest_syntax.html#auto-document-your-python-code>`_
with special `keywords
<http://www.sphinx-doc.org/en/stable/domains.html#info-field-lists>`_ to
document function and class parameters, return values, return types, members,
etc.

Here is an example of function documentation. Ideally the parameter descriptions
should be aligned vertically to make the docstrings as readable as possible.

.. code-block:: python

   def prune(self, filter_func=None, from_stash=None, to_stash=None):
       """
       Prune unsatisfiable paths from a stash.

       :param filter_func: Only prune paths that match this filter.
       :param from_stash:  Prune paths from this stash. (default: 'active')
       :param to_stash:    Put pruned paths in this stash. (default: 'pruned')
       :returns:           The resulting PathGroup.
       :rtype:             PathGroup
       """

This format has the advantage that the function parameters are clearly
identified in the generated documentation. However, it can make the
documentation repetitive, in some cases a textual description can be more
readable. Pick the format you feel is more appropriate for the functions or
classes you are documenting.

.. code-block:: python

    def read_bytes(self, addr, n):
       """
       Read `n` bytes at address `addr` in memory and return an array of bytes.
       """

Unit tests
----------

If you're pushing a new feature and it is not accompanied by a test case it
**will be broken** in very short order. Please write test cases for your stuff.

We have an internal CI server to run tests to check functionality and regression
on each commit. In order to have our server run your tests, write your tests in
a format acceptable to `nosetests <https://nose.readthedocs.org/en/latest/>`_ in
a file matching ``test_*.py`` in the ``tests`` folder of the appropriate
repository. A test file can contain any number of functions of the form ``def
test_*():`` or classes of the form ``class Test*(unittest.TestCase):``. Each of
them will be run as a test, and if they raise any exceptions or assertions, the
test fails. Do not use the ``nose.tools.assert_*`` functions, as we are
presently trying to migrate to ``nose2``. Use ``assert`` statements with
descriptive messages or the ``unittest.TestCase`` assert methods.

Look at the existing tests for examples. Many of them use an alternate format
where the ``test_*`` function is actually a generator that yields tuples of
functions to call and their arguments, for easy parametrization of tests.

Finally, do not add docstrings to your test functions.
