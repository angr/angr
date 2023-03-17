Writing Analyses
================

An analysis can be created by subclassing the ``angr.Analysis`` class. In this
section, we'll create a mock analysis to show off the various features. Let's
start with something simple:

.. code-block:: python

   >>> import angr

   >>> class MockAnalysis(angr.Analysis):
   ...     def __init__(self, option):
   ...         self.option = option

   >>> angr.AnalysesHub.register_default('MockAnalysis', MockAnalysis) # register the class with angr's global analysis list

This is a very simple analysis -- it takes an option, and stores it. Of course,
it's not useful, but this is just a demonstration.

Let's see how to run our new analysis:

.. code-block:: python

   >>> proj = angr.Project("/bin/true")
   >>> mock = proj.analyses.MockAnalysis('this is my option')
   >>> assert mock.option == 'this is my option'

Working with projects
^^^^^^^^^^^^^^^^^^^^^

Via some Python magic, your analysis will automatically have the project upon
which you are running it under the ``self.project`` property. Use this to
interact with your project and analyze it!

.. code-block:: python

   >>> class ProjectSummary(angr.Analysis):
   ...     def __init__(self):
   ...         self.result = 'This project is a %s binary with an entry point at %#x.' % (self.project.arch.name, self.project.entry)

   >>> angr.AnalysesHub.register_default('ProjectSummary', ProjectSummary)
   >>> proj = angr.Project("/bin/true")

   >>> summary = proj.analyses.ProjectSummary()
   >>> print(summary.result)
   This project is a AMD64 binary with an entry point at 0x401410.

Analysis Resilience
^^^^^^^^^^^^^^^^^^^

Sometimes, your (or our) code might suck and analyses might throw exceptions. We
understand, and we also understand that oftentimes a partial result is better
than nothing. This is specifically true when, for example, running an analysis
on all of the functions in a program. Even if some of the functions fails, we
still want to know the results of the functions that do not.

To facilitate this, the ``Analysis`` base class provides a resilience context
manager under ``self._resilience``. Here's an example:

.. code-block:: python

   >>> class ComplexFunctionAnalysis(angr.Analysis):
   ...     def __init__(self):
   ...         self._cfg = self.project.analyses.CFG()
   ...         self.results = { }
   ...         for addr, func in self._cfg.function_manager.functions.items():
   ...             with self._resilience():
   ...                 if addr % 2 == 0:
   ...                     raise ValueError("can't handle functions at even addresses")
   ...                 else:
   ...                     self.results[addr] = "GOOD"

The context manager catches any exceptions thrown and logs them (as a tuple of
the exception type, message, and traceback) to ``self.errors``. These are also
saved and loaded when the analysis is saved and loaded (although the traceback
is discarded, as it is not picklable).

You can tune the effects of the resilience with two optional keyword parameters
to ``self._resilience()``.

The first is ``name``, which affects where the error is logged. By default,
errors are placed in ``self.errors``, but if ``name`` is provided, then
instead the error is logged to ``self.named_errors``, which is a dict mapping
``name`` to a list of all the errors that were caught under that name. This
allows you to easily tell where thrown without examining its traceback.

The second argument is ``exception``, which should be the type of the
exception that ``resilience`` should catch. This defaults to ``Exception``,
which handles (and logs) almost anything that could go wrong. You can also pass
a tuple of exception types to this option, in which case all of them will be
caught.

Using ``resilience`` has a few advantages:


#. Your exceptions are gracefully logged and easily accessible afterwards. This
   is really nice for writing testcases.
#. When creating your analysis, the user can pass ``fail_fast=True``, which
   transparently disable the resilience, which is really nice for manual
   testing.
#. It's prettier than having ``try`` ``except`` everywhere.

Have fun with analyses! Once you master the rest of angr, you can use analyses
to understand anything computable!
