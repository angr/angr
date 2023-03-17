Analyses
========

angr's goal is to make it easy to carry out useful analyses on binary programs.
To this end, angr allows you to package analysis code in a common format that
can be easily applied to any project. We will cover writing your own analyses
:ref:`Writing Analyses`, but the idea is that all the analyses appear under
``project.analyses`` (for example, ``project.analyses.CFGFast()``) and can be
called as functions, returning analysis result instances.

Built-in Analyses
-----------------

.. list-table::
   :header-rows: 1

   * - Name
     - Description
   * - CFGFast
     - Constructs a fast *Control Flow Graph* of the program
   * - CFGEmulated
     - Constructs an accurate *Control Flow Graph* of the program
   * - VFG
     - Performs VSA on every function of the program, creating a *Value Flow
       Graph* and detecting stack variables
   * - DDG
     - Calculates a *Data Dependency Graph*, allowing one to determine what
       statements a given value depends on
   * - BackwardSlice
     - Computes a *Backward Slice* of a program with respect to a certain target
   * - Identifier
     - Identifies common library functions in CGC binaries
   * - More!
     - angr has quite a few analyses, most of which work! If you'd like to know
       how to use one, please submit an issue requesting documentation.


Resilience
----------

Analyses can be written to be resilient, and catch and log basically any error.
These errors, depending on how they're caught, are logged to the ``errors`` or
``named_errors`` attribute of the analysis. However, you might want to run an
analysis in "fail fast" mode, so that errors are not handled. To do this, the
argument ``fail_fast=True`` can be passed into the analysis constructor.
