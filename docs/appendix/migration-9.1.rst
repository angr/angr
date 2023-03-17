Migrating to angr 9.1
=====================

angr 9.1 is here!

Calling Conventions and Prototypes
----------------------------------

The main change motivating angr 9.1 is `this large refactor of SimCC <https://github.com/angr/angr/pull/2961>`_.
Here are the breaking changes:

SimCCs can no longer be customized
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you were using the ``sp_delta``, ``args``, or ``ret_val`` parameters to SimCC, you should use the new class
``SimCCUsercall``, which lets (requires) you to be explicit about the locations of each argument.

Passing SimTypes is now mandatory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Every method call on SimCC which interacts with typed data now requires a SimType to be passed in.
Previously, the use of ``is_fp`` and ``size`` was optional, but now these parameters will no longer be accepted and a
``SimType`` will be required.

This has some fairly non-intuitive consequences - in order to accommodate more esoteric calling conventions (think: passing large structs by value via an "invisible reference") you have to specify a function's return type before you can extract any of its arguments.

Additionally, some non-cc interfaces, such as ``call_state`` and ``callable`` and ``SimProcedure.call()``, now *require* a prototype to be passed to them.
You'd be surprised how many bugs we found in our own code from enforcing this requirement!

PointerWrapper has a new parameter
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Imagine you're passing something into a function which has a parameter of type ``char*``.
Is this a pointer to a single char or a pointer to an array of chars?
The answer changes how we typecheck the values you pass in.
If you're passing a PointerWrapper wrapping a large value which should be treated as an array of chars, you should construct your pointerwrapper as ``PointerWrapper(foo, buffer=True)``.
The buffer argument to PointerWrapper now instructs SimCC to treat the data to be serialized as an array of the child type instead of as a scalar.

``func_ty`` -> ``prototype``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Every usage of the name func_ty has been replaced with the name prototype.
This was done for consistency between the static analysis code and the dynamic FFI.
