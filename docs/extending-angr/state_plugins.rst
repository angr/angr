State Plugins
=============

If you want to store some data on a state and have that information propagated
from successor to successor, the easiest way to do this is with
``state.globals``. However, this can become obnoxious with large amounts of
interesting data, doesn't work at all for merging states, and isn't very
object-oriented.

The solution to these problems is to write a *State Plugin* - an appendix to the
state that holds data and implements an interface for dealing with the lifecycle
of a state.

My First Plugin
---------------

Let's get started! All state plugins are implemented as subclasses of
``SimStatePlugin``. Once you've read this document, you can use the API
reference for this class :py:class:`angr.state_plugins.plugin.SimStatePlugin` to
quickly review the semantics of all the interfaces you should implement.

The most important method you need to implement is ``copy``: it should be
annotated with the ``memo`` staticmethod and take a dict called the
"memo"---these'll be important later---and returns a copy of the plugin. Short
of that, you can do whatever you want. Just make sure to call the superclass
initializer!

.. code-block:: python

   >>> import angr
   >>> class MyFirstPlugin(angr.SimStatePlugin):
   ...     def __init__(self, foo):
   ...         super(MyFirstPlugin, self).__init__()
   ...         self.foo = foo
   ...
   ...     @angr.SimStatePlugin.memo
   ...     def copy(self, memo):
   ...         return MyFirstPlugin(self.foo)

   >>> state = angr.SimState(arch='AMD64')
   >>> state.register_plugin('my_plugin', MyFirstPlugin('bar'))
   >>> assert state.my_plugin.foo == 'bar'

   >>> state2 = state.copy()
   >>> state.my_plugin.foo = 'baz'
   >>> state3 = state.copy()
   >>> assert state2.my_plugin.foo == 'bar'
   >>> assert state3.my_plugin.foo == 'baz'

It works! Note that plugins automatically become available as attributes on the
state. ``state.get_plugin(name)`` is also available as a more programmatic
interface.

Where's the state?
------------------

State plugins have access to the state, right? So why isn't it part of the
initializer? It turns out, there are a plethora of issues related to
initialization order and dependency issues, so to simplify things as much as
possible, the state is not part of the initializer but is rather set onto the
state in a separate phase, by using the ``set_state`` method. You can override
this state if you need to do things like propagate the state to subcomponents or
extract architectural information.

.. code-block:: python

   >>> def set_state(self, state):
   ...     super(SimStatePlugin, self).set_state(state)
   ...     self.symbolic_word = claripy.BVS('my_variable', self.state.arch.bits)

Note the ``self.state``! That's what the super ``set_state`` sets up.

However, there's no guarantee on what order the states will be set onto the
plugins in, so if you need to interact with *other plugins* for initialization,
you need to override the ``init_state`` method.

Once again, there's no guarantee on what order these will be called in, so the
rule is to make sure you set yourself up good enough during ``set_state`` so
that if someone else tries to interact with you, no type errors will happen.
Here's an example of a good use of ``init_state``, to map a memory region in the
state. The use of an instance variable (presumably copied as part of ``copy()``)
ensures this only happens the first time the plugin is added to a state.

.. code-block:: python

   >>> def init_state(self):
   ...     if self.region is None:
   ...        self.region = self.state.memory.map_region(SOMEWHERE, 0x1000, 7)

Note: weak references
^^^^^^^^^^^^^^^^^^^^^

``self.state`` is not the state itself, but rather a `weak proxy
<https://docs.python.org/2/library/weakref.html>`_ to the state. You can still
use this object as a normal state, but attempts to store it persistently will
not work.

Merging
-------

The other element besides copying in the state lifecycle is merging. As input
you get the plugins to merge and a list of "merge conditions" - symbolic
booleans that are the "guard conditions" describing when the values from each
state should actually apply.

The important properties of the merge conditions are:


* They are mutually exclusive and span an entire domain - exactly one may be
  satisfied at once, and there will be additional constraints to ensure that at
  least one must be satisfied.
* ``len(merge_conditions)`` == len(others) + 1, since ``self`` counts too.
* ``zip(merge_conditions, [self] + others)`` will correctly pair merge
  conditions with plugins.

During the merge function, you should *mutate* ``self`` to become the merged
version of itself and all the others, with respect to the merge conditions. This
involves using the if-then-else structure that claripy provides. Here is an
example of constructing this merged structure by merging a bitvector instance
variable called ``myvar``, producing a binary tree of if-then-else expressions
searching for the correct condition:

.. code-block:: python

   for other_plugin, condition in zip(others, merge_conditions[1:]): # chop off self's condition
       self.myvar = claripy.If(condition, other_plugin.myvar, self.myvar)

This is such a common construction that we provide a utility to perform it
automatically: ``claripy.ite_cases``. The following code snippet is identical to
the previous one:

.. code-block:: python

   self.myvar = claripy.ite_cases(zip(merge_conditions[1:], [o.myvar for o in others]), self.myvar)

Keep in mind that like the rest of the top-level claripy functions,
``ite_cases`` and ``If`` are also available from ``state.solver``, and these
versions will perform SimActionObject unwrapping if applicable.

Common Ancestor
^^^^^^^^^^^^^^^

The full prototype of the ``merge`` interface is ``def merge(self, others,
merge_conditions, common_ancestor=None)``. ``others`` and ``merge_conditions``
have been discussed in depth already.

The common ancestor is the instance of the plugin from the most recent common
ancestor of the states being merged. It may not be available for all merges, in
which case it will be None. There are no rules for how exactly you should use
this to improve the quality of your merges, but you may find it useful in more
complex setups.

Widening
--------

There is another kind of merging called *widening* which takes several states
and produces a more general state. It is used during static analysis.

.. todo:: Explain what this means

Serialization
-------------

In order to support serialization of states which contain your plugin, you
should implement the ``__getstate__``/``__setstate__`` magic method pair. Keep
in mind the following guidelines:


* Your serialization result should *not* include the state.
* After deserialization, ``set_state()`` will be called again.

This means that plugins are "detached" from the state and serialized in an
isolated environment, and then reattached to the state on deserialization.

Plugins all the way down
------------------------

You may have components within your state plugins which are large and
complicated and start breaking object-orientation in order to make copy/merge
work well with the state lifecycle. You're in luck! Things can be state plugins
even if they aren't directly attached to a state. A great example of this is
``SimFile``, which is a state plugin but is stored in the filesystem plugin, and
is never used with ``SimState.register_plugin``. When you're doing this, there
are a handful of rules to remember which will keep your plugins safe and happy:


* Annotate your copy function with ``@SimStatePlugin.memo``.
* In order to prevent *divergence* while copying multiple references to the same
  plugin, make sure you're passing the memo (the argument to copy) to the
  ``.copy`` of any subplugins. This with the previous point will preserve object
  identity.
* In order to prevent *duplicate merging* while merging multiple references to
  the same plugin, there should be a concept of the "owner" of each instance,
  and only the owner should run the merge routine.
* While passing arguments down into sub-plugins ``merge()`` routines, make sure
  you unwrap ``others`` and ``common_ancestor`` into the appropriate types. For
  example, if ``PluginA`` contains a ``PluginB``, the former should do the
  following:

.. code-block:: python

   >>> def merge(self, others, merge_conditions, common_ancestor=None):
   ...     # ... merge self
   ...     self.plugin_b.merge([o.plugin_b for o in others], merge_conditions,
   ...         common_ancestor=None if common_ancestor is None else common_ancestor.plugin_b)

Setting Defaults
----------------

To make it so that a plugin will automatically become available on a state when
requested, without having to register it with the state first, you can register
it as a *default*. The following code example will make it so that whenever you
access ``state.my_plugin``, a new instance of ``MyPlugin`` will be instantiated
and registered with the state.

.. code-block:: python

   MyPlugin.register_default('my_plugin')
