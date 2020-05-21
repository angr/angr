from typing import cast

import angr # type annotations; pylint: disable=unused-import
import logging

from ..misc.ux import once

l = logging.getLogger(name=__name__)

class SimStatePlugin(object):
    """
    This is a base class for SimState plugins. A SimState plugin will be copied along with the state when the state is
    branched. They are intended to be used for things such as tracking open files, tracking heap details, and providing
    storage and persistence for SimProcedures.
    """

    STRONGREF_STATE = False

    def __init__(self):
        self.state = cast(angr.SimState, None) # type: angr.SimState

    def set_state(self, state):
        """
        Sets a new state (for example, if the state has been branched)
        """
        self.state = state._get_weakref()

    def set_strongref_state(self, state):
        pass

    def __getstate__(self):
        d = dict(self.__dict__)
        d['state'] = None
        return d

    def copy(self, _memo):
        """
        Should return a copy of the plugin without any state attached. Should check the memo first, and add itself to
        memo if it ends up making a new copy.

        In order to simplify using the memo, you should annotate implementations of this function with
        ``SimStatePlugin.memo``

        :param memo:    A dictionary mapping object identifiers (id(obj)) to their copied instance.  Use this to avoid
                        infinite recursion and diverged copies.
        """
        raise NotImplementedError("copy() not implement for %s" % self.__class__.__name__)

    @staticmethod
    def memo(f):
        """
        A decorator function you should apply to ``copy``
        """
        def inner(self, memo=None, **kwargs):
            if memo is None:
                memo = {}
            if id(self) in memo:
                return memo[id(self)]
            else:
                c = f(self, memo, **kwargs)
                memo[id(self)] = c
                return c
        return inner

    def merge(self, _others, _merge_conditions, _common_ancestor=None): #pylint:disable=unused-argument
        """
        Should merge the state plugin with the provided others. This will be called by ``state.merge()`` after copying
        the target state, so this should mutate the current instance to merge with the others.

        Note that when multiple instances of a single plugin object (for example, a file) are referenced in the state,
        it is important that merge only ever be called once. This should be solved by designating one of the plugin's referees as the "real owner", who should be the one to actually merge it.
        This technique doesn't work to resolve the similar issue that arises during copying because merging doesn't produce a new reference to insert.

        There will be n ``others`` and n+1 merge conditions, since the first condition corresponds to self.
        To match elements up to conditions, say ``zip([self] + others, merge_conditions)``

        When implementing this, make sure that you "deepen" both ``others`` and ``common_ancestor`` before calling sub-elements' merge methods,
        e.g. ``self.foo.merge([o.foo for o in others], merge_conditions, common_ancestor=common_ancestor.foo if common_ancestor is not None else None)``.

        During static analysis, merge_conditions can be None, in which case you should use ``state.solver.union(values)``.
        TODO: fish please make this less bullshit

        There is a utility ``state.solver.ite_cases`` which will help with constructing arbitrarily large merged ASTs.
        Use it like ``self.bar = self.state.solver.ite_cases(zip(conditions[1:], [o.bar for o in others]), self.bar)``

        :param others: the other state plugins to merge with
        :param merge_conditions: a symbolic condition for each of the plugins
        :param common_ancestor: a common ancestor of this plugin and the others being merged
        :returns: True if the state plugins are actually merged.
        :rtype: bool
        """
        raise NotImplementedError("merge() not implement for %s" % self.__class__.__name__)

    def widen(self, _others): #pylint:disable=unused-argument
        """
        The widening operation for plugins. Widening is a special kind of merging that produces a more general state
        from several more specific states. It is used only during intensive static analysis. The same behavior
        regarding copying and mutation from ``merge`` should be followed.

        :param others: the other state plugin

        :returns: True if the state plugin is actually widened.
        :rtype: bool
        """
        raise NotImplementedError('widen() not implemented for %s' % self.__class__.__name__)

    @classmethod
    def register_default(cls, name, xtr=None):
        if cls is SimStatePlugin:
            if once('simstateplugin_register_default deprecation'):
                l.critical("SimStatePlugin.register_default(name, cls) is deprecated, please use SimState.register_default(name)")

            from angr.sim_state import SimState
            SimState.register_default(name, xtr)

        else:
            if xtr is cls:
                if once('simstateplugin_register_default deprecation case 2'):
                    l.critical("SimStatePlugin.register_default(name, cls) is deprecated, please use cls.register_default(name)")
                xtr = None

            from angr.sim_state import SimState
            SimState.register_default(name, cls, xtr if xtr is not None else 'default')

    def init_state(self):
        """
        Use this function to perform any initialization on the state at plugin-add time
        """
        pass
