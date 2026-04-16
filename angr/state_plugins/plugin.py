from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from functools import wraps
from typing import TYPE_CHECKING, Any, Generic, Protocol, TypeVar, cast

from angr.misc.ux import once

if TYPE_CHECKING:
    from angr.sim_state import SimState

# pylint: disable=import-outside-toplevel


l = logging.getLogger(name=__name__)

S_co = TypeVar("S_co", covariant=True)


class _CopyFunc(Protocol, Generic[S_co]):
    """
    Function wrapping copy method for memo tracking.
    """

    def __call__(self, _self: Any, memo: dict[int, Any] | None = None) -> S_co: ...


class SimStatePlugin:
    """
    This is a base class for SimState plugins. A SimState plugin will be copied along with the state when the state is
    branched. They are intended to be used for things such as tracking open files, tracking heap details, and providing
    storage and persistence for SimProcedures.
    """

    STRONGREF_STATE = False

    def __init__(self) -> None:
        self.state: SimState[Any, Any] = cast("SimState[Any, Any]", None)

    def set_state(self, state) -> None:
        """
        Sets a new state (for example, if the state has been branched)
        """
        self.state = state._get_weakref()

    def set_strongref_state(self, state) -> None:
        pass

    def __getstate__(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["state"] = None
        return d

    @staticmethod
    def memo(f: Callable[[Any, dict[int, Any]], S_co]) -> _CopyFunc[S_co]:
        """
        A decorator function you should apply to ``copy``
        """

        @wraps(f)
        def inner(self: Any, memo: dict[int, Any] | None = None) -> S_co:
            if memo is None:
                memo = {}
            if id(self) in memo:
                return memo[id(self)]
            c = f(self, memo)
            memo[id(self)] = c
            return c

        return cast(_CopyFunc[S_co], inner)

    @memo
    def copy(self, _memo: dict[int, Any]) -> SimStatePlugin:
        """
        Should return a copy of the plugin without any state attached. Should check the memo first, and add itself to
        memo if it ends up making a new copy.

        In order to simplify using the memo, you should annotate implementations of this function with
        ``SimStatePlugin.memo``

        The base implementation of this function constructs a new instance of the plugin's class without calling its
        initializer. If you super-call down to it, make sure you instantiate all the fields in your copy method!

        :param memo:    A dictionary mapping object identifiers (id(obj)) to their copied instance.  Use this to avoid
                        infinite recursion and diverged copies.
        """
        o = type(self).__new__(type(self))
        o.state = None  # type: ignore
        return o

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint:disable=unused-argument
        """
        Should merge the state plugin with the provided others. This will be called by ``state.merge()`` after copying
        the target state, so this should mutate the current instance to merge with the others.

        Note that when multiple instances of a single plugin object (for example, a file) are referenced in the state,
        it is important that merge only ever be called once. This should be solved by designating one of the plugin's
        referees as the "real owner", who should be the one to actually merge it. This technique doesn't work to
        resolve the similar issue that arises during copying because merging doesn't produce a new reference to insert.

        There will be n ``others`` and n+1 merge conditions, since the first condition corresponds to self.
        To match elements up to conditions, say ``zip([self] + others, merge_conditions)``

        When implementing this, make sure that you "deepen" both ``others`` and ``common_ancestor`` before calling
        sub-elements' merge methods, e.g.

        .. code-block:: python

           self.foo.merge(
               [o.foo for o in others],
               merge_conditions,
               common_ancestor=common_ancestor.foo if common_ancestor is not None else None
           )

        During static analysis, merge_conditions can be None, in which case you should use
        ``state.solver.union(values)``.
        TODO: fish please make this less bullshit

        There is a utility ``claripy.ite_cases`` which will help with constructing arbitrarily large merged ASTs.
        Use it like ``self.bar = claripy.ite_cases(zip(conditions[1:], [o.bar for o in others]), self.bar)``

        :param others: the other state plugins to merge with
        :param merge_conditions: a symbolic condition for each of the plugins
        :param common_ancestor: a common ancestor of this plugin and the others being merged
        :returns: True if the state plugins are actually merged.
        :rtype: bool
        """
        raise NotImplementedError(f"merge() not implement for {self.__class__.__name__}")

    def widen(self, others: Iterable[SimStatePlugin]) -> bool:  # pylint:disable=unused-argument
        """
        The widening operation for plugins. Widening is a special kind of merging that produces a more general state
        from several more specific states. It is used only during intensive static analysis. The same behavior
        regarding copying and mutation from ``merge`` should be followed.

        :param others: the other state plugins to widen with

        :returns: True if the state plugin is actually widened.
        :rtype: bool
        """
        raise NotImplementedError(f"widen() not implemented for {self.__class__.__name__}")

    @classmethod
    def register_default(cls, name: str, xtr: type[SimStatePlugin] | str | None = None) -> None:
        if cls is SimStatePlugin:
            if once("simstateplugin_register_default deprecation"):
                l.critical(
                    "SimStatePlugin.register_default(name, cls) is deprecated, "
                    "please use SimState.register_default(name)"
                )

            if xtr is None or isinstance(xtr, str):
                raise TypeError(
                    "When calling SimStatePlugin.register_default, "
                    "the plugin class must be provided as the second argument."
                )

            from angr.sim_state import SimState

            SimState.register_default(name, xtr)

        else:
            if xtr is cls:
                if once("simstateplugin_register_default deprecation case 2"):
                    l.critical(
                        "SimStatePlugin.register_default(name, cls) is deprecated, "
                        "please use cls.register_default(name)"
                    )
                xtr = None
            elif not isinstance(xtr, str) and xtr is not None:
                raise TypeError(
                    "When calling a plugin subclass's register_default, "
                    "the second argument must be completely omitted or a preset string."
                )

            from angr.sim_state import SimState

            SimState.register_default(name, cls, xtr if xtr is not None else "default")

    def init_state(self) -> None:
        """
        Use this function to perform any initialization on the state at plugin-add time
        """
