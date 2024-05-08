# pylint: disable=no-self-use,unused-private-member

import abc
import logging
import threading
import angr

from archinfo.arch_soot import SootAddressDescriptor

l = logging.getLogger(name=__name__)


class SimEngineBase:
    """
    Even more basey of a base class for SimEngine. Used as a base by mixins which want access to the project but for
    which having method `process` (contained in `SimEngine`) doesn't make sense
    """

    def __init__(self, project=None, **kwargs):
        if kwargs:
            raise TypeError("Unused initializer args: " + ", ".join(kwargs.keys()))
        self.project: angr.Project | None = project
        self.state = None

    __tls = ("state",)

    def __getstate__(self):
        return (self.project,)

    def __setstate__(self, state):
        self.project = state[0]
        self.state = None

    def _is_true(self, v):
        return v is True

    def _is_false(self, v):
        return v is False


class SimEngine(SimEngineBase, metaclass=abc.ABCMeta):
    """
    A SimEngine is a class which understands how to perform execution on a state. This is a base class.
    """

    @abc.abstractmethod
    def process(self, state, **kwargs):
        """
        The main entry point for an engine. Should take a state and return a result.

        :param state:   The state to proceed from
        :return:        The result. Whatever you want ;)
        """


class TLSMixin:
    """
    Mix this class into any class that defines __tls to make all of the attributes named in that list into
    thread-local properties.

    MAGIC MAGIC MAGIC
    """

    def __new__(cls, *args, **kwargs):  # pylint:disable=unused-argument
        obj = super().__new__(cls)
        obj.__local = threading.local()
        return obj

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        for subcls in cls.mro():
            for attr in subcls.__dict__.get("_%s__tls" % subcls.__name__, ()):
                if attr.startswith("__"):
                    attr = f"_{subcls.__name__}{attr}"

                if hasattr(cls, attr):
                    if type(getattr(cls, attr, None)) is not TLSProperty:
                        raise Exception("Programming error: %s is both in __tls and __class__" % attr)
                else:
                    setattr(cls, attr, TLSProperty(attr))


class TLSProperty:  # pylint:disable=missing-class-docstring
    def __init__(self, name):
        self.name = name

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return getattr(instance._TLSMixin__local, self.name)

    def __set__(self, instance, value):
        setattr(instance._TLSMixin__local, self.name, value)

    def __delete__(self, instance):
        delattr(instance._TLSMixin__local, self.name)


class SuccessorsMixin(SimEngine):
    """
    A mixin for SimEngine which implements ``process`` to perform common operations related to symbolic execution
    and dispatches to a ``process_successors`` method to fill a SimSuccessors object with the results.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.successors: SimSuccessors | None = None

    __tls = ("successors",)

    def process(self, state, *args, **kwargs):  # pylint:disable=unused-argument
        """
        Perform execution with a state.

        You should only override this method in a subclass in order to provide the correct method signature and
        docstring. You should override the ``_process`` method to do your actual execution.

        :param state:       The state with which to execute. This state will be copied before
                            modification.
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        inline = kwargs.pop("inline", False)
        force_addr = kwargs.pop("force_addr", None)

        ip = state._ip
        addr = (
            (ip if isinstance(ip, SootAddressDescriptor) else state.solver.eval(ip))
            if force_addr is None
            else force_addr
        )

        # make a copy of the initial state for actual processing, if needed
        if not inline and o.COPY_STATES in state.options:
            new_state = state.copy()
        else:
            new_state = state
        # enforce this distinction
        old_state = state
        del state
        self.state = new_state

        # we have now officially begun the stepping process! now is where we "cycle" a state's
        # data - move the "present" into the "past" by pushing an entry on the history stack.
        # nuance: make sure to copy from the PREVIOUS state to the CURRENT one
        # to avoid creating a dead link in the history, messing up the statehierarchy
        new_state.register_plugin("history", old_state.history.make_child())
        new_state.history.recent_bbl_addrs.append(addr)
        if new_state.arch.unicorn_support:
            new_state.scratch.executed_pages_set = {addr & ~0xFFF}

        self.successors = SimSuccessors(addr, old_state)

        new_state._inspect(
            "engine_process", when=BP_BEFORE, sim_engine=self, sim_successors=self.successors, address=addr
        )
        self.successors = new_state._inspect_getattr("sim_successors", self.successors)
        try:
            self.process_successors(self.successors, **kwargs)
        except SimException as e:
            if o.EXCEPTION_HANDLING not in old_state.options:
                raise
            old_state.project.simos.handle_exception(self.successors, self, e)

        new_state._inspect("engine_process", when=BP_AFTER, sim_successors=self.successors, address=addr)
        self.successors = new_state._inspect_getattr("sim_successors", self.successors)

        # downsizing
        if new_state.supports_inspect:
            new_state.inspect.downsize()
        # if not TRACK, clear actions on OLD state
        # if o.TRACK_ACTION_HISTORY not in old_state.options:
        #    old_state.history.recent_events = []

        # fix up the descriptions...
        description = str(self.successors)
        l.info("Ticked state: %s", description)
        for succ in self.successors.all_successors:
            succ.history.recent_description = description
        for succ in self.successors.flat_successors:
            succ.history.recent_description = description

        return self.successors

    def process_successors(self, successors, **kwargs):
        """
        Implement this function to fill out the SimSuccessors object with the results of stepping state.

        In order to implement a model where multiple mixins can potentially handle a request, a mixin may implement
        this method and then perform a super() call if it wants to pass on handling to the next mixin.

        Keep in mind python's method resolution order when composing multiple classes implementing this method.
        In short: left-to-right, depth-first, but deferring any base classes which are shared by multiple subclasses
        (the merge point of a diamond pattern in the inheritance graph) until the last point where they would be
        encountered in this depth-first search. For example, if you have classes A, B(A), C(B), D(A), E(C, D), then the
        method resolution order will be E, C, B, D, A.

        :param state:           The state to manipulate
        :param successors:      The successors object to fill out
        :param kwargs:          Any extra arguments. Do not fail if you are passed unexpected arguments.
        """
        successors.processed = False  # mark failure


# pylint:disable=wrong-import-position
from .. import sim_options as o
from ..state_plugins.inspect import BP_BEFORE, BP_AFTER
from .successors import SimSuccessors
from ..errors import SimException
