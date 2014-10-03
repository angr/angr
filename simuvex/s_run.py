#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.s_run")

import simuvex.s_options as o
from .s_helpers import get_and_remove, flagged

class SimRunMeta(type):
    def __call__(cls, *args, **kwargs):
        c = cls.make_run(args, kwargs)
        if not hasattr(c.__init__, 'flagged'):
            c.__init__(*args[1:], **kwargs)

            # do some cleanup
            if o.DOWNSIZE_Z3 in c.initial_state.options:
                c.initial_state.downsize()

            # now delete the final state; it should be exported in exits
            if hasattr(c, 'state'):
                c.state.release_plugin('solver_engine')
                delattr(c, 'state')
        return c

    def make_run(cls, args, kwargs):
        state = args[0]
        addr = get_and_remove(kwargs, 'addr')
        inline = get_and_remove(kwargs, 'inline')
        custom_name = get_and_remove(kwargs, 'custom_name')

        c = cls.__new__(cls)
        SimRun.__init__(c, state, addr=addr, inline=inline, custom_name=custom_name)
        return c

class SimRun(object):
    __metaclass__ = SimRunMeta
    #__slots__ = [ 'addr', '_inline', 'initial_state', 'state', '_exits', '_refs', "_custom_name" ]

    @flagged
    def __init__(self, state, addr=None, inline=False, custom_name=None):
        # The address of this SimRun
        self.addr = addr

        # state stuff
        self.initial_state = state
        self._inline = inline
        if not self._inline and o.COW_STATES in self.initial_state.options:
            self.state = self.initial_state.copy()
        else:
            self.state = self.initial_state

        # Initialize the custom_name to None
        self._custom_name = custom_name

        # Intitialize the exits and refs
        self._exits = [ ]
        self._refs = [ ]

        #l.debug("%s created with %d constraints.", self, len(self.initial_state.constraints()))

    def refs(self):
        return self._refs

    def exits(self, reachable=None, symbolic=None, concrete=None):
        concrete = True if concrete is None else concrete

        symbolic_exits = [ ]
        concrete_exits = [ ]
        for e in self._exits:
            symbolic = o.SYMBOLIC in e.state.options if symbolic is None else symbolic

            if e.state.se.symbolic(e.target) and symbolic:
                symbolic_exits.append(e)
            elif concrete:
                concrete_exits.append(e)

        l.debug("Starting exits() with %d exits", len(self._exits))
        l.debug("... considering: %d symbolic and %d concrete", len(symbolic_exits), len(concrete_exits))

        if reachable is not None:
            symbolic_exits = [ e for e in symbolic_exits if e.reachable() == reachable ]
            concrete_exits = [ e for e in concrete_exits if e.reachable() == reachable ]
            l.debug("... reachable: %d symbolic and %d concrete", len(symbolic_exits), len(concrete_exits))

        return symbolic_exits + concrete_exits

    def flat_exits(self, reachable=None, symbolic=None, concrete=None):
        all_exits = [ ]
        for e in self.exits(symbolic=symbolic, concrete=concrete):
            if reachable is None or reachable == e.reachable():
                all_exits.extend(e.split())

        return all_exits

    # Categorize and add a sequence of refs to this run
    def add_refs(self, *refs):
        for r in refs:
            if o.SYMBOLIC not in self.initial_state.options and r.is_symbolic():
                continue

            self._refs.append(r)

    # Categorize and add a sequence of exits to this run
    def add_exits(self, *exits):
        self._exits.extend(exits)

    # Copy the references
    def copy_refs(self, other):
        self.add_refs(*other.refs())

    # Copy the exits
    def copy_exits(self, other):
        self.add_exits(*other.exits())

    # Copy the exits and references of a run.
    def copy_run(self, other):
        self.copy_refs(other)
        self.copy_exits(other)

    @property
    def id_str(self):
        if self._custom_name is not None:
            if self.addr is not None:
                return "%s (at 0x%x)" % (self._custom_name, self.addr)
            else:
                return self._custom_name
        elif self.addr is not None:
            return "0x%x" % self.addr
        else:
            return "uninitialized"

    def __repr__(self):
        return "<SimRun (%s) with addr %s and ID %s>" % (self.__class__.__name__, "0x%x" % self.addr if self.addr is not None else "None", self.id_str)
