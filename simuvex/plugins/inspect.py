# TODO: SimValue being able to compare two symbolics for is_solution

import logging
l = logging.getLogger("simuvex.plugins.inspect")

event_types = {
    'mem_read',
    'mem_write',
    'address_concretization',
    'reg_read',
    'reg_write',
    'tmp_read',
    'tmp_write',
    'expr',
    'statement',
    'instruction',
    'irsb',
    'constraints',
    'exit',
    'symbolic_variable',
    'call',
    'syscall',
    'path_step',
    'cfg_handle_entry',
}

inspect_attributes = {
    'mem_read_address',
    'mem_read_expr',
    'mem_read_length',

    'mem_write_address',
    'mem_write_expr',
    'mem_write_length',

    'reg_read_offset',
    'reg_read_expr',
    'reg_read_length',

    'reg_write_offset',
    'reg_write_expr',
    'reg_write_length',

    'tmp_read_num',
    'tmp_read_expr',

    'tmp_write_num',
    'tmp_write_expr',

    'expr',
    'statement',
    'instruction',
    'address',
    'added_constraints',
    'function_name',

    'exit_target',
    'exit_guard',
    'exit_jumpkind',
    'backtrace',

    'symbolic_name',
    'symbolic_size',
    'symbolic_expr',

    'address_concretization_strategy',
    'address_concretization_action',
    'address_concretization_memory',
    'address_concretization_expr',
    'address_concretization_result',
    'address_concretization_add_constraints',

    'syscall_name'
    }

BP_BEFORE = 'before'
BP_AFTER = 'after'
BP_BOTH = 'both'

BP_IPDB = 'ipdb'
BP_IPYTHON = 'ipython'

class BP(object):
    """
    A breakpoint.
    """
    def __init__(self, when=BP_BEFORE, enabled=None, condition=None, action=None, **kwargs):
        if len(set([ k.replace("_unique", "") for k in kwargs.keys()]) - set(inspect_attributes)) != 0:
            raise ValueError("Invalid inspect attribute(s) %s passed in. Should be one of %s, or their _unique option." % (kwargs, inspect_attributes))

        self.kwargs = kwargs

        self.enabled = True if enabled is None else enabled
        self.condition = condition
        self.action = action
        self.when = when

    def check(self, state, when):
        """
        Checks state `state` to see if the breakpoint should fire.

        :param state:   The state.
        :param when:    Whether the check is happening before or after the event.
        :return:        A boolean representing whether the checkpoint should fire.
        """
        ok = self.enabled and (when == self.when or self.when == BP_BOTH)
        if not ok:
            return ok
        l.debug("... after enabled and when: %s", ok)

        for a in [ _ for _ in self.kwargs.keys() if not _.endswith("_unique") ]:
            current_expr = getattr(state.inspect, a)
            needed = self.kwargs.get(a, None)

            l.debug("... checking condition %s", a)

            if current_expr is None and needed is None:
                l.debug("...... both None, True")
                c_ok = True
            elif current_expr is not None and needed is not None:
                if state.se.solution(current_expr, needed):
                    l.debug("...... is_solution!")
                    c_ok = True
                else:
                    l.debug("...... not solution...")
                    c_ok = False

                if c_ok and self.kwargs.get(a+'_unique', True):
                    l.debug("...... checking uniqueness")
                    if not state.se.unique(current_expr):
                        l.debug("...... not unique")
                        c_ok = False
            else:
                l.debug("...... one None, False")
                c_ok = False

            ok = ok and c_ok
            if not ok:
                return ok
            l.debug("... after condition %s: %s", a, ok)

        ok = ok and (self.condition is None or self.condition(state))
        l.debug("... after condition func: %s", ok)
        return ok

    def fire(self, state):
        """
        Trigger the breakpoint.

        :param state:   The state.
        """
        if self.action is None or self.action == BP_IPDB:
            import ipdb; ipdb.set_trace() #pylint:disable=F0401
        elif self.action == BP_IPYTHON:
            import IPython
            shell = IPython.terminal.embed.InteractiveShellEmbed()
            shell.mainloop(display_banner="This is an ipython shell for you to happily debug your state!\n" + \
                           "The state can be accessed through the variable 'state'. You can\n" +\
                           "make modifications, then exit this shell to resume your analysis.")
        else:
            self.action(state)

    def __repr__(self):
        return "<BP %s-action with conditions %r, %s condition func, %s action func>" % \
               (self.when, self.kwargs, "no" if self.condition is None else "with", "no" if self.action is None
               else "with")

from .plugin import SimStatePlugin


class SimInspector(SimStatePlugin):
    """
    SimInspector.
    """
    BP_AFTER = BP_AFTER
    BP_BEFORE = BP_BEFORE
    BP_BOTH = BP_BOTH

    def __init__(self):
        SimStatePlugin.__init__(self)
        self._breakpoints = { }
        for t in event_types:
            self._breakpoints[t] = [ ]

        for i in inspect_attributes:
            setattr(self, i, None)

    def __dir__(self):
        return sorted(set(dir(super(SimInspector, self)) + dir(inspect_attributes) + dir(self.__class__)))

    def action(self, event_type, when, **kwargs):
        """
        Called from within SimuVEX when events happens. This function checks all breakpoints registered for that event
        and fires the ones whose conditions match.
        """
        l.debug("Event %s (%s) firing...", event_type, when)
        for k,v in kwargs.iteritems():
            if k not in inspect_attributes:
                raise ValueError("Invalid inspect attribute %s passed in. Should be one of: %s" % (k, inspect_attributes))
            #l.debug("... %s = %r", k, v)
            l.debug("... setting %s", k)
            setattr(self, k, v)

        for bp in self._breakpoints[event_type]:
            l.debug("... checking bp %r", bp)
            if bp.check(self.state, when):
                l.debug("... FIRE")
                bp.fire(self.state)

    def make_breakpoint(self, event_type, *args, **kwargs):
        """
        Creates and adds a breakpoint which would trigger on `event_type`. Additional arguments are passed to the
        :class:`BP` constructor.

        :return:    The created breakpoint, so that it can be removed later.
        """
        bp = BP(*args, **kwargs)
        self.add_breakpoint(event_type, bp)
        return bp

    b = make_breakpoint

    def add_breakpoint(self, event_type, bp):
        """
        Adds a breakpoint which would trigger on `event_type`.

        :param event_type:  The event type to trigger on
        :param bp:          The breakpoint
        :return:            The created breakpoint.
        """
        if event_type not in event_types:
            raise ValueError("Invalid event type %s passed in. Should be one of: %s" % (event_type,
                                                                                        ", ".join(event_types))
                             )
        self._breakpoints[event_type].append(bp)

    def remove_breakpoint(self, event_type, bp):
        """
        Removes a breakpoint.

        :param bp:  The breakpoint to remove.
        """
        self._breakpoints[event_type].remove(bp)

    def copy(self):
        c = SimInspector()
        for i in inspect_attributes:
            setattr(c, i, getattr(self, i))

        for t,a in self._breakpoints.iteritems():
            c._breakpoints[t].extend(a)
        return c

    def downsize(self):
        """
        Remove previously stored attributes from this plugin instance to save memory.
        This method is supposed to be called by breakpoint implementors. A typical workflow looks like the following :

        >>> # Add `attr0` and `attr1` to `self.state.inspect`
        >>> self.state.inspect(xxxxxx, attr0=yyyy, attr1=zzzz)
        >>> # Get new attributes out of SimInspect in case they are modified by the user
        >>> new_attr0 = self.state._inspect.attr0
        >>> new_attr1 = self.state._inspect.attr1
        >>> # Remove them from SimInspect
        >>> self.state._inspect.downsize()
        """
        for k in inspect_attributes:
            if hasattr(self, k):
                setattr(self, k, None)

    def _combine(self, others):
        for t in event_types:
            seen = { id(e) for e in self._breakpoints[t] }
            for o in others:
                for b in o._breakpoints[t]:
                    if id(b) not in seen:
                        self._breakpoints[t].append(b)
                        seen.add(id(b))
        return False

    def merge(self, others, merge_conditions):
        return self._combine(others)

    def widen(self, others):
        return self._combine(others)

SimInspector.register_default('inspector', SimInspector)
