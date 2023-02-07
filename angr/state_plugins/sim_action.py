# This module contains data structures for handling memory, code, and register references.

import logging

l = logging.getLogger(name=__name__)

_noneset = frozenset()

from .sim_event import SimEvent


class SimAction(SimEvent):
    """
    A SimAction represents a semantic action that an analyzed program performs.
    """

    # __slots__ = [ 'bbl_addr', 'inst_addr', 'stmt_idx' ]

    TMP = "tmp"
    REG = "reg"
    MEM = "mem"
    _MAX_ACTION_ID = -1

    def __init__(self, state, region_type):
        """
        Initializes the SimAction.

        :param state: the state that's the SimAction is taking place in.
        """
        SimEvent.__init__(self, state, "action")
        self.type = region_type
        SimAction._MAX_ACTION_ID += 1
        self._action_id = SimAction._MAX_ACTION_ID

    def __repr__(self):
        if self.sim_procedure is not None:
            location = "%s()" % self.sim_procedure.display_name
        else:
            if self.stmt_idx is not None:
                location = "0x%x:%d" % (self.ins_addr, self.stmt_idx)  # TODO: Revert this!
            else:
                location = "0x%x" % self.bbl_addr
        return f"<{self.__class__.__name__} {location} {self._desc()}>"

    def _desc(self):
        raise NotImplementedError()

    @staticmethod
    def _make_object(v):
        if v is None:
            return None
        elif isinstance(v, SimActionObject):
            return v
        else:
            return SimActionObject(v, reg_deps=None, tmp_deps=None)

    @staticmethod
    def _copy_object(v):
        if isinstance(v, SimActionObject):
            return v.copy()
        else:
            return None

    @property
    def all_objects(self):
        raise NotImplementedError()

    @property
    def is_symbolic(self):
        raise NotImplementedError()

    @property
    def tmp_deps(self):
        return frozenset.union(*[v.tmp_deps for v in self.all_objects])

    @property
    def reg_deps(self):
        return frozenset.union(*[v.reg_deps for v in self.all_objects])

    def _copy_objects(self, c):
        raise NotImplementedError()

    def copy(self):
        c = self._copy_event()
        self._copy_objects(c)

        return c

    def downsize(self):
        """
        Clears some low-level details (that take up memory) out of the SimAction.
        """
        pass


class SimActionExit(SimAction):
    """
    An Exit action represents a (possibly conditional) jump.
    """

    CONDITIONAL = "conditional"
    DEFAULT = "default"

    def __init__(self, state, target, condition=None, exit_type=None):
        super().__init__(state, "exit")
        if exit_type is not None:
            self.exit_type = exit_type
        elif condition is None:
            self.exit_type = SimActionExit.CONDITIONAL
        else:
            self.exit_type = SimActionExit.DEFAULT

        self.target = self._make_object(target)
        self.condition = self._make_object(condition)

    def _desc(self):
        return self.exit_type

    @property
    def all_objects(self):
        return [a for a in (self.target, self.condition) if a is not None]

    @property
    def is_symbolic(self):
        return getattr(self.target, "symbolic", False)

    def _copy_objects(self, c):
        c.exit_type = self.exit_type
        c.target = self._copy_object(self.target)
        c.condition = self._copy_object(self.condition)


class SimActionConstraint(SimAction):
    """
    A constraint action represents an extra constraint added during execution of a path.
    """

    def __init__(self, state, constraint, condition=None):
        super().__init__(state, "constraint")

        self.constraint = self._make_object(constraint)
        self.condition = self._make_object(condition)

    @property
    def all_objects(self):
        return [a for a in (self.constraint, self.condition) if a is not None]

    @property
    def is_symbolic(self):
        return getattr(self.constraint, "symbolic", False)

    def _copy_objects(self, c):
        c.constraint = self._copy_object(self.constraint)
        c.condition = self._copy_object(self.condition)

    def _desc(self):
        s = "%s" % str(self.constraint)
        if self.condition is not None:
            s += " (cond)"
        return s


class SimActionOperation(SimAction):
    """
    An action representing an operation between variables and/or constants.
    """

    def __init__(self, state, op, exprs, result):
        super().__init__(state, "operation")

        self.op = op
        self.exprs = exprs

        self.result = result

    @property
    def all_objects(self):
        return [ex for ex in self.exprs if isinstance(ex, SimActionObject)]

    @property
    def is_symbolic(self):
        return any(getattr(ex, "symbolic", False) for ex in self.exprs)

    def _copy_objects(self, c):
        c.op = self.op
        c.exprs = self.exprs[::]
        c.result = self.result

    def _desc(self):
        return "operation/%s" % (self.op)


class SimActionData(SimAction):
    """
    A Data action represents a read or a write from memory, registers or a file.
    """

    # __slots__ = [ 'objects' ]

    READ = "read"
    WRITE = "write"
    OPERATE = "operate"

    def __init__(
        self,
        state,
        region_type,
        action,
        tmp=None,
        addr=None,
        size=None,
        data=None,
        condition=None,
        fallback=None,
        fd=None,
    ):
        super().__init__(state, region_type)
        self.action = action

        self._reg_dep = (
            _noneset
            if addr is None or action != SimActionData.READ or not isinstance(addr, int)
            else frozenset((addr,))
        )
        self._tmp_dep = _noneset if tmp is None or action != SimActionData.READ else frozenset((tmp,))

        self.tmp = tmp
        self.offset = None
        if region_type == "reg":
            if isinstance(addr, int):
                self.offset = addr
            else:
                if addr.symbolic:
                    # FIXME: we should fix it by allowing .offset taking ASTs instead of concretizing it right away
                    l.warning("Concretizing a symbolic register offset in SimActionData.")
                    self.offset = state.solver.eval(addr)
                else:
                    # it's not symbolic
                    self.offset = state.solver.eval_one(addr)
        self.addr = self._make_object(addr)
        self.size = self._make_object(size)
        self.data = self._make_object(data)
        self.condition = self._make_object(condition)
        self.fallback = self._make_object(fallback)
        self.fd = self._make_object(fd)

        # these are extra attributes that expose low-level effects, such as the *actual*
        # written value
        self.actual_addrs = None
        # `actual_value` always stores whatever the data looks like in memory from left to right, therefore it's always
        # big-endian (if endianness matters)
        self.actual_value = None
        self.added_constraints = None

    def downsize(self):
        self.actual_addrs = None
        self.actual_value = None
        self.added_constraints = None

    @property
    def all_objects(self):
        return [a for a in [self.addr, self.size, self.data, self.condition, self.fallback, self.fd] if a is not None]

    @property
    def is_symbolic(self):
        return any(getattr(a, "symbolic", False) for a in [self.addr, self.size, self.data] if a is not None)

    @property
    def tmp_deps(self):
        return super().tmp_deps | self._tmp_dep

    @property
    def reg_deps(self):
        return super().reg_deps | self._reg_dep

    @property
    def storage(self):
        def _repr(o):
            if type(o) in {bytes, str, int}:
                return o
            try:
                o = o.ast
            except AttributeError:
                pass
            if type(o) in {bytes, str, int}:
                return o
            return o.shallow_repr()

        if self.type == "reg":
            _size = self.size.ast if isinstance(self.size, SimActionObject) else self.size
            assert isinstance(_size, int)
            storage = self.arch.register_size_names[(self.offset, _size // self.arch.byte_width)]
        elif self.type == "tmp":
            storage = f"tmp_{self.tmp}"
        else:
            storage = self.addr

        return _repr(storage)

    def _desc(self):
        def _repr(o):
            if type(o) in {bytes, str, int}:
                return o
            try:
                o = o.ast
            except AttributeError:
                pass
            if type(o) in {bytes, str, int}:
                return o
            return o.shallow_repr()

        # if self.type == 'reg':
        #     _size = self.size.ast if isinstance(self.size, SimActionObject) else self.size
        #     assert isinstance(_size, int)
        #     storage = self.arch.register_size_names[(self.offset, _size // self.arch.byte_width)]
        # elif self.type == 'tmp':
        #     storage = f'tmp_{self.tmp}'
        # else:
        #     storage = self.addr
        direction = "<<----" if self.action == "write" else "---->>"
        return f"{self.type}/{self.action}: {self.storage}  {direction}  {_repr(self.data)}"

    def _copy_objects(self, c):
        c.action = self.action
        c.tmp = self.tmp
        c.addr = self._copy_object(self.addr)
        c.size = self._copy_object(self.size)
        c.data = self._copy_object(self.data)
        c.condition = self._copy_object(self.condition)
        c.fallback = self._copy_object(self.fallback)
        c.fd = self._copy_object(self.fd)


from .sim_action_object import SimActionObject
