# pylint:disable=no-member,import-outside-toplevel
import logging

from . import ExplorationTechnique


l = logging.getLogger(name=__name__)


class PickledStatesBase:
    """
    The base class of pickled states
    """

    def sort(self):
        """
        Sort pickled states.
        """

        raise NotImplementedError()

    def add(self, prio, sid):
        """
        Add a newly pickled state.

        :param int prio:    Priority of the state.
        :param str sid:     Persistent ID of the state.
        :return:            None
        """
        raise NotImplementedError()

    def pop_n(self, n):
        """
        Pop the top N states.

        :param int n:   Number of states to take.
        :return:        A list of states.
        """
        raise NotImplementedError()


class PickledStatesList(PickledStatesBase):
    """
    List-backed pickled state storage.
    """

    def __init__(self):
        self._picked_states = []

    def sort(self):
        self._picked_states.sort()

    def add(self, prio, sid):
        self._picked_states.append((prio, sid))

    def pop_n(self, n):
        ss = self._picked_states[:n]
        self._picked_states[:n] = []
        return ss


class PickledStatesDb(PickledStatesBase):
    """
    Database-backed pickled state storage.
    """

    def __init__(self, db_str="sqlite:///:memory:"):
        from .spiller_db import sqlalchemy, create_engine, Base, OperationalError, sessionmaker

        if sqlalchemy is None:
            raise ImportError(
                f"Cannot import SQLAlchemy. Please install SQLAlchemy before using " f"{self.__class__.__name__}."
            )

        # ORM declarations
        engine = create_engine(db_str)

        # create table
        try:
            Base.metadata.create_all(engine, checkfirst=True)
        except OperationalError:
            # table already exists
            pass

        self.Session = sessionmaker(bind=engine)

    def sort(self):
        pass

    def add(self, prio, sid, taken=False, stash="spilled"):  # pylint:disable=arguments-differ
        from .spiller_db import PickledState

        record = PickledState(id=sid, priority=prio, taken=taken, stash=stash)
        session = self.Session()
        session.add(record)
        session.commit()
        session.close()

    def pop_n(self, n, stash="spilled"):  # pylint:disable=arguments-differ
        from .spiller_db import PickledState

        session = self.Session()
        q = (
            session.query(PickledState)
            .filter_by(taken=False)
            .filter_by(stash=stash)
            .order_by(PickledState.priority)
            .limit(n)
            .all()
        )

        ss = []
        for r in q:
            r.taken = True
            ss.append((r.priority, r.id))
        session.commit()
        session.close()
        return ss

    def get_recent_n(self, n, stash="spilled"):
        from .spiller_db import PickledState

        session = self.Session()
        q = session.query(PickledState).filter_by(stash=stash).order_by(PickledState.timestamp.desc()).limit(n).all()

        ss = []
        for r in q:
            ss.append((r.timestamp, r.id))
        session.close()
        return ss

    def count(self):
        from .spiller_db import PickledState

        session = self.Session()
        q = session.query(PickledState).count()
        session.close()
        return q


class Spiller(ExplorationTechnique):
    """
    Automatically spill states out. It can spill out states to a different stash, spill
    them out to ANA, or first do the former and then (after enough states) the latter.
    """

    def __init__(
        self,
        src_stash="active",
        min=5,
        max=10,  # pylint:disable=redefined-builtin
        staging_stash="spill_stage",
        staging_min=10,
        staging_max=20,
        pickle_callback=None,
        unpickle_callback=None,
        post_pickle_callback=None,
        priority_key=None,
        vault=None,
        states_collection=None,
    ):
        """
        Initializes the spiller.

        :param max:          the number of states that are *not* spilled
        :param src_stash:    the stash from which to spill states (default: active)
        :param staging_stash: the stash *to* which to spill states (default: "spill_stage")
        :param staging_max:  the number of states that can be in the staging stash before things get spilled to ANA
                             (default: None. If staging_stash is set, then this means unlimited, and ANA will not be
                             used).
        :param priority_key: a function that takes a state and returns its numerical priority (MAX_INT is lowest
                             priority). By default, self.state_priority will be used, which prioritizes by object ID.
        :param vault:        an angr.Vault object to handle storing and loading of states. If not provided, an
                             angr.vaults.VaultShelf will be created with a temporary file.
        """
        super().__init__()
        self.max = max
        self.min = min
        self.src_stash = src_stash
        self.staging_stash = staging_stash
        self.staging_max = staging_max
        self.staging_min = staging_min

        # various callbacks
        self.priority_key = priority_key
        self.unpickle_callback = unpickle_callback
        self.pickle_callback = pickle_callback
        self.post_pickle_callback = post_pickle_callback

        # tracking of pickled stuff
        self._pickled_states = PickledStatesList() if states_collection is None else states_collection
        self._ever_pickled = 0
        self._ever_unpickled = 0
        self._vault = vaults.VaultShelf() if vault is None else vault

    def _unpickle(self, n):
        self._pickled_states.sort()
        unpickled = [(sid, self._load_state(sid)) for _, sid in self._pickled_states.pop_n(n)]
        self._ever_unpickled += len(unpickled)
        if self.unpickle_callback:
            for sid, u in unpickled:
                self.unpickle_callback(sid, u)
        return [u for _, u in unpickled]

    def _get_priority(self, state):
        return (self.priority_key or self.state_priority)(state)

    def _pickle(self, states):
        if self.pickle_callback:
            for s in states:
                self.pickle_callback(s)
        self._ever_pickled += len(states)
        for state in states:
            try:
                state_oid = self._store_state(state)
            except RecursionError:
                l.warning(
                    "Couldn't store the state because of a recursion error. This is most likely to be pickle's "
                    "fault. You may try to increase the recursion limit using sys.setrecursionlimit()."
                )
                continue
            prio = self._get_priority(state)
            if self.post_pickle_callback:
                self.post_pickle_callback(state, prio, state_oid)
            self._pickled_states.add(prio, state_oid)

    def _store_state(self, state):
        return self._vault.store(state)

    def _load_state(self, sid):
        return self._vault.load(sid)

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        l.debug(
            "STASH STATUS: active: %d, staging: %d",
            len(simgr.stashes[self.src_stash]),
            len(simgr.stashes[self.staging_stash]),
        )

        states = simgr.stashes[self.src_stash]
        staged_states = simgr.stashes.setdefault(self.staging_stash, []) if self.staging_stash else []

        if len(states) < self.min:
            missing = (self.max + self.min) // 2 - len(states)
            l.debug("Too few states (%d/%d) in stash %s.", len(states), self.min, self.src_stash)
            if self.staging_stash:
                l.debug("... retrieving states from staging stash (%s)", self.staging_stash)
                staged_states.sort(key=self.priority_key or self.state_priority)
                states += staged_states[:missing]
                staged_states[:missing] = []
            else:
                l.debug("... staging stash disabled; unpickling states")
                states += self._unpickle(missing)

        if len(states) > self.max:
            l.debug("Too many states (%d/%d) in stash %s", len(states), self.max, self.src_stash)
            states.sort(key=self.priority_key or self.state_priority)
            staged_states += states[self.max :]
            states[self.max :] = []

        # if we have too few staged states, unpickle up to halfway between max and min
        if len(staged_states) < self.staging_min:
            l.debug("Too few states in staging stash (%s)", self.staging_stash)
            staged_states += self._unpickle((self.staging_min + self.staging_max) // 2 - len(staged_states))

        if len(staged_states) > self.staging_max:
            l.debug("Too many states in staging stash (%s)", self.staging_stash)
            self._pickle(staged_states[self.staging_max :])
            staged_states[self.staging_max :] = []

        simgr.stashes[self.src_stash] = states
        simgr.stashes[self.staging_stash] = staged_states
        return simgr

    @staticmethod
    def state_priority(state):
        return id(state)


from .. import vaults
