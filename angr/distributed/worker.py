
import time
import multiprocessing
import logging

from ..exploration_techniques import Spiller, Bucketizer
from ..exploration_techniques.spiller import PickledStatesDb
from ..vaults import VaultDirShelf

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class Worker:
    """
    Worker implements a worker thread/process for conducting a task.
    """

    def __init__(self, worker_id, server):
        self.worker_id = worker_id
        self.server = server
        self._proc = None

    def start(self):
        self._proc = multiprocessing.Process(
            target=self.run,
        )
        self._proc.start()

    def run(self):
        simgr = self.server.project.factory.simgr()
        if self.server.bucketizer:
            bucktizer = Bucketizer()
            simgr.use_technique(bucktizer)

        spiller = Spiller(
            max=self.server.max_states,
            staging_min=1,
            staging_max=self.server.staging_max,
            pickle_callback=self._pickle_state,
            post_pickle_callback=self._post_pickle_state,
            unpickle_callback=self._unpickle_state,
            vault=VaultDirShelf(d=self.server.spill_yard),
            states_collection=PickledStatesDb(db_str=self.server.db_str),
        )
        simgr.use_technique(spiller)

        if self.worker_id == 0:
            # bootstrap: the very first worker - start exploring right away!
            _l.debug('Worker 0 starts exploring...')
            self.server.inc_active_workers()
            simgr.explore()
            self.server.dec_active_workers()

        while not self.server.stopped and self.server.active_workers > 0:
            # this is not the first worker - waiting for jobs to arrive
            state_oid = None
            while state_oid is None:
                if self.server.active_workers == 0:
                    break
                popped = spiller._pickled_states.pop_n(1)
                if popped:
                    # we are active!
                    self.server.inc_active_workers()
                    _, state_oid = popped[0]
                else:
                    # oops no job available
                    _l.debug("Worker %d is waiting for jobs...", self.worker_id)
                    time.sleep(1)

            if state_oid is None:
                break

            _l.debug("Worker %d got state %s.", self.worker_id, state_oid)
            state = spiller._load_state(state_oid)
            # update simgr._project
            simgr._project = state.project
            simgr.stashes['active'] = [state]

            simgr.explore()
            self.server.dec_active_workers()

        _l.debug("Worker %d exits.", self.worker_id)
        self.server.on_worker_exit(self.worker_id, simgr.stashes)

    #
    # Callbacks
    #

    def _pickle_state(self, state):
        # state.project = None  # this way we lose all changes the state makes after running... e.g., make_continuation()
        pass

    def _post_pickle_state(self, state, prio, sid):
        # notify other workers
        pass

    def _unpickle_state(self, sid, state):
        # state.project = self.project
        pass
