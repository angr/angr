from collections import defaultdict
from typing import Dict, List, Callable, Optional, Generic, TypeVar, Tuple, Set, TYPE_CHECKING, Union

import networkx

from .visitors.graph import NodeType
from ..cfg.cfg_job_base import CFGJobBase, BlockID
from ...sim_state import SimState
from ...errors import AngrForwardAnalysisError
from ...errors import AngrSkipJobNotice, AngrDelayJobNotice, AngrJobMergingFailureNotice, AngrJobWideningFailureNotice
from ...utils.algo import binary_insert
from .job_info import JobInfo

if TYPE_CHECKING:
    from .visitors.graph import GraphVisitor

AnalysisState = TypeVar("AnalysisState")

class ForwardAnalysis(Generic[AnalysisState, NodeType]):
    """
    This is my very first attempt to build a static forward analysis framework that can serve as the base of multiple
    static analyses in angr, including CFG analysis, VFG analysis, DDG, etc.

    In short, ForwardAnalysis performs a forward data-flow analysis by traversing a graph, compute on abstract values,
    and store results in abstract states. The user can specify what graph to traverse, how a graph should be traversed,
    how abstract values and abstract states are defined, etc.

    ForwardAnalysis has a few options to toggle, making it suitable to be the base class of several different styles of
    forward data-flow analysis implementations.

    ForwardAnalysis supports a special mode when no graph is available for traversal (for example, when a CFG is being
    initialized and constructed, no other graph can be used). In that case, the graph traversal functionality is
    disabled, and the optimal graph traversal order is not guaranteed. The user can provide a job sorting method to
    sort the jobs in queue and optimize traversal order.

    Feel free to discuss with me (Fish) if you have any suggestions or complaints.
    """

    def __init__(self, order_jobs=False, allow_merging=False, allow_widening=False, status_callback=None,
                 graph_visitor: "Optional[GraphVisitor[NodeType]]" = None
                 ):
        """
        Constructor

        :param bool order_jobs:     If all jobs should be ordered or not.
        :param bool allow_merging:  If job merging is allowed.
        :param bool allow_widening: If job widening is allowed.
        :param graph_visitor:       A graph visitor to provide successors.
        :type graph_visitor:        GraphVisitor or None
        :return: None
        """

        self._order_jobs = order_jobs
        self._allow_merging = allow_merging
        self._allow_widening = allow_widening
        self._status_callback = status_callback
        self._graph_visitor = graph_visitor

        # sanity checks
        if self._allow_widening and not self._allow_merging:
            raise AngrForwardAnalysisError('Merging must be allowed if widening is allowed.')

        # Analysis progress control
        self._should_abort = False

        # All remaining jobs
        self._job_info_queue: List[JobInfo] = []

        # A map between job key to job. Jobs with the same key will be merged by calling _merge_jobs()
        self._job_map: Dict[BlockID, JobInfo] = {}

        # A mapping between node and its input states
        self._input_states: Dict[NodeType, List[AnalysisState]] = defaultdict(list)
        # A mapping between node and its output state
        self._output_state: Dict[NodeType, AnalysisState] = {}

        # The graph!
        # Analysis results (nodes) are stored here
        self._graph = networkx.DiGraph()

    #
    # Properties
    #

    @property
    def should_abort(self):
        """
        Should the analysis be terminated.
        :return: True/False
        """

        return self._should_abort

    @property
    def graph(self) -> networkx.DiGraph:
        return self._graph

    @property
    def jobs(self):
        for job_info in self._job_info_queue:
            yield job_info.job

    #
    # Public methods
    #

    def abort(self):
        """
        Abort the analysis
        :return: None
        """

        self._should_abort = True

    def has_job(self, job: CFGJobBase) -> bool:
        """
        Checks whether there exists another job which has the same job key.
        :param job: The job to check.

        :return:    True if there exists another job with the same key, False otherwise.
        """
        job_key = self._job_key(job)
        return job_key in self._job_map

    def downsize(self):
        self._input_states = defaultdict(list)
        self._output_state = {}

    #
    # Abstract interfaces
    #

    # Common interfaces

    def _pre_analysis(self) -> None:
        raise NotImplementedError('_pre_analysis() is not implemented.')

    def _intra_analysis(self) -> None:
        raise NotImplementedError('_intra_analysis() is not implemented.')

    def _post_analysis(self) -> None:
        raise NotImplementedError('_post_analysis() is not implemented.')

    def _job_key(self, job: CFGJobBase) -> BlockID:
        raise NotImplementedError('_job_key() is not implemented.')

    def _get_successors(self, job: CFGJobBase) -> Union[List[SimState], List[CFGJobBase]]:
        raise NotImplementedError('_get_successors() is not implemented.')

    def _pre_job_handling(self, job: CFGJobBase) -> None:
        raise NotImplementedError('_pre_job_handling() is not implemented.')

    def _post_job_handling(self, job: CFGJobBase, new_jobs, successors: List[SimState]) -> None:
        raise NotImplementedError('_post_job_handling() is not implemented.')

    def _handle_successor(self, job: CFGJobBase, successor: SimState, successors: List[SimState]) -> List[CFGJobBase]:
        raise NotImplementedError('_handle_successor() is not implemented.')

    def _job_queue_empty(self) -> None:
        raise NotImplementedError('_job_queue_empty() is not implemented.')

    def _initial_abstract_state(self, node: NodeType) -> AnalysisState:
        raise NotImplementedError('_initial_abstract_state() is not implemented.')

    def _node_key(self, node: NodeType) -> NodeType:  # pylint:disable=no-self-use
        """
        Override this method if hash(node) is slow for the type of node that are in use.
        """
        return node

    def _run_on_node(self, node: NodeType, state: AnalysisState) -> Tuple[bool, AnalysisState]:
        """
        The analysis routine that runs on each node in the graph.

        For compatibility reasons, the variable `changed` in the returning tuple can have three values:
        - True, means a change has occurred, the output state is not the same as the input state, and a fixed point is
          not reached. Usually used if the analysis performs weak updates.
        - False, means no change has occurred. Usually used if the analysis performs weak updates.
        - None, means no change detection is performed during this process (e.g., if the analysis requires strong
          updates), and change detection will be performed later during _merge_states().

        :param node:    A node in the graph.
        :param state:   An abstract state that acts as the initial abstract state of this analysis routine.
        :return:        A tuple: (changed, output abstract state)
        """

        raise NotImplementedError('_run_on_node() is not implemented.')

    def _merge_states(self, node: NodeType, *states: AnalysisState) -> Tuple[AnalysisState, bool]:
        """
        Merge multiple abstract states into one.

        :param node:   A node in the graph.
        :param states: Abstract states to merge.
        :return:       A merged abstract state, and a boolean variable indicating if a local fixed-point has reached (
                       i.e., union(state0, state1) == state0), in which case, its successors will not be revisited.
        """

        raise NotImplementedError('_merge_states() is not implemented.')

    def _widen_states(self, *states: AnalysisState) -> AnalysisState:
        raise NotImplementedError('_widen_states() is not implemented.')

    # Special interfaces for non-graph-traversal mode

    def _merge_jobs(self, *jobs: CFGJobBase):
        raise NotImplementedError('_merge_jobs() is not implemented.')

    def _should_widen_jobs(self, *jobs: CFGJobBase):
        raise NotImplementedError('_should_widen_jobs() is not implemented.')

    def _widen_jobs(self, *jobs: CFGJobBase):
        raise NotImplementedError('_widen_jobs() is not implemented.')

    def _job_sorting_key(self, job: CFGJobBase) -> int:
        raise NotImplementedError('_job_sorting_key() is not implemented.')

    #
    # Private methods
    #

    def _analyze(self) -> None:
        """
        The main analysis routine.

        :return: None
        """

        self._pre_analysis()

        if self._graph_visitor is None:
            # There is no base graph that we can rely on. The analysis itself should generate successors for the
            # current job.
            # An example is the CFG recovery.

            self._analysis_core_baremetal()

        else:
            # We have a base graph to follow. Just handle the current job.

            self._analysis_core_graph()

        self._post_analysis()

    def _analysis_core_graph(self) -> None:

        while not self.should_abort:

            self._intra_analysis()

            n: NodeType = self._graph_visitor.next_node()

            if n is None:
                break

            job_state = self._get_and_update_input_state(n)
            if job_state is None:
                job_state = self._initial_abstract_state(n)

            changed, output_state = self._run_on_node(n, job_state)

            if changed is False:
                # no change is detected
                self._output_state[self._node_key(n)] = output_state
                continue
            elif changed is True:
                # changes detected

                # output state of node n is input state for successors to node n
                self._add_input_state(n, output_state)

                # revisit all its successors
                self._graph_visitor.revisit_successors(n, include_self=False)
            else:
                # the change of states are determined during state merging (_add_input_state()) instead of during
                # simulated execution (_run_on_node()).

                if self._node_key(n) not in self._output_state:
                    reached_fixedpoint = False
                else:
                    # is the output state the same as the old one?
                    _, reached_fixedpoint = self._merge_states(n, self._output_state[self._node_key(n)], output_state)
                self._output_state[self._node_key(n)] = output_state

                if not reached_fixedpoint:
                    successors_to_visit = self._add_input_state(n, output_state)
                    # revisit all successors in the `successors_to_visit` list
                    for succ in successors_to_visit:
                        self._graph_visitor.revisit_node(succ)

    def _add_input_state(self, node: NodeType, input_state: AnalysisState) -> Set[NodeType]:
        """
        Add the input state to all successors of the given node.

        :param node:        The node whose successors' input states will be touched.
        :param input_state: The state that will be added to successors of the node.
        """

        successors = set(self._graph_visitor.successors(node))
        # successors_to_visit = set()  # a collection of successors whose input states did not reach a fixed point

        for succ in successors:
            # if a node has only one predecessor, we overwrite existing input states
            # otherwise, we add the state as a new input state
            # this is an approximation for removing input states for all nodes that `node` dominates
            if sum(1 for _ in self._graph_visitor.predecessors(succ)) == 1:
                self._input_states[self._node_key(succ)] = [ input_state ]
            else:
                self._input_states[self._node_key(succ)].append(input_state)

        return successors

    def _get_and_update_input_state(self, node: NodeType) -> Optional[AnalysisState]:
        """
        Get the input abstract state for this node, and remove it from the state map.

        :param node: The node in graph.
        :return:     A merged state, or None if there is no input state for this node available.
        """

        if self._node_key(node) in self._input_states:
            input_state = self._get_input_state(node)
            self._input_states[self._node_key(node)] = [input_state]
            return input_state
        return None

    def _get_input_state(self, node: NodeType) -> Optional[AnalysisState]:
        """
        Get the input abstract state for this node.

        :param node:    The node in graph.
        :return:        A merged state, or None if there is no input state for this node available.
        """

        if self._node_key(node) not in self._input_states:
            return None

        all_input_states = self._input_states.get(self._node_key(node))
        if len(all_input_states) == 1:
            return all_input_states[0]
        merged_state, _ = self._merge_states(node, *all_input_states)
        return merged_state

    def _analysis_core_baremetal(self) -> None:

        if not self._job_info_queue:
            self._job_queue_empty()

        while not self.should_abort:

            if self._status_callback is not None:
                self._status_callback(self)

            # should_abort might be changed by the status callback function
            if self.should_abort:
                return

            if not self._job_info_queue:
                self._job_queue_empty()

            if not self._job_info_queue:
                # still no job available
                break

            job_info = self._job_info_queue[0]

            try:
                self._pre_job_handling(job_info.job)
            except AngrDelayJobNotice:
                # delay the handling of this job
                continue
            except AngrSkipJobNotice:
                # consume and skip this job
                self._job_info_queue = self._job_info_queue[1:]
                self._job_map.pop(self._job_key(job_info.job), None)
                continue

            # remove the job info from the map
            self._job_map.pop(self._job_key(job_info.job), None)

            self._job_info_queue = self._job_info_queue[1:]

            self._process_job_and_get_successors(job_info)

            # Short-cut for aborting the analysis
            if self.should_abort:
                break

            self._intra_analysis()

    def _process_job_and_get_successors(self, job_info: JobInfo) -> None:
        """
        Process a job, get all successors of this job, and call _handle_successor() to handle each successor.

        :param JobInfo job_info: The JobInfo instance
        :return: None
        """

        job = job_info.job

        successors = self._get_successors(job)

        all_new_jobs = [ ]

        for successor in successors:
            new_jobs = self._handle_successor(job, successor, successors)

            if new_jobs:
                all_new_jobs.extend(new_jobs)

                for new_job in new_jobs:
                    self._insert_job(new_job)

        self._post_job_handling(job, all_new_jobs, successors)

    def _insert_job(self, job: CFGJobBase) -> None:
        """
        Insert a new job into the job queue. If the job queue is ordered, this job will be inserted at the correct
        position.

        :param job: The job to insert
        :return:    None
        """

        key = self._job_key(job)

        if self._allow_merging:
            if key in self._job_map:
                job_info = self._job_map[key]

                # decide if we want to trigger a widening
                # if not, we'll simply do the merge
                # TODO: save all previous jobs for the sake of widening
                job_added = False
                if self._allow_widening and self._should_widen_jobs(job_info.job, job):
                    try:
                        widened_job = self._widen_jobs(job_info.job, job)
                        # remove the old job since now we have a widened one
                        if job_info in self._job_info_queue:
                            self._job_info_queue.remove(job_info)
                        job_info.add_job(widened_job, widened=True)
                        job_added = True
                    except AngrJobWideningFailureNotice:
                        # widening failed
                        # fall back to merging...
                        pass

                if not job_added:
                    try:
                        merged_job = self._merge_jobs(job_info.job, job)
                        # remove the old job since now we have a merged one
                        if job_info in self._job_info_queue:
                            self._job_info_queue.remove(job_info)
                        job_info.add_job(merged_job, merged=True)
                    except AngrJobMergingFailureNotice:
                        # merging failed
                        job_info = JobInfo(key, job)
                        # update the job map
                        self._job_map[key] = job_info

            else:
                job_info = JobInfo(key, job)
                self._job_map[key] = job_info

        else:
            job_info = JobInfo(key, job)
            self._job_map[key] = job_info

        if self._order_jobs:
            binary_insert(self._job_info_queue, job_info, lambda elem: self._job_sorting_key(elem.job))

        else:
            self._job_info_queue.append(job_info)

    def _peek_job(self, pos: int) -> CFGJobBase:
        """
        Return the job currently at position `pos`, but still keep it in the job queue. An IndexError will be raised
        if that position does not currently exist in the job list.

        :param int pos: Position of the job to get.
        :return:        The job
        """

        if pos < len(self._job_info_queue):
            return self._job_info_queue[pos].job

        raise IndexError()

    def _remove_job(self, predicate: Callable) -> None:
        """
        Remove jobs that satisfy certain criteria from job_info_queue.

        :param predicate:   A method that determines if a job should be removed or not.
        """

        to_remove = [ ]
        for job_info in self._job_info_queue:
            if predicate(job_info.job):
                to_remove.append(job_info)

        for job_info in to_remove:
            self._job_info_queue.remove(job_info)
            key = self._job_key(job_info.job)
            if key in self._job_map:
                del self._job_map[key]
