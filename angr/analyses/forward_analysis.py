
class ForwardAnalysis(object):
    """
    This is my very first attempt to build a static forward analysis framework that can serve as the base of multiple
    static analyses in angr, including CFG analysis, VFG analysis, DDG, etc.

    In short, ForwardAnalysis performs a forward data-flow analysis by traversing the CFG (or the binary if a CFG is
    not available) and generating a graph with nodes linked with each program point (usually per basic-block, or SimRun
    in angr terms). A node on the graph stores analysis-specific information. For more information about nodes, take a
    look at the implementation of CFGNode.

    Feel free to discuss with me (Fish) if you have any suggestion or complaint!
    """

    def __init__(self):
        """
        Constructor
        :return: None
        """

        # Analysis progress control
        self._should_abort = False

        # All remaining entries
        self._entries = [ ]

        # The graph!
        # Analysis results (nodes) are stored here
        self._graph = None

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
    def graph(self):
        return self._graph

    #
    # Public methods
    #

    def abort(self):
        """
        Abort the analysis
        :return: None
        """

        self._should_abort = True

    #
    # Abstract interfaces
    #

    def _pre_analysis(self):
        raise NotImplementedError('_pre_analysis() is not implemented.')

    def _intra_analysis(self):
        raise NotImplementedError('_intra_analysis() is not implemented.')

    def _post_analysis(self):
        raise NotImplementedError('_post_analysis() is not implemented.')

    def _get_successors(self, entry, _locals):
        raise NotImplementedError('_get_successors() is not implemented.')

    def _pre_entry_handling(self, entry, _locals):
        raise NotImplementedError('_pre_entry_handling() is not implemented.')

    def _post_entry_handling(self, entry, successors, _locals):
        raise NotImplementedError('_post_entry_handling() is not implemented.')

    def _handle_successor(self, entry, successor, successors, _locals):
        raise NotImplementedError('_handle_successor() is not implemented.')

    def _entry_list_empty(self):
        raise NotImplementedError('_entry_list_empty() is not implemented.')

    def _merge_entries(self, entries):
        raise NotImplementedError('_merge_entries() is not implemented.')

    def _widen_entries(self, entries):
        raise NotImplementedError('_widen_entries() is not implemented.')

    #
    # Private methods
    #

    def _init_analysis(self):
        """
        Do a bunch of initialization prior to the real analysis work
        :return: None
        """

        self._entries = [ ]

    def _analyze(self):
        """
        The main analysis routine.

        :return: None
        """

        self._init_analysis()

        self._pre_analysis()

        while not self.should_abort and self._entries:

            entry = self._entries.pop()

            self._handle_entry(entry)

            # Short-cut for aborting the analysis
            if self.should_abort:
                break

            self._intra_analysis()

            if not self._entries:
                self._entry_list_empty()

        self._post_analysis()

    def _handle_entry(self, entry):
        """
        Process an entry, get all successors, and call _handle_successor() to handle each successor.
        :param entry: The entry
        :return: None
        """

        _locals = {}

        try:
            self._pre_entry_handling(entry, _locals)
        except AngrForwardAnalysisSkipEntry:
            return

        successors = self._get_successors(entry, _locals)

        for successor in successors:
            self._handle_successor(entry, successor, successors, _locals)

        self._post_entry_handling(entry, successors, _locals)

from ..errors import AngrForwardAnalysisSkipEntry
