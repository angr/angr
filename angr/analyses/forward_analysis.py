import networkx

# errors
from ..errors import AngrForwardAnalysisError
# notices
from ..errors import AngrSkipEntryNotice, AngrDelayEntryNotice, AngrJobMergingFailureNotice, \
    AngrJobWideningFailureNotice

class EntryInfo(object):
    """
    Stores information for each entry
    """
    def __init__(self, key, entry):
        self.key = key
        self.entries = [ (entry, '') ]

        self.narrowing_count = 0  # not used

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, o):
        return type(self) == type(o) and \
               self.key == o.key

    def __repr__(self):
        s = "<EntryInfo %s>" % (str(self.key))
        return s

    @property
    def entry(self):
        """
        Get the latest available entry.

        :return: The latest available entry.
        """

        ent, _ = self.entries[-1]
        return ent

    @property
    def merged_entries(self):
        for ent, entry_type in self.entries:
            if entry_type == 'merged':
                yield ent

    @property
    def widened_entries(self):
        for ent, entry_type in self.entries:
            if entry_type == 'widened':
                yield ent

    def add_entry(self, entry, merged=False, widened=False):
        """
        Appended a new entry to this EntryInfo node.
        :param entry: The new entry to append
        :param bool merged: Whether it is a merged entry or not.
        :param bool widened: Whether it is a widened entry or not.
        """

        entry_type = ''
        if merged:
            entry_type = 'merged'
        elif widened:
            entry_type = 'widened'
        self.entries.append((entry, entry_type))


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

    def __init__(self, order_entries=False, allow_merging=False, allow_widening=False, status_callback=None):
        """
        Constructor

        :param bool order_entries: If all entries should be ordered or not.
        :param bool allow_merging: If entry merging is allowed.
        :param bool allow_widening: If entry widening is allowed.
        :return: None
        """

        self._order_entries = order_entries

        self._allow_merging = allow_merging
        self._allow_widening = allow_widening

        self._status_callback = status_callback

        # sanity checks
        if self._allow_widening and not self._allow_merging:
            raise AngrForwardAnalysisError('Merging must be allowed if widening is allowed.')

        # Analysis progress control
        self._should_abort = False

        # All remaining entries
        self._entries = [ ]

        # A map between entry key to entry. Entries with the same key will be merged by calling _merge_entries()
        self._entries_map = { }

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
    def graph(self):
        return self._graph

    @property
    def entries(self):
        for entry_info in self._entries:
            yield entry_info.entry

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

    def _entry_key(self, entry):
        raise NotImplementedError('_entry_key() is not implemented.')

    def _get_successors(self, entry):
        raise NotImplementedError('_get_successors() is not implemented.')

    def _pre_entry_handling(self, entry):
        raise NotImplementedError('_pre_entry_handling() is not implemented.')

    def _post_entry_handling(self, entry, new_entries, successors):
        raise NotImplementedError('_post_entry_handling() is not implemented.')

    def _handle_successor(self, entry, successor, successors):
        raise NotImplementedError('_handle_successor() is not implemented.')

    def _entry_list_empty(self):
        raise NotImplementedError('_entry_list_empty() is not implemented.')

    def _merge_entries(self, *entries):
        raise NotImplementedError('_merge_entries() is not implemented.')

    def _should_widen_entries(self, *entries):
        raise NotImplementedError('_should_widen_entries() is not implemented.')

    def _widen_entries(self, *entries):
        raise NotImplementedError('_widen_entries() is not implemented.')

    def _entry_sorting_key(self, entry):
        raise NotImplementedError('_entry_sorting_key() is not implemented.')

    #
    # Private methods
    #

    def _analyze(self):
        """
        The main analysis routine.

        :return: None
        """

        self._pre_analysis()

        if not self._entries:
            self._entry_list_empty()

        while not self.should_abort:

            if self._status_callback is not None:
                self._status_callback(self)

            # should_abort might be changed by the status callback function
            if self.should_abort:
                return

            if not self._entries:
                self._entry_list_empty()

            if not self._entries:
                # still no job available
                break

            entry_info = self._entries[0]

            try:
                self._pre_entry_handling(entry_info.entry)
            except AngrDelayEntryNotice:
                # delay the handling of this job
                continue
            except AngrSkipEntryNotice:
                # consume and skip this job
                self._entries.pop(0)
                continue

            self._entries.pop(0)

            self._handle_entry(entry_info)

            # Short-cut for aborting the analysis
            if self.should_abort:
                break

            self._intra_analysis()

        self._post_analysis()

    def _handle_entry(self, entry_info):
        """
        Process an entry, get all successors, and call _handle_successor() to handle each successor.
        :param EntryInfo entry: The EntryInfo instance
        :return: None
        """

        entry = entry_info.entry

        successors = self._get_successors(entry)

        all_new_entries = [ ]

        for successor in successors:
            new_entries = self._handle_successor(entry, successor, successors)

            if new_entries:
                all_new_entries.extend(new_entries)

                for new_entry in new_entries:
                    self._insert_entry(new_entry)

        self._post_entry_handling(entry, all_new_entries, successors)

    def _insert_entry(self, entry):
        """
        Insert a new entry into the entry list. If the entry list is ordered, this entry will be inserted at the
        correct position.

        :param entry: The entry to insert
        :return: None
        """

        key = self._entry_key(entry)

        if self._allow_merging:
            if key in self._entries_map:
                entry_info = self._entries_map[key]

                # decide if we want to trigger a widening
                # if not, we'll simply do the merge
                # TODO: save all previous entries for the sake of widening
                entry_added = False
                if self._allow_widening and self._should_widen_entries(entry_info.entry, entry):
                    try:
                        widened_entry = self._widen_entries(entry_info.entry, entry)
                        # remove the old job since now we have a widened one
                        if entry_info in self._entries:
                            self._entries.remove(entry_info)
                        entry_info.add_entry(widened_entry, widened=True)
                        entry_added = True
                    except AngrJobWideningFailureNotice:
                        # widening failed
                        # fall back to merging...
                        pass

                if not entry_added:
                    try:
                        merged_entry = self._merge_entries(entry_info.entry, entry)
                        # remove the old job since now we have a merged one
                        if entry_info in self._entries:
                            self._entries.remove(entry_info)
                        entry_info.add_entry(merged_entry, merged=True)
                    except AngrJobMergingFailureNotice:
                        # merging failed
                        entry_info = EntryInfo(key, entry)
                        # update the entries map
                        self._entries_map[key] = entry_info

            else:
                entry_info = EntryInfo(key, entry)
                self._entries_map[key] = entry_info

        else:
            entry_info = EntryInfo(key, entry)

        if self._order_entries:
            self._binary_insert(self._entries, entry_info, lambda elem: self._entry_sorting_key(elem.entry))

        else:
            self._entries.append(entry_info)

    def _peek_entry(self, pos):
        """
        Return the entry currently at position `pos`, but still keep it in the entry list. An IndexError will be raised
        if that position does not currently exist in the entry list.

        :param int pos: Position of the entry to get.
        :return: The entry
        """

        if pos < len(self._entries):
            return self._entries[pos].entry

        raise IndexError()

    #
    # Utils
    #

    @staticmethod
    def _binary_insert(lst, elem, key, lo=0, hi=None):
        """
        Insert an element into a sorted list, and keep the list sorted.

        The major difference from bisect.bisect_left is that this function supports a key method, so user doesn't have
        to create the key array for each insertion.

        :param list lst: The list. Must be pre-ordered.
        :param object element: An element to insert into the list.
        :param func key: A method to get the key for each element in the list.
        :param int lo: Lower bound of the search.
        :param int hi: Upper bound of the search.
        :return: None
        """

        if lo < 0:
            raise ValueError("lo must be a non-negative number")

        if hi is None:
            hi = len(lst)

        while lo < hi:
            mid = (lo + hi) // 2
            if key(lst[mid]) < key(elem):
                lo = mid + 1
            else:
                hi = mid

        lst.insert(lo, elem)
