from ..errors import AngrMemoryError
from ..analysis import Analysis, register_analysis

from collections import deque
import logging
import math
import networkx
import types

# todo include an explanation of the algorithm
# todo include a method that detects any change other than constants
# todo use function names / string references where available

l = logging.getLogger(name="angr.analyses.bindiff")

# basic block changes
DIFF_TYPE = "type"
DIFF_VALUE = "value"


# exception for trying find basic block changes
class UnmatchedStatementsException(Exception):
    pass


# statement difference classes
class Difference(object):
    def __init__(self, diff_type, value_a, value_b):
        self.type = diff_type
        self.value_a = value_a
        self.value_b = value_b


class ConstantChange(object):
    def __init__(self, offset, value_a, value_b):
        self.offset = offset
        self.value_a = value_a
        self.value_b = value_b


# helper methods
def _euclidean_dist(vector_a, vector_b):
    """
    :param vector_a: list of numbers
    :param vector_b: list of numbers
    :return: the euclidean distance between the two vectors
    """
    dist = 0
    for (x, y) in zip(vector_a, vector_b):
        dist += (x-y)*(x-y)
    return math.sqrt(dist)


def _get_closest_matches(input_attributes, target_attributes):
    """
    :param input_attributes: first dictionary of objects to attribute tuples
    :param target_attributes: second dictionary of blocks to attribute tuples
    :return: dictionary of objects in the input_attributes to the closest objects in the target_attributes
    """
    closest_matches = {}

    # for each object in the first set find the objects with the closest target attributes
    for a in input_attributes:
        best_dist = float('inf')
        best_matches = []
        for b in target_attributes:
            dist = _euclidean_dist(input_attributes[a], target_attributes[b])
            if dist < best_dist:
                best_matches = [b]
                best_dist = dist
            elif dist == best_dist:
                best_matches.append(b)
        closest_matches[a] = best_matches

    return closest_matches


# from http://rosettacode.org/wiki/Levenshtein_distance
def _levenshtein_distance(s1, s2):
    """
    :param s1: A list or string
    :param s2: Another list or string
    :return: The levenshtein distance between the two
    """
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for index2, num2 in enumerate(s2):
        new_distances = [index2 + 1]
        for index1, num1 in enumerate(s1):
            if num1 == num2:
                new_distances.append(distances[index1])
            else:
                new_distances.append(1 + min((distances[index1],
                                             distances[index1+1],
                                             new_distances[-1])))
        distances = new_distances
    return distances[-1]


def _normalized_levenshtein_distance(s1, s2, acceptable_differences):
    """
    This function calculates the levenshtein distance but allows for elements in the lists to be different by any number
    in the set acceptable_differences.
    :param s1: A list
    :param s2: Another list
    :param acceptable_differences: A set of numbers. If (s2[i]-s1[i]) is in the set then they are considered equal
    :return:
    """
    if len(s1) > len(s2):
        s1, s2 = s2, s1
        acceptable_differences = set(-i for i in acceptable_differences)
    distances = range(len(s1) + 1)
    for index2, num2 in enumerate(s2):
        new_distances = [index2 + 1]
        for index1, num1 in enumerate(s1):
            if num2 - num1 in acceptable_differences:
                new_distances.append(distances[index1])
            else:
                new_distances.append(1 + min((distances[index1],
                                             distances[index1+1],
                                             new_distances[-1])))
        distances = new_distances
    return distances[-1]


def _is_better_match(x, y, matched_a, matched_b, attributes_dict_a, attributes_dict_b):
    """
    :param x: the first element of a possible match
    :param y: the second element of a possible match
    :param matched_a: the current matches for the first set
    :param matched_b: the current matches for the second set
    :param attributes_dict_a: the attributes for each element in the first set
    :param attributes_dict_b: the attributes for each element in the second set
    :return:
    """
    attributes_x = attributes_dict_a[x]
    attributes_y = attributes_dict_b[y]
    if x in matched_a:
        attributes_match = attributes_dict_b[matched_a[x]]
        if _euclidean_dist(attributes_x, attributes_y) >= _euclidean_dist(attributes_x, attributes_match):
            return False
    if y in matched_b:
        attributes_match = attributes_dict_a[matched_b[y]]
        if _euclidean_dist(attributes_x, attributes_y) >= _euclidean_dist(attributes_y, attributes_match):
            return False
    return True


def differing_constants(block_a, block_b):
    """
    Compares two basic blocks and finds all the constants that differ from the first block to the second
    :param block_a: the first block to compare
    :param block_b: the second block to compare
    :return: returns a list of differing constants in the form of ConstantChange, which has the offset in the block
             and the respective constants.
    """
    statements_a = [s for s in block_a.vex.statements if s.tag != "Ist_IMark"] + [block_a.vex.next]
    statements_b = [s for s in block_b.vex.statements if s.tag != "Ist_IMark"] + [block_b.vex.next]
    if len(statements_a) != len(statements_b):
        raise UnmatchedStatementsException("Blocks have different numbers of statements")

    start_1 = min(block_a.instruction_addrs)
    start_2 = min(block_b.instruction_addrs)

    changes = []

    # check statements
    current_offset = None
    for statement, statement_2 in zip(statements_a, statements_b):
        # sanity check
        if statement.tag != statement_2.tag:
            raise UnmatchedStatementsException("Statement tag has changed")

        if statement.tag == "Ist_IMark":
            if statement.addr - start_1 != statement_2.addr - start_2:
                raise UnmatchedStatementsException("Instruction length has changed")
            current_offset = statement.addr - start_1
            continue

        differences = compare_statement_dict(statement, statement_2)
        for d in differences:
            if d.type != DIFF_VALUE:
                raise UnmatchedStatementsException("Instruction has changed")
            else:
                changes.append(ConstantChange(current_offset, d.value_a, d.value_b))

    return changes


def compare_statement_dict(statement_1, statement_2):
    # should return whether or not the statement's type/effects changed
    # need to return the specific number that changed too

    if type(statement_1) != type(statement_2):
        return [Difference(DIFF_TYPE, None, None)]

    # None
    if statement_1 is None and statement_2 is None:
        return []

    # constants
    if isinstance(statement_1, (int, long, float, str)):
        if statement_1 == statement_2:
            return []
        else:
            return [Difference(None, statement_1, statement_2)]

    # tuples/lists
    if isinstance(statement_1, (tuple, list)):
        if len(statement_1) != len(statement_2):
            return Difference(DIFF_TYPE, None, None)

        differences = []
        for s1, s2 in zip(statement_1, statement_2):
            differences += compare_statement_dict(s1, s2)
        return differences

    # Yan's weird types
    differences = []
    for attr in statement_1.__dict__:
        # don't check arch, property, or methods
        if attr == "arch":
            continue
        if hasattr(statement_1.__class__, attr) and isinstance(getattr(statement_1.__class__, attr), property):
            continue
        if isinstance(getattr(statement_1, attr), types.MethodType):
            continue

        new_diffs = compare_statement_dict(getattr(statement_1, attr), getattr(statement_2, attr))
        # set the difference types
        for diff in new_diffs:
            if diff.type is None:
                diff.type = attr
        differences += new_diffs

    return differences


class NormalizedBlock(object):
    # block may span multiple calls
    def __init__(self, addr, function):
        addresses = [addr]
        if addr in function.merged_blocks:
            for a in function.merged_blocks[addr]:
                addresses.append(a)

        self.addr = addr
        self.addresses = addresses
        self.statements = []
        self.all_constants = []
        self.operations = []
        self.call_targets = []
        self.blocks = []
        self.instruction_addrs = []

        if addr in function.call_sites:
            self.call_targets = function.call_sites[addr]

        self.jumpkind = None

        for a in addresses:
            block = function.project.factory.block(a)
            self.instruction_addrs += block.instruction_addrs
            irsb = block.vex
            self.blocks.append(block)
            self.statements += irsb.statements
            self.all_constants += irsb.all_constants
            self.operations += irsb.operations
            self.jumpkind = irsb.jumpkind

    def __repr__(self):
        size = sum([b.size for b in self.blocks])
        return '<Normalized Block for %#x, %d bytes>' % (self.addr, size)

class NormalizedFunction(object):
    # a more normalized function
    def __init__(self, function):
        # start by copying the graph
        self.graph = function.local_transition_graph.copy()
        self.project = function._function_manager.project
        self.call_sites = dict()
        self.startpoint = function.startpoint
        self.merged_blocks = dict()
        self.orig_function = function

        # find nodes which end in call and combine them
        done = False
        while not done:
            done = True
            for node in self.graph.nodes():
                try:
                    bl = self.project.factory.block(node)
                except AngrMemoryError:
                    continue
                # merge if it ends with a single call, and the successor has only one predecessor
                successors = self.graph.successors(node)
                if bl.vex.jumpkind == "Ijk_Call" and len(successors) == 1 and \
                        len(self.graph.predecessors(successors[0])) == 1:
                    # add edges to the successors of its successor, and delete the original successors
                    succ = self.graph.successors(node)[0]
                    for s in self.graph.successors(succ):
                        self.graph.add_edge(node, s)
                    self.graph.remove_node(succ)
                    done = False

                    # add to merged blocks
                    if node not in self.merged_blocks:
                        self.merged_blocks[node] = []
                    self.merged_blocks[node].append(succ)
                    if succ in self.merged_blocks:
                        self.merged_blocks[node] += self.merged_blocks[succ]
                        del self.merged_blocks[succ]

                    # stop iterating and start over
                    break

        # set up call sites
        for n in self.graph.nodes():
            call_targets = []
            if n in self.orig_function.get_call_sites():
                call_targets.append(self.orig_function.get_call_target(n))
            if n in self.merged_blocks:
                for block in self.merged_blocks[n]:
                    if block in self.orig_function.get_call_sites():
                        call_targets.append(self.orig_function.get_call_target(block))
            if len(call_targets) > 0:
                self.call_sites[n] = call_targets


class FunctionDiff(object):
    """
    This class computes the a diff between two functions
    """
    def __init__(self, function_a, function_b, bindiff=None):
        """
        :param function_a: The first angr Function object to diff
        :param function_b: The second angr Function object
        :param bindiff: An optional Bindiff object. Used for some extra normalization during basic block comparison
        """
        self._function_a = NormalizedFunction(function_a)
        self._function_b = NormalizedFunction(function_b)
        self._project_a = self._function_a.project
        self._project_b = self._function_b.project
        self._bindiff = bindiff

        self._attributes_a = dict()
        self._attributes_a = dict()

        self._block_matches = set()
        self._unmatched_blocks_from_a = set()
        self._unmatched_blocks_from_b = set()

        self._compute_diff()

    @property
    def probably_identical(self):
        """
        :return: Whether or not these two functions are identical.
        """
        if len(self._unmatched_blocks_from_a | self._unmatched_blocks_from_b) > 0:
            return False
        for (a, b) in self._block_matches:
            if not self.blocks_probably_identical(a, b):
                return False
        return True

    @property
    def identical_blocks(self):
        """
        :return: A list of block matches which appear to be identical
        """
        identical_blocks = []
        for (block_a, block_b) in self._block_matches:
            if self.blocks_probably_identical(block_a, block_b):
                identical_blocks.append((block_a, block_b))
        return identical_blocks

    @property
    def differing_blocks(self):
        """
        :return: A list of block matches which appear to differ
        """
        differing_blocks = []
        for (block_a, block_b) in self._block_matches:
            if not self.blocks_probably_identical(block_a, block_b):
                differing_blocks.append((block_a, block_b))
        return differing_blocks

    @property
    def block_matches(self):
        return self._block_matches

    @property
    def unmatched_blocks(self):
        return self._unmatched_blocks_from_a, self._unmatched_blocks_from_b

    def get_normalized_block(self, addr, function):
        """
        :param addr: where to start the normalized block
        :param function: function containing the block address
        :return: a normalized basic block
        """
        return NormalizedBlock(addr, function)

    def block_similarity(self, block_a, block_b):
        """
        :param block_a: the first block address
        :param block_b: the second block address
        :return: the similarity of the basic blocks, normalized for the base address of the block and function call
        addresses
        """

        # handle sim procedure blocks
        if self._project_a.is_hooked(block_a) and self._project_b.is_hooked(block_b):
            if self._project_a._sim_procedures[block_a] == self._project_b._sim_procedures[block_b]:
                return 1.0
            else:
                return 0.0

        try:
            block_a = NormalizedBlock(block_a, self._function_a)
        except AngrMemoryError:
            block_a = None

        try:
            block_b = NormalizedBlock(block_b, self._function_b)
        except AngrMemoryError:
            block_b = None

        # if both were None then they are assumed to be the same, if only one was the same they are assumed to differ
        if block_a is None and block_b is None:
            return 1.0
        elif block_a is None or block_b is None:
            return 0.0

        # get all elements for computing similarity
        tags_a = [s.tag for s in block_a.statements]
        tags_b = [s.tag for s in block_b.statements]
        consts_a = [c.value for c in block_a.all_constants]
        consts_b = [c.value for c in block_b.all_constants]
        all_registers_a = [s.offset for s in block_a.statements if hasattr(s, "offset")]
        all_registers_b = [s.offset for s in block_b.statements if hasattr(s, "offset")]
        jumpkind_a = block_a.jumpkind
        jumpkind_b = block_b.jumpkind

        # compute total distance
        total_dist = 0
        total_dist += _levenshtein_distance(tags_a, tags_b)
        total_dist += _levenshtein_distance(block_a.operations, block_b.operations)
        total_dist += _levenshtein_distance(all_registers_a, all_registers_b)
        acceptable_differences = self._get_acceptable_constant_differences(block_a, block_b)
        total_dist += _normalized_levenshtein_distance(consts_a, consts_b, acceptable_differences)
        total_dist += 0 if jumpkind_a == jumpkind_b else 1

        # compute similarity
        num_values = max(len(tags_a), len(tags_b))
        num_values += max(len(consts_a), len(consts_b))
        num_values += max(len(block_a.operations), len(block_b.operations))
        num_values += 1  # jumpkind
        similarity = 1 - (float(total_dist) / num_values)

        return similarity

    def blocks_probably_identical(self, block_a, block_b):
        """
        :param block_a: the first block address
        :param block_b: the second block address
        :return: Whether or not the blocks appear to be identical
        """
        # handle sim procedure blocks
        if self._project_a.is_hooked(block_a) and self._project_b.is_hooked(block_b):
            return self._project_a._sim_procedures[block_a] == self._project_b._sim_procedures[block_b]

        try:
            block_a = NormalizedBlock(block_a, self._function_a)
        except AngrMemoryError:
            block_a = None

        try:
            block_b = NormalizedBlock(block_b, self._function_b)
        except AngrMemoryError:
            block_b = None

        # if both were None then they are assumed to be the same, if only one was None they are assumed to differ
        if block_a is None and block_b is None:
            return True
        elif block_a is None or block_b is None:
            return False

        # if they represent a different number of blocks they are not the same
        if len(block_a.blocks) != len(block_b.blocks):
            return False

        # check differing constants
        diff_constants = []
        for irsb_a, irsb_b in zip(block_a.blocks, block_b.blocks):
            try:
                diff_constants += differing_constants(irsb_a, irsb_b)
            except UnmatchedStatementsException:
                return False

        # get values of differences that probably indicate no change
        acceptable_differences = self._get_acceptable_constant_differences(block_a, block_b)

        # todo match constants that often move such as those in rodata
        for c in diff_constants:
            if (c.value_a, c.value_b) in self._block_matches:
                # constants point to matched basic blocks
                continue
            if self._bindiff is not None and (c.value_a and c.value_b) in self._bindiff.function_matches:
                # constants point to matched functions
                continue
            # if both are in rodata assume it's good for now
            if ".rodata" in self._project_a.loader.main_bin.sections_map and \
                    ".rodata" in self._project_b.loader.main_bin.sections_map:
                ro_data_a = self._project_a.loader.main_bin.sections_map[".rodata"]
                ro_data_b = self._project_b.loader.main_bin.sections_map[".rodata"]
                base_addr_a = self._project_a.loader.main_bin.rebase_addr
                base_addr_b = self._project_b.loader.main_bin.rebase_addr
                if ro_data_a.contains_addr(c.value_a-base_addr_a) and ro_data_b.contains_addr(c.value_b-base_addr_b):
                    continue
            # if both are in got assume it's good for now
            if ".got.plt" in self._project_a.loader.main_bin.sections_map and \
                    ".got.plt" in self._project_b.loader.main_bin.sections_map:
                ro_data_a = self._project_a.loader.main_bin.sections_map[".got.plt"]
                ro_data_b = self._project_b.loader.main_bin.sections_map[".got.plt"]
                base_addr_a = self._project_a.loader.main_bin.rebase_addr
                base_addr_b = self._project_b.loader.main_bin.rebase_addr
                if ro_data_a.contains_addr(c.value_a-base_addr_a) and ro_data_b.contains_addr(c.value_b-base_addr_b):
                    continue
            # if the difference is equal to the difference in block addr's or successor addr's we'll say it's also okay
            if (c.value_b - c.value_a) in acceptable_differences:
                continue
            # otherwise they probably are different
            return False

        # the blocks appear to be identical
        return True

    @staticmethod
    def _compute_block_attributes(function):
        """
        :param function: A normalized function object
        :return: a dictionary of basic block addresses to tuples of attributes
        """
        # The attributes we use are the distance form function start, distance from function exit and whether
        # or not it has a subfunction call
        distances_from_start = FunctionDiff._distances_from_function_start(function)
        distances_from_exit = FunctionDiff._distances_from_function_exit(function)
        call_sites = function.call_sites

        attributes = {}
        for block in function.graph.nodes():
            if block in call_sites:
                number_of_subfunction_calls = len(call_sites[block])
            else:
                number_of_subfunction_calls = 0
            # there really shouldn't be blocks that can't be reached from the start, but there are for now
            dist_start = distances_from_start[block] if block in distances_from_start else 10000
            dist_exit = distances_from_exit[block] if block in distances_from_exit else 10000

            attributes[block] = (dist_start, dist_exit, number_of_subfunction_calls)

        return attributes

    @staticmethod
    def _distances_from_function_start(function):
        """
        :param function: A normalized Function object
        :return: a dictionary of basic block addresses and their distance to the start of the function
        """
        return networkx.single_source_shortest_path_length(function.graph,
                                                           function.startpoint)

    @staticmethod
    def _distances_from_function_exit(function):
        """
        :param function: A normalized Function object
        :return: a dictionary of basic block addresses and their distance to the exit of the function
        """
        reverse_graph = function.graph.reverse()
        # we aren't guaranteed to have an exit from the function so explicitly add the node
        reverse_graph.add_node("start")
        for n in function.graph.nodes():
            if len(function.graph.successors(n)) == 0:
                reverse_graph.add_edge("start", n)

        dists = networkx.single_source_shortest_path_length(reverse_graph, "start")

        # remove temp node
        del dists["start"]

        # correct for the added node
        for n in dists:
            dists[n] -= 1

        return dists

    def _compute_diff(self):
        """
        Computes the diff of the functions and saves the result
        """
        # get the attributes for all blocks
        l.debug("Computing diff of functions: %s, %s", hex(self._function_a.startpoint),
                hex(self._function_b.startpoint))
        self.attributes_a = self._compute_block_attributes(self._function_a)
        self.attributes_b = self._compute_block_attributes(self._function_b)

        # get the initial matches
        initial_matches = self._get_block_matches(self.attributes_a, self.attributes_b,
                                                  tiebreak_with_block_similarity=False)

        # Use a queue so we process matches in the order that they are found
        to_process = deque(initial_matches)

        # Keep track of which matches we've already added to the queue
        processed_matches = set((x, y) for (x, y) in initial_matches)

        # Keep a dict of current matches, which will be updated if better matches are found
        matched_a = dict()
        matched_b = dict()
        for (x, y) in processed_matches:
            matched_a[x] = y
            matched_b[y] = x

        # while queue is not empty
        while to_process:
            (block_a, block_b) = to_process.pop()
            l.debug("FunctionDiff: Processing (%#x, %#x)", block_a, block_b)

            # we could find new matches in the successors or predecessors of functions
            block_a_succ = self._function_a.graph.successors(block_a)
            block_b_succ = self._function_b.graph.successors(block_b)
            block_a_pred = self._function_a.graph.predecessors(block_a)
            block_b_pred = self._function_b.graph.predecessors(block_b)

            # propagate the difference in blocks as delta
            delta = tuple((i-j) for i, j in zip(self.attributes_b[block_b], self.attributes_a[block_a]))

            # get possible new matches
            new_matches = []

            # if the blocks are identical then the successors should most likely be matched in the same order
            if self.blocks_probably_identical(block_b, block_b) and len(block_a_succ) == len(block_b_succ):
                new_matches += zip(block_a_succ, block_b_succ)

            new_matches += self._get_block_matches(self.attributes_a, self.attributes_b, block_a_succ, block_b_succ,
                                                  delta, tiebreak_with_block_similarity=True)
            new_matches += self._get_block_matches(self.attributes_a, self.attributes_b, block_a_pred, block_b_pred,
                                                   delta, tiebreak_with_block_similarity=True)


            # for each of the possible new matches add it if it improves the matching
            for (x, y) in new_matches:
                if (x, y) not in processed_matches:
                    processed_matches.add((x, y))
                    l.debug("FunctionDiff: checking if (%#x, %#x) is better", x, y)
                    # if it's a better match than what we already have use it
                    if _is_better_match(x, y, matched_a, matched_b, self.attributes_a, self.attributes_b):
                        l.debug("FunctionDiff: adding possible match (%#x, %#x)", x, y)
                        if x in matched_a:
                            old_match = matched_a[x]
                            del matched_b[old_match]
                        if y in matched_b:
                            old_match = matched_b[y]
                            del matched_a[old_match]
                        matched_a[x] = y
                        matched_b[y] = x
                        to_process.appendleft((x, y))

        # reformat matches into a set of pairs
        self._block_matches = set((x, y) for (x, y) in matched_a.items())

        # get the unmatched blocks
        self._unmatched_blocks_from_a = set(x for x in self._function_a.graph.nodes() if x not in matched_a)
        self._unmatched_blocks_from_b = set(x for x in self._function_b.graph.nodes() if x not in matched_b)

    def _get_block_matches(self, attributes_a, attributes_b, filter_set_a=None, filter_set_b=None, delta=(0, 0, 0),
                           tiebreak_with_block_similarity = False):
        """
        :param attributes_a: dict of blocks to their attributes
        :param attributes_b: dict of blocks to their attributes
        :param filter_set_a: an optional set to limit attributes_a to the blocks in this set
        :param filter_set_b: an optional set to limit attributes_b to the blocks in this set
        :param delta: offset to add to each vector in attributes_a
        :return: a list of tuples of matching objects
        """
        # get the attributes that are in the sets
        if filter_set_a is None:
            filtered_attributes_a = {k: v for k, v in attributes_a.items()}
        else:
            filtered_attributes_a = {k: v for k, v in attributes_a.items() if k in filter_set_a}

        if filter_set_b is None:
            filtered_attributes_b = {k: v for k, v in attributes_b.items()}
        else:
            filtered_attributes_b = {k: v for k, v in attributes_b.items() if k in filter_set_b}

        # add delta
        for k in filtered_attributes_a:
            filtered_attributes_a[k] = tuple((i+j) for i, j in zip(filtered_attributes_a[k], delta))
        for k in filtered_attributes_b:
            filtered_attributes_b[k] = tuple((i+j) for i, j in zip(filtered_attributes_b[k], delta))

        # get closest
        closest_a = _get_closest_matches(filtered_attributes_a, filtered_attributes_b)
        closest_b = _get_closest_matches(filtered_attributes_b, filtered_attributes_a)

        if tiebreak_with_block_similarity:
            # use block similarity to break ties in the first set
            for a in closest_a:
                if len(closest_a[a]) > 1:
                    best_similarity = 0
                    best = []
                    for x in closest_a[a]:
                        similarity = self.block_similarity(a, x)
                        if similarity > best_similarity:
                            best_similarity = similarity
                            best = [x]
                        elif similarity == best_similarity:
                            best.append(x)
                    closest_a[a] = best

            # use block similarity to break ties in the second set
            for b in closest_b:
                if len(closest_b[b]) > 1:
                    best_similarity = 0
                    best = []
                    for x in closest_b[b]:
                        similarity = self.block_similarity(x, b)
                        if similarity > best_similarity:
                            best_similarity = similarity
                            best = [x]
                        elif similarity == best_similarity:
                            best.append(x)
                    closest_b[b] = best

        # a match (x,y) is good if x is the closest to y and y is the closest to x
        matches = []
        for a in closest_a:
            if len(closest_a[a]) == 1:
                match = closest_a[a][0]
                if len(closest_b[match]) == 1 and closest_b[match][0] == a:
                    matches.append((a, match))

        return matches

    def _get_acceptable_constant_differences(self, block_a, block_b):
        # keep a set of the acceptable differences in constants between the two blocks
        acceptable_differences = set()
        acceptable_differences.add(0)

        block_a_base = block_a.instruction_addrs[0]
        block_b_base = block_b.instruction_addrs[0]
        acceptable_differences.add(block_b_base - block_a_base)

        # get matching successors
        for target_a, target_b in zip(block_a.call_targets, block_b.call_targets):
            # these can be none if we couldn't resolve the call target
            if target_a is None or target_b is None:
                continue
            acceptable_differences.add(target_b - target_a)
            acceptable_differences.add((target_b - block_b_base) - (target_a - block_a_base))

        # get the difference between the data segments
        # this is hackish
        if ".bss" in self._project_a.loader.main_bin.sections_map and \
                ".bss" in self._project_b.loader.main_bin.sections_map:
            bss_a = self._project_a.loader.main_bin.sections_map[".bss"].min_addr
            bss_b = self._project_b.loader.main_bin.sections_map[".bss"].min_addr
            acceptable_differences.add(bss_b - bss_a)
            acceptable_differences.add((bss_b - block_b_base) - (bss_a - block_a_base))

        return acceptable_differences

class BinDiff(Analysis):
    """
    This class computes the a diff between two binaries represented by angr Projects
    """
    def __init__(self, other_project):
        """
        :param other_project: The second project to diff
        """
        l.debug("Computing cfg's")
        self.cfg_a = self.project.analyses.CFG(context_sensitivity_level=1,
                                          keep_input_state=True,
                                          enable_symbolic_back_traversal=True)
        self.cfg_b = other_project.analyses.CFG(context_sensitivity_level=1,
                                                keep_input_state=True,
                                                enable_symbolic_back_traversal=True)
        l.debug("Done computing cfg's")

        self._p2 = other_project
        self._attributes_a = dict()
        self._attributes_a = dict()

        self._function_diffs = dict()
        self.function_matches = set()
        self._unmatched_functions_from_a = set()
        self._unmatched_functions_from_b = set()

        self._compute_diff()

    def functions_probably_identical(self, func_a_addr, func_b_addr):
        """
        :param func_a_addr: The address of the first function (in the first binary)
        :param func_b_addr: The address of the second function (in the second binary)
        :return: whether or not the functions appear to be identical
        """
        if self.cfg_a.project.is_hooked(func_a_addr) and self.cfg_b.project.is_hooked(func_b_addr):
            return self.cfg_a.project._sim_procedures[func_a_addr] == self.cfg_b.project._sim_procedures[func_b_addr]

        func_diff = self.get_function_diff(func_a_addr, func_b_addr)
        return func_diff.probably_identical

    @property
    def identical_functions(self):
        """
        :return: A list of function matches that appear to be identical
        """
        identical_funcs = []
        for (func_a, func_b) in self.function_matches:
            if self.functions_probably_identical(func_a, func_b):
                identical_funcs.append((func_a, func_b))
        return identical_funcs

    @property
    def differing_functions(self):
        """
        :return: A list of function matches that appear to differ
        """
        different_funcs = []
        for (func_a, func_b) in self.function_matches:
            if not self.functions_probably_identical(func_a, func_b):
                different_funcs.append((func_a, func_b))
        return different_funcs

    @property
    def unmatched_functions(self):
        return self._unmatched_functions_from_a, self._unmatched_functions_from_b

    # gets the diff of two functions in the binaries
    def get_function_diff(self, function_addr_a, function_addr_b):
        """
        :param function_addr_a: The address of the first function (in the first binary)
        :param function_addr_b: The address of the second function (in the second binary)
        :return: the FunctionDiff of the two functions
        """
        pair = (function_addr_a, function_addr_b)
        if pair not in self._function_diffs:
            function_a = self.cfg_a.function_manager.function(function_addr_a)
            function_b = self.cfg_b.function_manager.function(function_addr_b)
            self._function_diffs[pair] = FunctionDiff(function_a, function_b, self)
        return self._function_diffs[pair]

    @staticmethod
    def _compute_function_attributes(cfg):
        """
        :param cfg: An angr CFG object
        :return: a dictionary of function addresses to tuples of attributes
        """
        # the attributes we use are the number of basic blocks, number of edges, and number of subfunction calls
        attributes = dict()
        for function_addr in cfg.function_manager.functions:
            normalized_funtion = NormalizedFunction(cfg.function_manager.function(function_addr))
            number_of_basic_blocks = len(normalized_funtion.graph.nodes())
            number_of_edges = len(normalized_funtion.graph.edges())
            number_of_subfunction_calls = len(cfg.function_manager.interfunction_graph.successors(function_addr))
            attributes[function_addr] = (number_of_basic_blocks, number_of_edges, number_of_subfunction_calls)

        return attributes

    def _get_call_site_matches(self, func_a, func_b):
        possible_matches = set()

        fd = self.get_function_diff(func_a, func_b)
        basic_block_matches = fd.block_matches
        function_a = fd._function_a
        function_b = fd._function_b
        for (a, b) in basic_block_matches:
            if a in function_a.call_sites and b in function_b.call_sites:
                # add them in order
                for target_a, target_b in zip(function_a.call_sites[a], function_b.call_sites[b]):
                    possible_matches.add((target_a, target_b))
                # add them in reverse, since if a new call was added the ordering from each side
                # will remain constant until the change
                for target_a, target_b in zip(reversed(function_a.call_sites[a]),
                                              reversed(function_b.call_sites[b])):
                    possible_matches.add((target_a, target_b))

        return possible_matches

    def _get_plt_matches(self):
        plt_matches = []
        for name, addr in self.project.loader.main_bin.plt.items():
            if name in self._p2.loader.main_bin.plt:
                plt_matches.append((addr, self._p2.loader.main_bin.plt[name]))
        return plt_matches

    def _compute_diff(self):
        # get the attributes for all functions
        self.attributes_a = self._compute_function_attributes(self.cfg_a)
        self.attributes_b = self._compute_function_attributes(self.cfg_b)

        # get the initial matches
        initial_matches = self._get_plt_matches()
        initial_matches += self._get_function_matches(self.attributes_a, self.attributes_b)
        for (a, b) in initial_matches:
            l.debug("Initally matched (%#x, %#x)", a, b)

        # Use a queue so we process matches in the order that they are found
        to_process = deque(initial_matches)

        # Keep track of which matches we've already added to the queue
        processed_matches = set((x, y) for (x, y) in initial_matches)

        # Keep a dict of current matches, which will be updated if better matches are found
        matched_a = dict()
        matched_b = dict()
        for (x, y) in processed_matches:
            matched_a[x] = y
            matched_b[y] = x

        # while queue is not empty
        while to_process:
            (func_a, func_b) = to_process.pop()
            l.debug("Processing (%#x, %#x)", func_a, func_b)

            # we could find new matches in the successors or predecessors of functions
            func_a_succ = self.cfg_a.function_manager.interfunction_graph.successors(func_a)
            func_b_succ = self.cfg_b.function_manager.interfunction_graph.successors(func_b)
            func_a_pred = self.cfg_a.function_manager.interfunction_graph.predecessors(func_a)
            func_b_pred = self.cfg_b.function_manager.interfunction_graph.predecessors(func_b)

            # get possible new matches
            new_matches = set(self._get_function_matches(self.attributes_a, self.attributes_b,
                                                         func_a_succ, func_b_succ))
            new_matches |= set(self._get_function_matches(self.attributes_a, self.attributes_b,
                                                          func_a_pred, func_b_pred))

            # could also find matches as function calls of matched basic blocks
            new_matches.update(self._get_call_site_matches(func_a, func_b))

            # for each of the possible new matches add it if it improves the matching
            for (x, y) in new_matches:
                if (x, y) not in processed_matches:
                    processed_matches.add((x, y))
                    # if it's a better match than what we already have use it
                    l.debug("Checking function match %s, %s", hex(x), hex(y))
                    if _is_better_match(x, y, matched_a, matched_b, self.attributes_a, self.attributes_b):
                        l.debug("Adding potential match %s, %s", hex(x), hex(y))
                        if x in matched_a:
                            old_match = matched_a[x]
                            del matched_b[old_match]
                            l.debug("Removing previous match (%#x, %#x)", x, old_match)
                        if y in matched_b:
                            old_match = matched_b[y]
                            del matched_a[old_match]
                            l.debug("Removing previous match (%#x, %#x)", old_match, y)
                        matched_a[x] = y
                        matched_b[y] = x
                        to_process.appendleft((x, y))

        # reformat matches into a set of pairs
        self.function_matches = set((x, y) for (x, y) in matched_a.items())

        # get the unmatched blocks
        self._unmatched_functions_from_a = set(x for x in self.cfg_a.function_manager.functions if x not in matched_a)
        self._unmatched_functions_from_b = set(x for x in self.cfg_b.function_manager.functions if x not in matched_b)

        # remove unneeded function diffs
        for (x, y) in dict(self._function_diffs):
            if (x, y) not in self.function_matches:
                del self._function_diffs[(x, y)]

    @staticmethod
    def _get_function_matches(attributes_a, attributes_b, filter_set_a=None, filter_set_b=None):
        """
        :param attributes_a: dict of functions to their attributes
        :param attributes_b: dict of functions to their attributes
        :param filter_set_a: an optional set to limit attributes_a to the functions in this set
        :param filter_set_b: an optional set to limit attributes_b to the functions in this set
        :return: a list of tuples of matching objects
        """
        # get the attributes that are in the sets
        if filter_set_a is None:
            filtered_attributes_a = {k: v for k, v in attributes_a.items()}
        else:
            filtered_attributes_a = {k: v for k, v in attributes_a.items() if k in filter_set_a}

        if filter_set_b is None:
            filtered_attributes_b = {k: v for k, v in attributes_b.items()}
        else:
            filtered_attributes_b = {k: v for k, v in attributes_b.items() if k in filter_set_b}

        # get closest
        closest_a = _get_closest_matches(filtered_attributes_a, filtered_attributes_b)
        closest_b = _get_closest_matches(filtered_attributes_b, filtered_attributes_a)

        # a match (x,y) is good if x is the closest to y and y is the closest to x
        matches = []
        for a in closest_a:
            if len(closest_a[a]) == 1:
                match = closest_a[a][0]
                if len(closest_b[match]) == 1 and closest_b[match][0] == a:
                    matches.append((a, match))

        return matches

register_analysis(BinDiff, 'BinDiff')
