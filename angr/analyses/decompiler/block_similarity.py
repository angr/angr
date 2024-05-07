import networkx as nx
from ailment.block import Block
from ailment.statement import Statement, ConditionalJump

from .utils import find_block_by_addr


def has_similar_stmt(blk1: Block, blk2: Block):
    """
    Returns True if blk1 has a statement that is similar to a statement in blk2, False otherwise.
    """
    for stmt1 in blk1.statements:
        for stmt2 in blk2.statements:
            if is_similar(stmt1, stmt2):
                return True
    return False


def is_similar(
    ail_obj1: Block | Statement, ail_obj2: Block | Statement, graph: nx.DiGraph = None, partial: bool = True
):
    """
    Returns True if the two AIL objects are similar, False otherwise.
    """
    if type(ail_obj1) is not type(ail_obj2):
        return False

    if ail_obj1 is ail_obj2:
        return True

    # AIL Blocks
    if isinstance(ail_obj1, Block):
        if len(ail_obj1.statements) != len(ail_obj2.statements):
            return False

        for stmt1, stmt2 in zip(ail_obj1.statements, ail_obj2.statements):
            if not is_similar(stmt1, stmt2, graph=graph):
                return False
        return True

    # AIL Statements
    elif isinstance(ail_obj1, Statement):
        # if all(barr in [0x404530, 0x404573] for barr in [ail_obj1.ins_addr, ail_obj2.ins_addr]):
        #    do a breakpoint

        # ConditionalJump Handler
        if isinstance(ail_obj1, ConditionalJump):
            # try a simple compare
            liked = ail_obj1.likes(ail_obj2)
            if liked or not graph:
                return liked

            # even in partial matching, the condition must at least match
            if not ail_obj1.condition.likes(ail_obj2.condition):
                return False

            # must use graph to know
            for attr in ["true_target", "false_target"]:
                t1, t2 = getattr(ail_obj1, attr).value, getattr(ail_obj2, attr).value
                try:
                    t1_blk, t2_blk = find_block_by_addr(graph, t1), find_block_by_addr(graph, t2)
                except KeyError:
                    return False

                # special checks for when a node is empty:
                if not t1_blk.statements or not t2_blk.statements:
                    # when both are empty, they are similar
                    if len(t1_blk.statements) == len(t2_blk.statements):
                        continue

                    # TODO: implement a check for when one is empty and other is jump.
                    #   this will require a recursive call into similar() to check if a jump and empty are equal
                    return False

                # skip full checks when partial checking is on
                if partial and t1_blk.statements[0].likes(t2_blk.statements[0]):
                    continue

                if not is_similar(t1_blk, t2_blk, graph=graph):
                    return False
            return True

        # Generic Statement Handler
        else:
            return ail_obj1.likes(ail_obj2)
    else:
        return False


#
# Knuth-Morris-Pratt Similarity Matching
#


def _kmp_search_ail_obj(search_pattern, stmt_seq, graph=None, partial=True):
    """
    Uses the Knuth-Morris-Pratt algorithm for searching.
    Found: https://code.activestate.com/recipes/117214/.

    Returns a generator of positions, which will be empty if its not found.
    """
    # allow indexing into pattern and protect against change during yield
    search_pattern = list(search_pattern)

    # build table of shift amounts
    shifts = [1] * (len(search_pattern) + 1)
    shift = 1
    for pos, curr_pattern in enumerate(search_pattern):
        while shift <= pos and not is_similar(curr_pattern, search_pattern[pos - shift], graph=graph, partial=partial):
            shift += shifts[pos - shift]
        shifts[pos + 1] = shift

    # do the actual search
    start_pos = 0
    match_len = 0
    for c in stmt_seq:
        while (
            match_len == len(search_pattern)
            or match_len >= 0
            and not is_similar(search_pattern[match_len], c, graph=graph, partial=partial)
        ):
            start_pos += shifts[match_len]
            match_len -= shifts[match_len]
        match_len += 1
        if match_len == len(search_pattern):
            yield start_pos


def index_of_similar_stmts(search_stmts, other_stmts, graph=None, all_positions=False) -> int | None:
    """
    Returns the index of the first occurrence of the search_stmts (a list of Statement) in other_stmts (a list of
    Statement). If all_positions is True, returns a list of all positions.

    @return: None or int (position start in other)
    """
    positions = list(_kmp_search_ail_obj(search_stmts, other_stmts, graph=graph))

    if len(positions) == 0:
        return None

    return positions.pop() if not all_positions else positions


def in_other(stmts, other, graph=None):
    """
    Returns True if the stmts (a list of Statement) is found as a subsequence in other

    @return:
    """

    if index_of_similar_stmts(stmts, other, graph=graph) is not None:
        return True

    return False


def longest_ail_subseq(
    stmts_list: list[list[Statement]], graph=None
) -> tuple[list[Statement] | None, list[int] | None]:
    """
    Given a list of List[Statement], it returns the longest List[Statement] that is a subsequence of all the lists.
    The common List[Statement] most all be in the same order and adjacent to each other. If no common subsequence is
    found, it returns None.

    @param stmts_list:
    @param graph:
    @return: Tuple[List[Statement], List[int]], where the first element is the longest common subsequence, and the
             second element is a list of integers indicating the index of the longest common subsequence in each
             list of statements.
    """

    # find the longest sequence in all stmts
    subseq = []
    if len(stmts_list) <= 1:
        return stmts_list[0], [0]

    if len(stmts_list[0]) > 0:
        for i in range(len(stmts_list[0])):
            for j in range(len(stmts_list[0]) - i + 1):
                if j > len(subseq) and all(
                    in_other(stmts_list[0][i : i + j], stmts, graph=graph) for stmts in stmts_list
                ):
                    subseq = stmts_list[0][i : i + j]

    if not subseq:
        return None, [None] * len(stmts_list)

    return subseq, [index_of_similar_stmts(subseq, stmts, graph=graph) for stmts in stmts_list]
