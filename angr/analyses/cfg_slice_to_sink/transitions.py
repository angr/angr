"""
Some utilitary functions to manage our representation of transitions:
    A dictionary, indexed by int (source addresses), which values are list of ints (target addresses).
"""

from __future__ import annotations


def merge_transitions(transitions, existing_transitions):
    """
    Merge two dictionaries of transitions together.

    :param Dict[int,List[int]] transitions:          Some transitions.
    :param Dict[int,List[int]] existing_transitions: Other transitions.

    :return Dict[int,List[int]]: The merge of the two parameters.
    """

    def _add_to_existing(address, values):
        if address in existing_transitions:
            values += existing_transitions[address]
            values = list(set(values))
        existing_transitions.update({address: values})

    [_add_to_existing(x[0], x[1]) for x in transitions.items()]

    return existing_transitions
