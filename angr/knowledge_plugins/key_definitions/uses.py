from typing import Dict, Set, TYPE_CHECKING
from collections import defaultdict

from ...code_location import CodeLocation

if TYPE_CHECKING:
    from .definition import Definition


class Uses:

    __slots__ = ('_uses_by_definition', '_uses_by_location' )

    def __init__(self):
        self._uses_by_definition: Dict['Definition',Set[CodeLocation]] = defaultdict(set)
        self._uses_by_location: Dict[CodeLocation, Set['Definition']] = defaultdict(set)

    def add_use(self, definition, codeloc: CodeLocation):
        """
        Add a use for a given definition.

        :param angr.analyses.reaching_definitions.definition.Definition definition: The definition that is used.
        :param codeloc: The code location where the use occurs.
        """
        self._uses_by_definition[definition].add(codeloc)
        self._uses_by_location[codeloc].add(definition)

    def get_uses(self, definition: 'Definition'):
        """
        Retrieve the uses of a given definition.

        :param definition: The definition for which we get the uses.
        """
        return self._uses_by_definition.get(definition, set())

    def remove_use(self, definition: 'Definition', codeloc: 'CodeLocation') -> None:
        """
        Remove one use of a given definition.

        :param definition:  The definition of which to remove the uses.
        :param codeloc:     The code location where the use is.
        :return:            None
        """
        if definition in self._uses_by_definition:
            if codeloc in self._uses_by_definition[definition]:
                self._uses_by_definition[definition].remove(codeloc)

        if codeloc in self._uses_by_location:
            self._uses_by_location[codeloc].remove(definition)

    def remove_uses(self, definition: 'Definition'):
        """
        Remove all uses of a given definition.

        :param definition:  The definition of which to remove the uses.
        :return:            None
        """
        if definition in self._uses_by_definition:
            codelocs = self._uses_by_definition[definition]
            del self._uses_by_definition[definition]

            for codeloc in codelocs:
                self._uses_by_location[codeloc].remove(definition)

    def get_uses_by_location(self, codeloc: CodeLocation) -> Set:
        """
        Retrieve all definitions that are used at a given location.

        :param codeloc: The code location.
        :return:        A set of definitions that are used at the given location.
        """
        return self._uses_by_location.get(codeloc, set())

    def copy(self):
        """
        Copy the instance.

        :return angr.angr.analyses.reaching_definitions.uses.Uses: Return a new <Uses> instance containing the same data.
        """
        u = Uses()
        u._uses_by_definition = defaultdict(set, ((k, set(v)) for k, v in self._uses_by_definition.items()))
        u._uses_by_location = defaultdict(set, ((k, set(v)) for k, v in self._uses_by_location.items()))

        return u

    def merge(self, other) -> bool:
        """
        Merge an instance of <Uses> into the current instance.

        :param angr.angr.analyses.reaching_definitions.uses.Uses other: The other <Uses> from which the data will be added
                                                                        to the current instance.
        :return: True if any merge occurred, False otherwise
        """
        merge_occurred = False

        for k, v in other._uses_by_definition.items():
            if k not in self._uses_by_definition:
                self._uses_by_definition[k] = v
                merge_occurred = True
            elif not v.issubset(self._uses_by_definition[k]):
                merge_occurred = True
                self._uses_by_definition[k] |= v

        for k, v in other._uses_by_location.items():
            if k not in self._uses_by_location:
                self._uses_by_location[k] = v
                merge_occurred = True
            elif not v.issubset(self._uses_by_location[k]):
                merge_occurred = True
                self._uses_by_location[k] |= v

        return merge_occurred
