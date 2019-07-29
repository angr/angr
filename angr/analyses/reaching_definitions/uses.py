
from collections import defaultdict


class Uses:

    __slots__ = ('_uses_by_definition', )

    def __init__(self):
        self._uses_by_definition = defaultdict(set)

    def add_use(self, definition, codeloc):
        """
        Add a use for a given definition.

        :param angr.analyses.reaching_definitions.definition.Definition definition: The definition that is used.
        :param angr.analyses.code_location.CodeLocation codeloc: The code location where the use occurs.
        """
        self._uses_by_definition[definition].add(codeloc)

    def get_uses(self, definition):
        """
        Retrieve the uses of a given definition.

        :param angr.analyses.reaching_definitions.definition.Definition definition: The definition for which we get the
                                                                                    uses.
        """
        if definition not in self._uses_by_definition:
            return set()
        return self._uses_by_definition[definition]

    def copy(self):
        """
        Copy the instance.

        :return angr.angr.analyses.reaching_definitions.uses.Uses: Return a new <Uses> instance containing the same data.
        """
        u = Uses()
        u._uses_by_definition = self._uses_by_definition.copy()

        return u

    def merge(self, other):
        """
        Merge an instance of <Uses> into the current instance.

        :param angr.angr.analyses.reaching_definitions.uses.Uses other: The other <Uses> from which the data will be added
                                                                        to the current instance.
        """
        for k, v in other._uses_by_definition.items():
            if k not in self._uses_by_definition:
                self._uses_by_definition[k] = v
            else:
                self._uses_by_definition[k] |= v
