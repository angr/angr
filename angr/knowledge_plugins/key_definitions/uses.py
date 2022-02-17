from typing import Dict, Set, List, Tuple, Union, Any, TYPE_CHECKING
from collections import defaultdict

from ...code_location import CodeLocation

if TYPE_CHECKING:
    from .definition import Definition


class TotalUses:
    _total_uses_by_definition: Dict['Definition', List[Dict[str, Union[Set[CodeLocation], int]]]] = defaultdict(dict)
    _total_uses_by_location: Dict[CodeLocation, List[Dict[str, Union[Set['Definition'], int]]]] = defaultdict(dict)

    def __init__(self, is_definition_map=True):
        self.is_definition_map = is_definition_map
        self._total_uses_map: Dict[Union['Definition', CodeLocation], int] = dict()

    def __setitem__(self, key, value):
        if key in self._total_uses_map:
            del self[key]

        new_mapping = hash(frozenset(value))
        self._total_uses_map[key] = new_mapping

        if new_mapping in self._total_uses[key]:
            self._total_uses[key][new_mapping]["count"] += 1
        else:
            self._total_uses[key][new_mapping] = {"set": value, "count": 1}

    def __getitem__(self, key):
        if key in self._total_uses_map:
            mapping = self._total_uses_map[key]
            return self._total_uses[key][mapping]["set"]
        else:
            mapping = hash(frozenset(set()))
            self._total_uses_map[key] = mapping
            if mapping in self._total_uses[key]:
                self._total_uses[key][mapping]["count"] += 1
            else:
                self._total_uses[key][mapping] = {"set": set(), "count": 1}

            return self._total_uses[key][mapping]["set"]

    def __iter__(self):
        yield from self._total_uses_map

    def __delitem__(self, key):
        mapping = self._total_uses_map[key]
        del self._total_uses_map[key]
        self._total_uses[key][mapping]["count"] -= 1
        if self._total_uses[key][mapping]["count"] <= 0:
            del self._total_uses[key][mapping]

    @property
    def _total_uses(self):
        if self.is_definition_map:
            return TotalUses._total_uses_by_definition
        else:
            return TotalUses._total_uses_by_location

    def copy(self):
        new_obj = TotalUses(self.is_definition_map)
        for k, v in self.items():
            new_obj[k] = v
        return new_obj

    def items(self):
        for key in self._total_uses_map:
            yield key, self[key]

    def get(self, key, optional=None):
        if optional is None:
            return self[key]
        else:
            if key in self._total_uses_map:
                return self[key]
            else:
                return optional

    def add(self, key, value):
        old_set = self[key]
        del self[key]
        old_set.add(value)
        self[key] = old_set

    def remove(self, key, value):
        old_set = self[key]
        del self[key]
        old_set.remove(value)
        self[key] = old_set

    def merge(self, key, value: set):
        old_set = self[key]
        del self[key]
        self[key] = old_set | value



class Uses:

    __slots__ = ('_uses_by_definition', '_uses_by_location' )

    def __init__(self):
        self._uses_by_definition: TotalUses = TotalUses(is_definition_map=True)
        self._uses_by_location: TotalUses = TotalUses(is_definition_map=False)

    def add_use(self, definition: "Definition", codeloc: CodeLocation):
        """
        Add a use for a given definition.
        :param angr.analyses.reaching_definitions.definition.Definition definition: The definition that is used.
        :param codeloc: The code location where the use occurs.
        """
        self._uses_by_definition.add(definition, codeloc)
        self._uses_by_location.add(codeloc, definition)

    def get_uses(self, definition: 'Definition') -> Set[CodeLocation]:
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
                self._uses_by_definition.remove(definition, codeloc)

        if codeloc in self._uses_by_location:
            self._uses_by_location.remove(codeloc, definition)

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
                self._uses_by_location.remove(codeloc, definition)

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
        u._uses_by_definition = self._uses_by_definition.copy()
        u._uses_by_location = self._uses_by_location.copy()

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
                self._uses_by_definition.merge(k, v)

        for k, v in other._uses_by_location.items():
            if k not in self._uses_by_location:
                self._uses_by_location[k] = v
                merge_occurred = True
            elif not v.issubset(self._uses_by_location[k]):
                merge_occurred = True
                self._uses_by_location.merge(k, v)

        return merge_occurred