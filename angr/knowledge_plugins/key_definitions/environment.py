from typing import Dict, Tuple, Union

from .dataset import dataset_from_datasets, DataSet
from .undefined import Undefined, UNDEFINED
from .unknown_size import UNKNOWN_SIZE


class Environment:
    """
    Represent the environment in which a program runs.
    It's a mapping of variable names, to <DataSet> that should contain possible addresses, or <UNDEFINED>, at
    which their respective values are stored.

    **Note**: The <Environment> object does not store the values associated with variables themselves.
    """
    def __init__(self, environment: Dict[Union[str,Undefined],DataSet]=None):
        self._environment: Dict[Union[str,Undefined],DataSet] = environment or {}

    def get(self, names: DataSet) -> Tuple[DataSet,bool]:
        """
        :param names: Potential values for the name of the environment variable to get the pointers of.
        :return:
            The potential addresses of the values the environment variable can take;
            And a boolean value telling whether all the names were known of the internal representation (i.e. will be
            False if one of the queried variable was not found).
        """
        has_unknown = not all(map(lambda name: name in self._environment.keys(), names))

        def _get(name):
            if not isinstance(name, (str, Undefined)):
                raise TypeError("get(): Expected str, or Undefined, got %s" % type(name).__name__)
            return self._environment.get(name, DataSet({UNDEFINED}, UNKNOWN_SIZE))

        pointers = dataset_from_datasets(list(map(_get, names)))

        return (pointers, has_unknown)

    def set(self, name: Union[str,Undefined], pointers: DataSet):
        """
        :param name: Name of the environment variable to which we will associate the pointers.
        :param pointers: New addresses where the new values of the environment variable are located.
        """
        if not isinstance(name, (str, Undefined)):
            raise TypeError("set(): Expected str, or Undefined, got %s" % type(name).__name__)
        self._environment[name] = pointers

    def __str__(self):
        return "Environment: %s" % self._environment

    def __repr__(self):
        return "Environment: %s" % self._environment
