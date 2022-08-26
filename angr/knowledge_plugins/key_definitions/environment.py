from typing import Dict, Tuple, Union, Set

import claripy

from .undefined import Undefined, UNDEFINED


class Environment:
    """
    Represent the environment in which a program runs.
    It's a mapping of variable names, to `claripy.ast.Base` that should contain possible addresses, or <UNDEFINED>, at
    which their respective values are stored.

    **Note**: The <Environment> object does not store the values associated with variables themselves.
    """
    def __init__(self, environment: Dict[Union[str,Undefined],Set[claripy.ast.Base]]=None):
        self._environment: Dict[Union[str,Undefined],Set[claripy.ast.Base]] = environment or {}

    def get(self, names: Set[str]) -> Tuple[Set[claripy.ast.Base],bool]:
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
            return self._environment.get(name, {UNDEFINED})

        pointers = set()
        for values in map(_get, names):
            pointers |= values

        return pointers, has_unknown

    def set(self, name: Union[str,Undefined], pointers: Set[claripy.ast.Base]):
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

    def __eq__(self, other: object) -> bool:
        assert isinstance(other, Environment), "Cannot compare Environment with %s" % type(other).__name__
        return self._environment == other._environment

    def merge(self, *others: 'Environment') -> Tuple['Environment',bool]:

        new_env = self._environment

        for other in others:
            if not isinstance(other, Environment):
                raise TypeError("Cannot merge Environment with %s" % type(other).__name__)

            keys = set(new_env.keys())
            keys |= other._environment.keys()

            def _dataset_from_key(key, environment1, environment2):
                v = environment1.get(key, None)
                w = environment2.get(key, None)
                # Because the key is coming from one of them, they cannot be both `None`.
                if v is None: return w
                if w is None: return v
                return v | w

            new_env = dict(map(
                lambda k: (k, _dataset_from_key(k, new_env, other._environment)),
                keys
            ))

        merge_occurred = new_env != self._environment
        return Environment(environment=new_env), merge_occurred
