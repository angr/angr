from __future__ import annotations
import claripy

from .undefined import Undefined, UNDEFINED


class Environment:
    """
    Represent the environment in which a program runs.
    It's a mapping of variable names, to `claripy.ast.Base` that should contain possible addresses, or <UNDEFINED>, at
    which their respective values are stored.

    **Note**: The <Environment> object does not store the values associated with variables themselves.
    """

    __slots__ = ("_environment",)

    def __init__(self, environment: dict[str | Undefined, set[claripy.ast.Base]] | None = None):
        self._environment: dict[str | Undefined, set[claripy.ast.Base]] = environment or {}

    def get(self, names: set[str]) -> tuple[set[claripy.ast.Base], bool]:
        """
        :param names: Potential values for the name of the environment variable to get the pointers of.
        :return:
            The potential addresses of the values the environment variable can take;
            And a boolean value telling whether all the names were known of the internal representation (i.e. will be
            False if one of the queried variable was not found).
        """
        has_unknown = not all(name in self._environment for name in names)

        def _get(name):
            if not isinstance(name, (str, Undefined)):
                raise TypeError(f"get(): Expected str, or Undefined, got {type(name).__name__}")
            return self._environment.get(name, {UNDEFINED})

        pointers = set()
        for values in map(_get, names):
            pointers |= values

        return pointers, has_unknown

    def set(self, name: str | Undefined, pointers: set[claripy.ast.Base]):
        """
        :param name: Name of the environment variable to which we will associate the pointers.
        :param pointers: New addresses where the new values of the environment variable are located.
        """
        if not isinstance(name, (str, Undefined)):
            raise TypeError(f"set(): Expected str, or Undefined, got {type(name).__name__}")
        self._environment[name] = pointers

    def __str__(self):
        return f"Environment: {self._environment}"

    def __repr__(self):
        return f"Environment: {self._environment}"

    def __eq__(self, other: object) -> bool:
        assert isinstance(other, Environment), f"Cannot compare Environment with {type(other).__name__}"
        return self._environment == other._environment

    def merge(self, *others: Environment) -> tuple[Environment, bool]:
        new_env = self._environment

        for other in others:
            if not isinstance(other, Environment):
                raise TypeError(f"Cannot merge Environment with {type(other).__name__}")

            keys = set(new_env.keys())
            keys |= other._environment.keys()

            def _dataset_from_key(key, environment1, environment2):
                v = environment1.get(key, None)
                w = environment2.get(key, None)
                # Because the key is coming from one of them, they cannot be both `None`.
                if v is None:
                    return w
                if w is None:
                    return v
                return v | w

            new_env = {k: _dataset_from_key(k, new_env, other._environment) for k in keys}

        merge_occurred = new_env != self._environment
        return Environment(environment=new_env), merge_occurred

    def compare(self, other: Environment) -> bool:
        for k in set(self._environment.keys()).union(set(other._environment.keys())):
            if k not in self._environment:
                return False
            if (
                k in self._environment
                and k in other._environment
                and not self._environment[k].issuperset(other._environment[k])
            ):
                return False
        return True
