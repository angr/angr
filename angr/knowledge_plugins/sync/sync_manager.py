
from functools import wraps

import binsync

from ..plugin import KnowledgeBasePlugin
from ..functions import Function


def init_checker(f):
    @wraps(f)
    def initcheck(self, *args, **kwargs):
        if self._client is None:
            raise ValueError("Please initialize SynchronizationManager by calling initialize(client).")
        return f(self, *args, **kwargs)
    return initcheck


class SynchronizationManager(KnowledgeBasePlugin):
    """
    SynchronizationManager interfaces with a binsync client to push changes upwards and pull changes downwards.

    :ivar binsync.Client _client:   The binsync client.
    """
    def __init__(self, kb):
        super().__init__()

        self._kb = kb

        self._client = None  # binsync client

    #
    # Public methods
    #

    def connect(self, client):
        self._client = client

    @property
    def connected(self):
        return self._client is not None

    def commit(self):
        self._client.save_state()

    @init_checker
    def users(self):
        return self._client.users()

    #
    # Pushers
    #

    @init_checker
    def push_function(self, func):
        """
        Push a function upwards.

        :param Function func:   The Function object to push upwards.
        :return:                True if updates are made. False otherwise.
        :rtype:                 bool
        """

        _func = binsync.data.Function(func.addr, name=func.name, comment=None)
        return self._client.get_state().set_function(_func)

    @init_checker
    def pull_function(self, addr):
        """
        Pull a function downwards.

        :param int addr:    Address of the function.
        :return:            The binsync.data.Function object if pulling succeeds, or None if pulling fails.
        :rtype:             binsync.data.Function
        """

        try:
            func = self._client.get_state().get_function(addr)
            return func
        except KeyError:
            return None


KnowledgeBasePlugin.register_default("sync", SynchronizationManager)
