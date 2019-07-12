
from functools import wraps

try:
    import binsync
    binsync_available = True
except ImportError:
    binsync_available = False

from ..plugin import KnowledgeBasePlugin


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

    def update(self):
        self._client.update()

    def copy(self):
        raise NotImplementedError

    @init_checker
    def users(self):
        return self._client.users()

    def tally(self, users=None):
        return self._client.tally(users=users)

    #
    # Fillers
    #

    def fill_function(self, func, user=None):
        """
        Grab all relevant information from the specified user and fill the @func.

        :param Function func:   The Function object to work on.
        :param str user:        Name of the user where we are going to pull information from. If None, information will
                                be pulled from the current user.
        :return:                None
        """

        _func = self.pull_function(func.addr, user=user)  # type: binsync.data.Function
        if _func is None:
            # the function does not exist for that user's state
            return
        func.name = _func.name

        # comments
        for block in func.blocks:
            for ins_addr in block.instruction_addrs:
                _comment = self.pull_comment(ins_addr, user=user)
                if _comment is not None:
                    self._kb.comments[ins_addr] = _comment

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

        _func = binsync.data.Function(func.addr, name=func.name, notes=None)
        return self._client.get_state().set_function(_func)

    @init_checker
    def push_comment(self, addr, comment):
        """
        Push a comment at a certain address upwards.

        :param int addr:    Address of the comment.
        :param str comment: The comment itself.
        :return:            bool
        """

        return self._client.get_state().set_comment(addr, comment)

    @init_checker
    def push_comments(self, comments):
        """
        Push a bunch of comments upwards.

        :param dict comments:   A dict of comments keyed by their instruction addresses.
        :return:                bool
        """

        r = False
        for addr, comment in comments.items():
            r |= self._client.get_state().set_comment(addr, comment)
        return r

    #
    # Pullers
    #

    @init_checker
    def pull_function(self, addr, user=None):
        """
        Pull a function downwards.

        :param int addr:    Address of the function.
        :param str user:    Name of the user.
        :return:            The binsync.data.Function object if pulling succeeds, or None if pulling fails.
        :rtype:             binsync.data.Function
        """

        try:
            func = self._client.get_state(user=user).get_function(addr)
            return func
        except KeyError:
            return None

    @init_checker
    def pull_comment(self, addr, user=None):
        """
        Pull a comment downwards.

        :param int addr:    Address of the comment.
        :param str user:    Name of the user.
        :return:            The comment it self, or None if there is no comment.
        :rtype:             str or None
        """

        try:
            comment = self._client.get_state(user=user).get_comment(addr)
            return comment
        except KeyError:
            return None

    @init_checker
    def pull_comments(self, start_addr, end_addr=None, user=None):
        """
        Pull comments downwards.

        :param int start_addr:  Where we want to pull comments.
        :param int end_addr:    Where we want to stop pulling comments (exclusive).
        :return:                An iterator.
        :rtype:                 Iterable
        """

        return self._client.get_state(user=user).get_comments(start_addr, end_addr=end_addr)

    @init_checker
    def pull_patches(self, user=None):
        """
        Pull patches.

        :param str user:    Name of the user to patches from.
        :return:            An iterator
        :rtype:             Iterable
        """

        return self._client.get_state(user=user).get_patches()


if binsync_available:
    KnowledgeBasePlugin.register_default("sync", SynchronizationManager)
