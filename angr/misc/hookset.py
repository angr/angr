

class HookSet(object):

    @staticmethod
    def install_hooks(target, **what):
        """

        :param target:
        :param what:
        :return:
        """
        for name, hook in what.iteritems():
            func = getattr(target, name)
            if not isinstance(func, HookedMethod):
                func = HookedMethod(func)
                setattr(target, name, func)
            func.pending.append(hook)

    @staticmethod
    def remove_hooks(target, **what):
        """

        :param target:
        :param what:
        :return:
        """
        for name, hook in what.iteritems():
            hooked = getattr(target, name)
            if hook in hooked.pending:
                hooked.pending.remove(hook)
            if not hooked.pending:
                setattr(target, name, hooked.func)


class HookedMethod(object):

    def __init__(self, func):
        """

        :param func:
        """
        self.func = func
        self.pending = []
        self.pulled = []

    def __repr__(self):
        return "<HookedMethod(func: %s.%s, pending: %d, pulled: %d)>" % \
               (self.func.im_class.__name__, self.func.__name__,
                len(self.pending), len(self.pulled))

    def __call__(self, *args, **kwargs):
        try:
            if self.pending:
                next_hook = self.pending.pop()
                self.pulled.append(next_hook)
                result = next_hook(self.func.im_self, *args, **kwargs)

            else:
                result = self.func(*args, **kwargs)

        finally:
            self.pending.extend(reversed(self.pulled))
            self.pulled = []

        return result
