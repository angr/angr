#!/usr/bin/env python

import logging
l = logging.getLogger("angr.helpers")


def once(f):
    name = f.__name__

    def func(self, *args, **kwargs):
        if len(args) + len(kwargs) == 0:
            if hasattr(self, "_" + name):
                return getattr(self, "_" + name)

            a = f(self, *args, **kwargs)
            setattr(self, "_" + name, a)
            return a
        else:
            return f(self, *args, **kwargs)
    func.__name__ = f.__name__
    return func
