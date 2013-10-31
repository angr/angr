#!/usr/bin/env python

import logging
l = logging.getLogger("angr.helpers")

def once(f):
	name = f.__name__
	def func(self, *args, **kwargs):
		if hasattr(self, "_" + name):
			return getattr(self, "_" + name)

		a = f(self, *args, **kwargs)
		setattr(self, "_" + name, a)
		return a
	func.__name__ = f.__name__
	return func

