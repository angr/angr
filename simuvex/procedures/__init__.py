import os
import sys

# Import all classes under the current directory
SimProcedures = { }
path = os.path.dirname(os.path.abspath(__file__))

for py in [f[ : -3] for f in os.listdir(path) if f.endswith(".py") and f != "__init__.py"]:
	mod = __import__('.'.join([__name__, py]), fromlist = [py])
	classes = [getattr(mod, x) for x in dir(mod) if isinstance(getattr(mod, x), type)]
	for class_ in classes:
		SimProcedures[class_.__name__] = class_
