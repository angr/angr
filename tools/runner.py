"""Run an eval script.py with project attribute overrides taken from PUSHAN_OVERRIDES.

PUSHAN_OVERRIDES is a comma-separated list of name=0|1, applied to every Project
created by the script. Lets us A/B the new ctf-finder switches without editing
the evaluation scripts.
"""
import os
import runpy
import sys

import angr

def _coerce(value):
    # 0/1/true/false stay booleans (the A/B switches); anything else is kept as a string
    # so paths like vm_deob_dump_path can be passed too.
    if value in ("0", "false", "False", ""):
        return False
    if value in ("1", "true", "True"):
        return True
    return value


overrides = {}
for item in os.environ.get("PUSHAN_OVERRIDES", "").split(","):
    if not item.strip():
        continue
    name, _, value = item.partition("=")
    overrides[name.strip()] = _coerce(value.strip())

if overrides:
    _orig_init = angr.Project.__init__

    def _patched_init(self, *args, **kwargs):
        _orig_init(self, *args, **kwargs)
        for name, value in overrides.items():
            setattr(self, name, value)

    angr.Project.__init__ = _patched_init
    print(f"[runner] project overrides: {overrides}", flush=True)

sys.argv = ["script.py"]
runpy.run_path("script.py", run_name="__main__")
