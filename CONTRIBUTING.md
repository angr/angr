# Bug Reports

If you've found something that angr isn't able to solve and appears to be a bug, please let us know!

1. Create a fork off of angr/binaries and angr/angr
2. Give us a pull request with angr/binaries, with the binaries in question
3. Give us a pull request for angr/angr, with testcases that trigger the binaries in `angr/tests/broken_x.py`, `angr/tests/broken_y.py`, etc

Please try to follow the testcase format that we have (so the code is in a test_blah function), that way we can very easily merge that and make the scripts run.

Ideally, we can just fix the bug and rename `broken_x.py` to `test_x.py` without making any changes and it'll all work in our private CI.

# Contributing Code

Try to maintain the same coding style as existing files. *TODO: Add more info about this.*
