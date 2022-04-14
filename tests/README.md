Tests
=====

These tests require the nose python package.

    pip install nose

Then you can run tests by calling nosetests, by default it will run all the tests in the tests/ folder. You can also
specify a file.

    # Run all tests
    nosetests -v --nologcapture test_*.py
    # Run tests from a single file
    nosetests -v --nologcapture test_fauxware.py

These tests require the binaries repository, clone it in the folder where angr was cloned.

    git clone https://github.com/angr/binaries
