import pytest

def pytest_addoption(parser):
    parser.addoption("--binary", action="store", default="")

@pytest.fixture
def binary(request):
    return request.config.getoption("--binary")
