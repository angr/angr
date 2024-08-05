# Decompilation Corpus Tests

The decompilation corpus test suite is a collection of binaries that are run against `angr` to produce
decompilation results. The intention of this test suite is to ensure quality and consistency of the
decompilation analysis in the `angr` framework.

## External Repository Links

Corpus Data Store: https://github.com/project-purcellville/direct-file-store-0000

- The store of binaries that are used for decompilation testing

Snapshot Data Store: https://github.com/project-purcellville/snapshots-0000

- The store of the resulting binary decompilation from the test suite for comparison

## Purpose

This test suite ensures the consistency and quality of `angr`'s decompilation analysis.
Beyond validating the determinism of the decompilation output, it also verifies that any
changes to the decompilation process that result in different outputs are reasonable and realistic.

To gain a greater resiliency to edge cases, this test suite provides a substantial amount of
test binaries with a variety of build targets to ensure robustness of the `angr` analysis framework.

## Github Actions Approach

Using the Github API, get a tree listing of the test corpus directory after first getting the SHA value for the desired top level directory.

```shell
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer <YOUR-TOKEN>" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/OWNER/REPO/content/PATH?ref=main
```

https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28

```shell
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer <YOUR-TOKEN>" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/OWNER/REPO/git/trees/TREE_SHA
```

**Important notes for Github actions rate limiting: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28**

> ### Primary rate limit for GITHUB_TOKEN in GitHub Actions

> You can use the built-in GITHUB_TOKEN to authenticate requests in GitHub Actions workflows. See "Automatic token authentication."

> The rate limit for GITHUB_TOKEN is 1,000 requests per hour per repository. For requests to resources that belong to a GitHub Enterprise Cloud account, the limit is 15,000 requests per hour per repository.

> ### About secondary rate limits

> In addition to primary rate limits, GitHub enforces secondary rate limits in order to prevent abuse and keep the API available for all users.

> **You may encounter a secondary rate limit if you:**

> - Make too many concurrent requests. No more than 100 concurrent requests are allowed. This limit is shared across the REST API and GraphQL API.

> - Make too many requests to a single endpoint per minute. No more than 900 points per minute are allowed for REST API endpoints, and no more than 2,000 points per minute are allowed for the GraphQL API endpoint. For more information about points, see "Calculating points for the secondary rate limit."

> - Make too many requests per minute. No more than 90 seconds of CPU time per 60 seconds of real time is allowed. No more than 60 seconds of this CPU time may be for the GraphQL API. You can roughly estimate the CPU time by measuring the total response time for your API requests.

In order to combat this rate limiting, the use of the tree API will allow the actions pipeline to make a single
request for all of the sub binaries in the test corpus repo. Through the use of the raw.githubusercontent.com
interface, the binaries will be downloaded to the Github runner to be processed by `angr`. Limits may exist on
the raw githubusercontent https://stackoverflow.com/questions/66522261/does-github-rate-limit-access-to-public-raw-files.
GitHub provides little with respect to the raw.githubusercontent limitations, so this may turn into some issues later down the road.

### Configuration

There are currently a few variables that can be used for configuration that is used within the Github Action.
These are configurable and can be used to test on a subset of binaries based on the path into the corpus repo.

```shell
# points to the github repo that contains the corpus for testing
CORPUS_GITHUB_OWNER="project-purcellville"
CORPUS_GITHUB_REPO="direct-file-store-0000"
CORPUS_GITHUB_PATH="cgc-binaries" # or a subset via "cgc-binaries/linux-build/challenges"

# points to the github repo that contains the snapshots of the decompilation output
SNAPSHOT_GITHUB_OWNER="project-purcellville"
SNAPSHOT_GITHUB_REPO="snapshots-0000"
```

### Optimizations

Through the use of the Github matrix operation, the processing of the test corpus binaries will be parallelized over up to 256 concurrent runners.

Cache dependencies using actions/cache to speed up workflow runs

### Angr Decompilation Testing Approach

Using the angr python API, a CFG is generated for the desired test corpus binary. The discovered functions are then iterated over and passed into the Decompiler analysis. Each of these functions are then stored off into a json object with the keys as a composition of "func_addr:func_name" and the values being the decompilation output or null on failure.

```python
def analyze_binary(binary_path):
    """
    Run the binary through CFG generation and extract the decompilation from the Decompiler analysis.
    The intention of this analysis function is to use as little angr interfaces as possible since they may
    change over time. If they change, this script will need updating.
    """
    project = angr.Project(binary_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    decompilation = {}

    function: angr.knowledge_plugins.functions.function.Function
    for function in cfg.functions.values():
        function.normalize()

        # Wrapping in a try/except because the decompiler sometimes fails
        try:
            decomp = project.analyses.Decompiler(
                func=function,
                cfg=cfg,
                # setting show_casts to false because of non-determinism
                options=[
                    (
                        PARAM_TO_OPTION["structurer_cls"],
                        "Phoenix",
                    ),
                    (
                        PARAM_TO_OPTION["show_casts"],
                        False,
                    ),
                ],
            )
        except Exception as e:
            print(e)

        func_key = f"{function.addr}:{function.name}"

        if decomp.codegen:
            decompilation[func_key] = decomp.codegen.text
        else:
            decompilation[func_key] = None

    return decompilation
```

#### Using pytest-insta for snapshot comparison

Since pytest-insta is an extension of the pytest library, it can be easily integrated into the testing suite by passing in a snapshot into the test.

The pytest framework is also extended with a --binary option which allows the passing in of a cli parameter to dynamically specify which binary to run the decompilation test on.

```python
### in conftest.py
import pytest

def pytest_addoption(parser):
    parser.addoption("--binary", action="store", default="")

@pytest.fixture
def binary(request):
    return request.config.getoption("--binary")


### in test_corpus.py
def test_functions_decompilation(binary, snapshot):
    analysis = analyze_binary(binary)
    assert snapshot(f"{binary.replace('/', '_')}.json") == analysis
```

The binary parameter in the test comes from the extension in conftest.py and the snapshot comes from `pip install
pytest-insta`. These `pytest-insta` snapshots are then used to validate if the decompilation has changed
for each PR.

### Decompilation Diff Acceptance

Through the use of the [snapshots repository](https://github.com/project-purcellville/snapshots-0000),
the snapshots from the GitHub Actions pipeline run will create a new PR with the associated snapshot changes
(if any exist). The workflow it to then review the PR in the snapshots repo (more information on that exists
in the readme of the snapshots repo) and comment/approve/merge the PR to then allow the `angr` PR to
pass and be mergable.
