# Decompilation Corpus Tests

The decompilation corpus test suite is a collection of GitHub repositories and
GitHub Action workflows designed to produce and track the quality and
consistency of `angr` decompilation results.

## Purpose

This test suite ensures the consistency and robustness of `angr`'s decompilation
capabilities. It is intended to validate that `angr` is able to successfully
analyze and decompile files from the test corpus, as well as produce
deterministic decompilation output. For the times when differing output is
produced, we compare against historically collected decompilation snapshots and
offer up these changes summarized for developer acceptance review.

## External Repository Links

Corpus Data Store: https://github.com/project-purcellville/direct-file-store-0000

- The publicly-available store of binaries that are used for decompilation
  testing

Snapshot Data Store: https://github.com/project-purcellville/snapshots-0000

- The store of the resulting binary decompilation from the test suite for
  comparison

## Usage

Create a GitHub Actions event (https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows) file to simulate the desired workflow.
In this case, a run of the test suite against a pull request.

```json
# pr.event
{
  "inputs": {
    "corpus_github_path": "stable/"
    "nightly": false
  },
  "pull_request": {
    "head": {
      "ref": "snapshot-diff-cli-utility"
    },
    "base": {
      "ref": "master"
    }
  }
}
```

Then we call `act` on the `corpus_test.yml` workflow with this event. We provide
the path to the above event file, secrets needed for GitHub integration, and the
event type of `workflow_call`.

This kicks off a local GitHub Actions run that will build the specified version
of `angr`, and run it in parallel jobs against a selection of files from the
test file corpus.

```shell
sudo $(which act) \
  -W .github/workflows/corpus_test.yml \
  --eventpath pr.event \
  -s GH_TOKEN="$(gh auth token)" \
  -s SNAPSHOTS_PAT="$(gh auth token)" \
  workflow_call
```

After running, this will create a PR in the snapshots repository if it does not
already exist, commit the snapshots, and comment a change summary.

The change summary can be reproduced locally with:

```shell
./corpus_tests/scripts/snapshot_diff.sh \
  -H snapshot-diff-cli-utility \
  -t $(gh auth token)
```

## Design

This test suite is designed for primary integration with GitHub Actions and
development activity in the `angr` repository.

The suite is designed to be run whenever PRs are created to ensure that
decompiler regressions are noticed early and often and nightly for additional,
more extensive testing.

For local testing and usage of the test suite, we make extensive use of the
`act` utility (https://github.com/nektos/act).

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
def test_decompilation(binary, snapshot):
    """
    In order to accommodate insta's need to have snapshots stored in a single
    file directly in the local `./snapshots/` directory, but also allow a
    reasonable comparison with the snapshots repo using github's pull request
    comparison, we pull down each snapshot from deeper within the snapshot
    repo's directory structure, but place it with a flat name (path delimiters
    replaced) in the `./snapshots/`, tweaking it to work with the standard
    way `pytest-insta` works (see `pytest_insta_snapshot_name()` above).

    Note that the snapshot should already be downloaded (by the workflow or
    manually) and placed in the snapshots directory. The name should be
    'corpus__decompilation__<binary-subpath-/-escaped>.json.txt__0.txt'. For
    example, the binary 'binaries/my/path/binary.exe' should be named
    'corpus__decompilation__my_path_binary.exe.json.txt__0.txt' in the
    local `./snapshots/` directory.

    This needs to stay in sync with the code that downloads the snapshots
    in `corpus_test.yml`.
    """
    decompilation = analyze_binary(binary)
    if not decompilation:
        # Message already emitted.
        return False

    # Adds newlines after each newline literal '\\n'.
    diffable_decompilation = create_diffable_decompilation(decompilation)

    # This replaces path delimiters with underscores and appends ".json.txt".
    snapshot_name = pytest_insta_snapshot_name(binary)

    print(f'Loading snapshot "{snapshot_name}".')
    assert snapshot(snapshot_name) == diffable_decompilation
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
SNAPSHOTS_PAT=<YOUR-PERSONAL-ACCESS-TOKEN-FOR-SNAPSHOTS-REPO>  # As a secret.
```

### Effective Remote Repository Listing

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

### Optimizations

Through the use of the Github matrix operation, the processing of the test corpus binaries will be parallelized over up to 256 concurrent runners.

Cache dependencies using actions/cache to speed up workflow runs
