# Presend Dependency Security Check

A GitHub Action that checks the dependencies in your `package.json` or `requirements.txt` for three supply-chain risks:

- **Typosquats** (npm and PyPI): a dependency whose name is one or two edits away from a popular package (`expres` next to `express`). It uses [Presend](https://presend.pages.dev)'s typosquat check, whose false-positive rate on the most-used packages is [measured and published](https://presend.pages.dev/measurements).
- **Suspicious maintainer changes** (npm only): a new publisher after a long period of dormancy, the pattern behind the `event-stream` compromise. It cannot detect a hijacked existing account (`ua-parser-js`) or a malicious release by the original maintainer (`colors.js`). A flagged change is a signal for review, not proof of compromise: legitimate handoffs happen.
- **Names that do not exist** (npm and PyPI): a dependency name that is not on the registry, for instance invented by an AI model, is reported as an issue.
- **New packages** (npm and PyPI): a dependency first published less than 30 days ago (on PyPI, the age of the oldest release still published) is reported as a warning, which does not fail the job. A recent package is often legitimate; it is also where invented and look-alike names get registered. These two signals come with the maintainer-change check: removing `maintainer` from `checks` removes them too.
- **Known vulnerabilities** (npm and PyPI) of the version you use, straight from [OSV.dev](https://osv.dev).

It is not a malware scanner and does not analyse package code: use it alongside one.

No signup, no API key, no paid tiers (per-minute rate limits apply). The action sends package names to the Presend API and package names with versions to OSV.dev; it never sends your code. Its requests identify themselves with the User-Agent `presend-check-action`.

**Teams:** we are testing a paid version (a comment on every pull request that changes a dependency, higher limits, measurements re-run with every release). Nothing is for sale yet: [join the waitlist](https://presend.pages.dev/teams). This action stays free.

## Usage

### npm

```yaml
- uses: presendapp/presend-check-action@v1
  with:
    ecosystem: 'npm'                              # optional, this is the default
    manifest-path: 'package.json'                 # optional, defaults to package.json
    checks: 'typosquat,maintainer,vulnerability'  # optional, defaults to all three
    fail-on-issue: 'true'                         # optional, 'false' to only report
    fail-on-incomplete: 'false'                   # optional, 'true' to fail when some checks could not run
```

### Python / PyPI

```yaml
- uses: presendapp/presend-check-action@v1
  with:
    ecosystem: 'pypi'
    manifest-path: 'requirements.txt'   # optional, defaults to requirements.txt
```

The publisher-change analysis is npm-only: in `pypi` mode the same check reports only names that do not exist and new packages.

Full example workflow:

```yaml
name: Dependency security check
on: [push, pull_request]
jobs:
  check-npm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: presendapp/presend-check-action@v1

  check-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: presendapp/presend-check-action@v1
        with:
          ecosystem: 'pypi'
```

## What it does

The action reads the direct dependencies of the manifest (`dependencies` and `devDependencies` for npm). Names are checked in batches (100 per typosquat request, 20 per maintainer request) and all versions are sent to OSV.dev in a single request, so even a large manifest needs only a few requests. Rate limits are per minute: if one is reached, the action waits and retries before giving up.

**Which version is checked.** For npm, the installed version from `package-lock.json` when it sits next to `package.json`. Otherwise the version written in the manifest; for a range such as `^1.2.3` or `>=1.2`, that is its lower bound, labelled as such in the output, because the installed version may already include the fix. A dependency without a version is reported as not checked for vulnerabilities.

**Incomplete results.** When a check cannot run (rate limit, network error), the action says so with a warning and `RESULT INCOMPLETE`, and never reports a clean result for checks that did not run. This does not fail the job unless `fail-on-incomplete` is `'true'`.

If any package is flagged and `fail-on-issue` is `'true'` (the default), the step fails.

## Source

This action wraps the public Presend API. Full API docs, source, and the underlying endpoints: [github.com/presendapp/presend-source](https://github.com/presendapp/presend-source)
