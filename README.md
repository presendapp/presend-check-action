# Presend Dependency Security Check

A GitHub Action that checks your dependencies against [Presend](https://presend.pages.dev)'s free API for two real supply-chain risks:

- **Suspicious maintainer changes** (npm only) -- a package whose publisher changed after a long period of dormancy, the pattern behind the `event-stream` compromise. It cannot detect a hijacked existing account (`ua-parser-js`) or a malicious release by the original maintainer (`colors.js`).
- **Known vulnerabilities** (npm and PyPI) -- via [OSV.dev](https://osv.dev).

No signup, no API key, no paid tiers (per-minute rate limits apply) -- the underlying API is free to call directly too.

## Usage

### npm

```yaml
- uses: presendapp/presend-check-action@v1
  with:
    ecosystem: 'npm'                    # optional, this is the default
    manifest-path: 'package.json'       # optional, defaults to package.json
    checks: 'maintainer,vulnerability'  # optional, defaults to both
    fail-on-issue: 'true'               # optional, set to 'false' to only warn
```

### Python / PyPI

```yaml
- uses: presendapp/presend-check-action@v1
  with:
    ecosystem: 'pypi'
    manifest-path: 'requirements.txt'   # optional, defaults to requirements.txt
```

`maintainer-change-check` is npm-only for now and is silently skipped in `pypi` mode -- only `vulnerability-check` runs.

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

For each dependency in the manifest file, the action calls Presend's endpoints and prints a summary. If any package is flagged and `fail-on-issue` is `true` (the default), the workflow step fails.

A flagged maintainer change is a signal for manual review, not proof of compromise -- legitimate maintainer handoffs happen. Read the summary before assuming the worst.

## Source

This action wraps the public Presend API. Full API docs, source, and the underlying endpoints: [github.com/presendapp/presend-source](https://github.com/presendapp/presend-source)
