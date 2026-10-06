# AttackPath Engine

A pure-Python security analysis engine. It operates on JSON scenario data (an
event log plus an environment graph) to:

- correlate suspicious events into attack groups,
- reconstruct the ordered attack path,
- identify the root cause,
- compute the blast radius (reachable and sensitive assets),
- apply candidate remediations and verify whether they break the path,
- explain the analysis in human-readable form.

The public API lives in `attackpath` and exposes `analyze`, `apply_remediation`,
`verify`, and `explain`. (The engine logic is implemented incrementally; this is
the baseline skeleton.)

## Offline setup caveat

This sandbox has **no access to PyPI** (the package index is blocked). The
required pure-Python dependencies (networkx and the pytest toolchain) are
therefore **vendored from pre-cloned GitHub sources** rather than installed from
PyPI. The `scripts/setup_env.sh` script encapsulates the full, reproducible
procedure: it creates a virtual environment, copies the dependency packages into
its `site-packages`, writes the static version files those packages need, and
performs an editable install of this package.

By default the vendoring sources are read from `/projects/sandbox`. Override the
base directory with the `VENDOR_SRC` environment variable if your checkouts live
elsewhere.

## Running

```bash
bash scripts/setup_env.sh
source .venv/bin/activate
python -m pytest -q
```

`scripts/setup_env.sh` is idempotent and safe to re-run.
