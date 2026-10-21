# Luminus Flatpak repository

Catalog and validation tools for Luminus Flatpak distribution. `catalog.json`
registers ZapTide and Aetheris for x86_64/aarch64 and stable/testing. Package
publishing and the public remote are not implemented yet.

## Run the tests

Requires Python 3.10 or newer and GnuPG at `/usr/bin/gpg`.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: -r requirements-dev.txt
.venv/bin/python -B -m unittest discover -s contracts -p 'test_*.py' -v
.venv/bin/python -B -m unittest discover -s tests -p 'test_*.py' -v
.venv/bin/python tools/catalog.py catalog.json
```

## Extend the catalog

Add an application ID and its source repository/workflow to `catalog.json`, then
run the checks above. Both architectures and channels remain required. Catalog
validation does not fetch builds, approve releases, or publish packages.

`contracts/` is the frozen T01 artifact-contract v1 snapshot, with SHA-256 values
in `contracts.lock.json`. It still accepts release artifacts only for the three
initially approved applications. A new catalog entry does not extend that
release allowlist; revise the contract and its consumers before publishing a
new application. Update matching snapshots in both infrastructure repositories
together, with review and tests. Do not edit individual snapshot files locally.

## Credential transport test

Run `T02 protected credential transport` manually from protected `main`.
The `t02-issuer-testing` and `t02-issuer-stable` environments each need
`T02_PARENT_CANARY` and `T02_TRANSPORT_KEY`: random 64-character hexadecimal
values, unique to each channel. Each matching publisher environment needs only
the same transport key. Keep the parent canary absent from publisher secrets.

All four environments must restrict deployments to `main`. Stable issuance
requires human approval. Encrypted envelopes expire after 300 seconds and are
bound to the channel, commit and workflow run. Remove test secrets and artifacts
after inspection. Use synthetic values only.

[The original test passed](https://github.com/luminusOS/flatpak-repo/actions/runs/39341947363).
[An untrusted branch was blocked before starting a runner](https://github.com/luminusOS/flatpak-repo/actions/runs/39341951844).
Those test secrets and artifacts have been removed; another run needs fresh
synthetic values. These results do not validate R2 access from CI or production
package publishing.
