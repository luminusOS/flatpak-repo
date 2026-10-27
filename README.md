# Luminus Flatpak repository

Catalog, validation and channel-publishing tools for Luminus Flatpak
distribution. `catalog.json` registers ZapTide and Aetheris for
x86_64/aarch64 and stable/testing. The manual publisher workflow imports
verified releases and emits a channel-specific catalog update artifact after
public verification. See [`docs/PUBLISHING.md`](docs/PUBLISHING.md).

The manual credential-transport workflow tests encrypted handoff between
separate GitHub Actions jobs using synthetic secrets, without accessing R2.

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

`contracts/` is the frozen artifact-contract v1 snapshot, with SHA-256 values
in `contracts.lock.json`. It still accepts release artifacts only for the three
initially approved applications. A new catalog entry does not extend that
release allowlist; revise the contract and its consumers before publishing a
new application. Update matching snapshots in both infrastructure repositories
together, with review and tests. Do not edit individual snapshot files locally.

## Workflows

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| Validate catalogs and contracts | pull request, push to `main` | Runs the tests and checks the catalog. Its `validate` job is the required check. |
| Publish Flatpak release | manual, protected `main` | Imports a verified release into a channel, signs it and uploads it. See `docs/PUBLISHING.md`. |
| Check R2 credential scope | manual, protected `main` | Issues short-lived channel credentials and can probe what they may and may not do. See `docs/ISSUER.md`. |
| Check environment protections | pull request, manual | Shows that pull requests cannot enter a signing environment and that dispatches are authorized. |
