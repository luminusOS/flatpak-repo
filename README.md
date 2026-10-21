# Luminus Flatpak repository

Infrastructure for Luminus Flatpak distribution. Package publishing is not yet
implemented. The current workflow tests encrypted handoff between separate
GitHub Actions jobs using synthetic secrets, without accessing R2.

## Run the tests

Requires Python 3 and GnuPG at `/usr/bin/gpg`.

```sh
/usr/bin/python3 -B -m unittest discover -s tests -v
```

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
