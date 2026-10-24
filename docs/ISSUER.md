# R2 credential issuer

`issue-credentials.yml` runs only from protected `main` through `workflow_dispatch`.
The issuer checks the format-specific descriptor, derives `stable/` or `testing/`
from the selected channel, fixes the bucket to `luminus-flatpak`, and signs the
local R2 temporary-credential JWT with the parent secret. The request shape is
limited to object read-write permission, that bucket, that prefix, and a 600-second
default TTL capped at 900 seconds. The encrypted capsule expires after 600 seconds.

Before reading parent credentials, the issuer queries the GitHub Actions run API.
It accepts only `push` runs for the package's contract-mapped repository and
workflow. ZapTide uses `luminusOS/zaptide` and
`.github/workflows/release.yml`; Aetheris uses `luminusOS/aetheris` and
`.github/workflows/release-flatpak.yml`; Sirius uses `luminusOS/sirius` and
`.github/workflows/ci.yml`. ZapTide and Sirius run their contract workflows
directly. Aetheris records the caller `.github/workflows/release.yml`, so the issuer
requires `referenced_workflows` to identify
`luminusOS/aetheris/.github/workflows/release-flatpak.yml` with the descriptor SHA.
The run must be completed successfully, its ID and caller workflow path must match
exactly, including `@refs/tags/<tag>`; branch refs are rejected. The run's
`head_sha`, tag, and version must match the descriptor and contract. A `-rc.N`
version is accepted only for `testing`.
The required positive `source_run_attempt` input must match the API response and is
recorded in the capsule descriptor. The issuer step uses the built-in `GITHUB_TOKEN`
only to read these public run records; workflow permissions remain `contents: read`.

GPG symmetric encryption carries credentials in a capsule bound to this repository,
issuer run ID and attempt, workflow SHA, ref, and channel. Its nonce is not a
single-use claim: a capsule can be replayed within the same run and attempt while
its 600-second validity window is open. That bounded replay retains the same short
window and credential scope; no durable replay store is used. The publisher checks
the binding and scope, then writes credentials only to an exclusive mode-0600 file
under `RUNNER_TEMP`. It performs a synthetic SigV4 PUT-shape check without making a
network request. The encrypted artifact is retained for one day. `t02-transport.yml`
remains the separate synthetic transport proof; it does not issue R2 credentials.

## Environment configuration

Use separate protected environments `issuer-stable`, `issuer-testing`,
`publisher-stable`, and `publisher-testing`. Keep the transport key unique to each
channel and install the same channel value in its issuer and publisher environment.

| Environment | Required secrets | Required variables |
| --- | --- | --- |
| `issuer-stable` | `R2_PARENT_ACCESS_KEY_ID`, `R2_PARENT_SECRET_ACCESS_KEY`, `TRANSPORT_KEY` | — |
| `issuer-testing` | `R2_PARENT_ACCESS_KEY_ID`, `R2_PARENT_SECRET_ACCESS_KEY`, `TRANSPORT_KEY` | — |
| `publisher-stable` | `TRANSPORT_KEY`, `SIGNING_SUBKEY`, `SIGNING_SUBKEY_PASSPHRASE` | `SIGNING_PRIMARY_FINGERPRINT`, `SIGNING_SUBKEY_FINGERPRINT` |
| `publisher-testing` | `TRANSPORT_KEY`, `SIGNING_SUBKEY`, `SIGNING_SUBKEY_PASSPHRASE` | `SIGNING_PRIMARY_FINGERPRINT`, `SIGNING_SUBKEY_FINGERPRINT` |

The R2 parent keys must come from an R2 Object Read & Write token restricted to
this repository's bucket. Do not place them in publisher environments. Stable
issuer and publisher environments must retain their existing human approval gates.
The publisher workflow does not consume signing keys during this synthetic check.

## Limits and provisioning

The provenance check does not inspect artifact contents or independently resolve
the tag ref to a commit; it checks the run metadata and reported `head_sha`. T08/T09
still need authenticated cross-repository dispatch and artifact hash verification.
No CI run has tested credentials against live R2, verified expiry during real
publication, or demonstrated fork rejection. The synthetic SigV4 check does not
show that an R2 request succeeds or that R2 enforces the claimed scope. A
user-authorized provisioning step is still required to create bucket-scoped parent
R2 API tokens and configure the four protected environments and their secrets.
