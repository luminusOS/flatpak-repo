# R2 credential issuer

`r2-credential-check.yml` runs only from protected `main` through `workflow_dispatch`.
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
`luminusOS/aetheris/.github/workflows/release-flatpak.yml` with the descriptor SHA
and `refs/tags/<tag>` ref.
The run object must be completed successfully, its ID and caller workflow path must
match exactly, and its `head_sha`, tag, and version must match the descriptor and
contract. The caller workflow `path` is the workflow filename only; an earlier
assumption that GitHub appended `@refs/tags/<tag>` was wrong and was corrected after
the first real dispatch failed provenance verification. Since `head_branch` alone
does not distinguish a tag from a same-named branch, the issuer also reads the
repository's Git tag ref and verifies that it points to the descriptor commit. For
annotated tags it reads the tag object once and requires that object to point directly
to the same commit; nested annotated tags are rejected. A `-rc.N` version is accepted
only for `testing`.
The required positive `source_run_attempt` input must match the API response and is
recorded in the capsule descriptor. The issuer step uses the built-in `GITHUB_TOKEN`
only to read these public run and tag records; workflow permissions remain
`contents: read`.

GPG symmetric encryption carries credentials in a capsule bound to this repository,
issuer run ID and attempt, workflow SHA, ref, and channel. Its nonce is not a
single-use claim: a capsule can be replayed within the same run and attempt while
its 600-second validity window is open. That bounded replay retains the same short
window and credential scope; no durable replay store is used. The publisher checks
the binding and scope, then writes credentials only to an exclusive mode-0600 file
under `RUNNER_TEMP`. It performs a synthetic SigV4 PUT-shape check without making a
network request. The encrypted artifact is retained for one day.

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

## Opt-in live scope probe

On protected-main `workflow_dispatch`, set `live_probe=true` to run
`tools/r2_probe.py` in the publisher job after the synthetic check. It reads only
the publisher's mode-0600 credentials file; it never receives parent keys.
`ttl_seconds` is a choice of 600 (default) or 300. Set `expiry_check=true` only
with 300 seconds, and target `testing` for expiry runs to avoid the stable
environment's additional approval burden. The probe requires 120–300 seconds
of credential lifetime at start. If less than 120 seconds remain, it exits with
code 2 and reports `expired or nearly expired before probe; retry`; issue a new
credential and rerun. Expiry mode completes the positive PUT, same-key conditional
write guard, cleanup, and both final listings before waiting for expiration. After
expiration it performs only two nonce-named conditional PUT denial checks; it does
not attempt cleanup or listings again. Expiry proof accepts HTTP 403 with the
S3 denial codes observed in the earlier credential proof (`403` or `AccessDenied`); HTTP 401 `Unauthorized`
indicates revocation, not expiry, and fails the check. An unexpectedly successful
post-expiry PUT fails the probe and prints its exact bucket and key in
`expiry_residue` so an operator can remove the synthetic object manually. No
cleanup is claimed for post-expiry residue.

The matrix writes small synthetic objects only under
`<channel>/_scope-probe/<run-id>-<attempt>/`. It checks own-prefix PUT, GET, HEAD,
list, copy, delete, and a one-part multipart upload, plus expected HTTP 403
denials for nonce-unique keys in the other channel and bucket, a nonce-unique
root key, list/multipart/bucket operations, and cross-prefix copy/delete. The
cross-prefix DELETE target is absent by construction: it contains a fresh,
unguessable per-invocation nonce. Negative PUTs use `If-None-Match: *`; any
unexpectedly created object is tracked by exact bucket and key for best-effort
cleanup; any remaining keys are printed in the stdout `residue` list. Before any
negative tests, a same-key conditional PUT must return HTTP 412, proving the
precondition protects an existing probe-owned key. No prefix-wide deletes are
used. Final object and bounded multipart
listings must both succeed and be empty. Stdout is one JSON report; the step summary is
sanitized to operation names, expected/observed status, and pass/fail. Neither
contains credentials, signatures, authorization headers, or object contents.
The earlier credential proof observed HTTP 403 for denied prefix accesses and successfully exercised a
5-second credential TTL; HTTP 404 is not accepted as evidence of isolation.

This opt-in test is not package publication, package/signature validation,
edge-cache coverage, revocation proof, or proof against a compromised runner.
The provenance check verifies the run object and independently resolves its tag ref
to the descriptor commit, but does not inspect artifact contents; the release export and import work still need
authenticated cross-repository dispatch and artifact hash verification.

## Rotation

The parent R2 tokens expire on **2027-10-20**. Before then, recreate bucket-scoped
parent tokens and update `R2_PARENT_ACCESS_KEY_ID` and
`R2_PARENT_SECRET_ACCESS_KEY` in each `issuer-*` environment. Keep publisher
environments parent-key-free.


## Expiry response observed from R2

A real run showed that R2 answers a request signed with an expired temporary
credential with HTTP 403 and the S3 code `SignatureDoesNotMatch`, for both writes and
reads. The same signing code succeeded before expiry in the same run, so the expiry
phase accepts that code only after its own positive control passed. A revoked parent
token still differs: it yields HTTP 401.
