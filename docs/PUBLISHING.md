# Flatpak publishing

The manual `Publish Flatpak release` workflow imports one allowlisted release
into a shared OSTree repository per channel. It accepts only the registered
application IDs, stable/testing channels, the source repository and workflow in
the frozen distribution contract, and a source run identity verified by the
protected issuer. Application source is never checked out or executed.

## Three-phase flow

1. **Checks** runs the test suite and distribution contracts on protected
   `main`.
2. **Prepare** has no GitHub environment and no secrets. It installs Flatpak and
   OSTree, mirrors `https://flatpak.luminusos.org/<channel>/` over public HTTPS,
   then authenticates the mirror before downloading release bundles or changing
   the repository. The summary's detached signature must verify using the
   channel public key in `trust/<channel>.asc`, and GnuPG's signing-subkey and
   primary fingerprints must both match `trust.json`. The ledger, when present,
   must also have a valid detached signature from that exact channel subkey.
   OSTree summary verification is enabled on the temporary remote; after pull,
   the importer checks every ref and checksum in the verified summary against
   the mirror's local refs. Only then does prepare validate the release
   descriptor/manifest/report and both bundles, verify each bundle's size and
   SHA-256 against the manifest, import without signing, and upload the staged
   repository and public inputs as an artifact. For existing channels,
   `ostree pull --mirror` mirrors all
   advertised refs and the commit/object/delta closure reachable from those
   refs; this deliberately favors a complete ref-complete mirror over a narrow
   per-application pull. An empty-repository first publish is allowed only when
   both the summary and refs endpoints return HTTP 404 and the initialized local
   repository contains no summary, ledger, or refs. A summary without its
   signature always fails closed. A valid signed summary with no ledger is the
   documented legacy bootstrap; it can only record an exact already-current
   commit, and the next publish writes a signed ledger. No R2 credentials are
   used to read or mirror repository data.
3. **Issuer** runs only after prepare succeeds, behind the selected
   `issuer-<channel>` environment. The proven issuer step requests the maximum
   supported R2 credential TTL, 900 seconds (`MAX_TTL_SECONDS`). Its encrypted
   capsule has a separate fixed 600-second transport lifetime. **Publisher** is
   gated by `publisher-<channel>` approval and consumes the capsule before any
   install, staged-repo download or signing work. The first artifact-download
   action only retrieves the capsule; capsule consumption is the first command
   step. If stable approvals take longer than the capsule's 600-second lifetime,
   consumption fails closed; re-dispatch after approval rather than extending
   the capsule lifetime. Issuer approval precedes issuance, publisher approval
   follows it.

The prepare artifact is not trusted by the publisher. Prepare saves the signed
base files (summary, its signatures, and the ledger with its signature) under
`base-auth/`, or an `EMPTY` marker for a first publish. Before signing anything
the publisher rebuilds the trusted descriptor from the dispatch inputs, downloads
the release manifest and both bundles itself, checks them against the manifest,
and derives the expected commits from those bundles. It then requires that
the base signatures verify against the pinned channel key and that the staged
repository holds exactly the refs of the authenticated base plus the two new
refs, each at the expected commit. The staged ledger must equal the
authenticated base ledger plus the entries for this release, the version rules
are replayed against the authenticated ledger, top-level entries must be on an
allowlist, and `ostree fsck` must pass. An `EMPTY` claim is accepted only if the
public summary and refs endpoints return 404. The upload set does not depend
on any value from the prepare artifact: the publisher lists the channel prefix
in R2 with its scoped credentials, uploads every immutable file that is not
there yet, always uploads the mutable metadata last, and fails if a published
immutable object has a different size from the staged one. Objects unreachable
from any ref are pruned from the staged copy before signing. Not independently
verified: the staged `config` file and prepare-generated static deltas, which
clients check against commit checksums but which could be published as
unneeded files. The listing permission of the scoped credentials is covered by
the live probe only for narrower prefixes, so the first real run confirms it.

Flatpak clients verify every commit, not only the summary. The publisher
therefore signs the commit of each application ref with the channel subkey before
it updates the summary, and clients configured with the channel key reject a
commit that carries no signature from that key. Found by installing from the
published testing channel with the real `flatpak` command.

After consuming the capsule, publisher imports the channel signing subkey into
a mode-0700 GnuPG home on `/dev/shm`; it verifies the filesystem type is `tmpfs`
before using the key. An unconditional cleanup kills `gpg-agent` and removes
the key home and credential file. The importer reads the mode-0600 credentials
file inside the upload process only. Secret values are never exported through
`GITHUB_ENV`, step outputs, or later steps.

The importer validates expected architecture refs, application/runtime
metadata and safe tree paths before either bundle is merged. Release versions
come from the descriptor after it has been matched to the source release
manifest; commit subjects and custom `Application.version` metadata are not
used for version comparison. Every imported ref is recorded in mutable
channel-root `luminus-imports.json`:

```json
{"schema_version":1,"refs":{"app/example.App/x86_64/stable":{"commit":"…","version":"1.2.3","source_run_id":"123","manifest_sha256":"…"}}}
```

Same ref and commit is an idempotent no-op. Same version with a different
commit and lower versions are rejected; higher versions may replace the ref.
The comparison uses the distribution semver ordering, where an `rc` sorts
before its final version. Rollback is not supported (T18). If a public ref
exists but is absent from the ledger, the safe bootstrap is to publish the
exact current commit once so the ledger can record it. A different commit is
rejected until that one-time same-commit bootstrap succeeds; operators must not
manually invent version history.

Publisher signs the staged repository, generates static deltas for changed
refs, then creates a detached signature for `luminus-imports.json` with the
channel signing subkey, and computes a PUT-only upload plan. Immutable objects/deltas are
uploaded first and checked at their exact public HTTPS URLs. Before mutable
metadata starts, the importer requires at least 120 seconds remain on the
credential expiry; this is a reserved bound for the small metadata phase. It
also checks expiry before each upload. If immutable work consumes the budget,
the run stops without writing mutable metadata. Immutable PUTs are
content-addressed and safe to repeat on re-dispatch with a fresh capsule.
Summary, summary signature, refs, AppStream metadata, config, imports ledger
and its detached signature are mutable data written last. Public checks then verify the mutable state before
the workflow emits its channel-specific `catalog-update.json` artifact.

R2 has no multi-object transaction. An upload or verification failure leaves
already uploaded immutable objects in place and never deletes them. A failure
during mutable writes can leave a temporary generation mismatch; inspect the
public summary/signature before re-dispatching. Per-channel Actions concurrency
prevents overlapping publishes. Publication does not update `main`; review the
catalog update artifact and make any registration/source changes separately.

## Run local checks

With Python 3.10+, Flatpak, OSTree, GnuPG and `requirements-dev.txt` available:

```sh
python3 -m venv /tmp/opencode/luminus-t07-venv
/tmp/opencode/luminus-t07-venv/bin/python -m pip install --only-binary=:all: -r requirements-dev.txt
/tmp/opencode/luminus-t07-venv/bin/python -B -m unittest discover -s tests -p 'test_*.py' -v
/tmp/opencode/luminus-t07-venv/bin/python -B -m unittest discover -s contracts -p 'test_*.py' -v
```

Integration tests create synthetic OSTree commits, Flatpak bundles and a
throwaway signing identity under `/tmp/opencode`. They never use production
subkeys or contact GitHub, R2 or the public domain.

## Limits

Offline tests establish local contract validation, merge behavior, signed
summary/ledger authentication with isolated GnuPG keys, ledger version rules,
expiry-budget gating, channel refs, upload ordering and summary signature
acceptance by a local Flatpak client. Authentication proves that the downloaded
summary and ledger were signed by the pinned channel key and that mirrored refs
match that summary. It does not prove that the origin/CDN served the newest
generation, prevent replay of an older valid signed generation, or authenticate
the network endpoint itself. Tests do not prove live R2 S3
compatibility, the GitHub release-asset redirect, production secrets, CDN
cache behavior, application runtime installation or aarch64 runtime
availability. Rollback/retention is T18. Never use channel-wide deletion or
`sync --delete` for recovery.
