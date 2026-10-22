# Signing trust

`trust.json` records this repository's public trust roots. It starts
`unprovisioned`; each provisioned channel names one certification-only primary
and one signing subkey. Keys are RSA 3072 and valid for one year. The verifier
caps key validity at 400 days to allow for date and export boundaries.

## Approved key ceremony

The project owner approved an agent-run ceremony for Flatpak and RPM stable and
testing. Each key has a certify-only RSA 3072 primary and one RSA 3072
signing-only subkey. The user ID is only the channel name, for example
`Luminus OS Flatpak Stable`.

The primary is created in tmpfs and protected by a random in-memory passphrase.
After exporting the public key, a revocation certificate, and the
passphrase-protected signing subkey, the primary is destroyed immediately. No
primary secret is retained or backed up, and it is not renewed; yearly rotation
creates a new identity.

The signing subkey and its passphrase belong in GitHub environment secrets
`SIGNING_SUBKEY` and `SIGNING_SUBKEY_PASSPHRASE` in the matching
`publisher-stable` or `publisher-testing` environment. The public fingerprints
are environment variables `SIGNING_PRIMARY_FINGERPRINT` and
`SIGNING_SUBKEY_FINGERPRINT`. Issuer environments do not receive signing keys.
Those protected GitHub environment secrets are the intended store. Private
keys and passphrases must not appear in chat, logs, command arguments, process
environment, repository files, or workflow artifacts.

Keep revocation certificates outside the repositories in an owner-only
directory. The machine used for the ceremony did not have encrypted disk and
swap was active, so key or passphrase pages could in principle have reached
swap. The signing-subkey passphrase equals the destroyed primary's passphrase;
GnuPG cannot assign different passphrases in this ceremony. Someone who
recovered the encrypted primary from swap and also obtained the GitHub secrets
could decrypt it. The primary existed for seconds; yearly re-keying limits the
exposure window but does not erase this residual risk.

The ceremony uploads with GitHub's create-or-replace secret command, which cannot
refuse an existing name. It therefore requires an exclusive-writer window: no other
administrator may change secrets, variables or deployment branch rules of the four
`publisher-*` environments while it runs. The script rechecks the branch rule and
the target names right before each upload and stops without writing if either
changed, but this check narrows the window and does not close it. If a run fails,
it removes exactly the names it created and restores the local trust files. When
something cannot be undone, it records manual cleanup in its ledger and keeps the
revocation certificates. A leftover ledger or private directory blocks the next
run until someone reviews it.

## Register and validate public trust

Place the public export at `trust/stable.gpg` or `trust/testing.gpg`, update the
channel's full uppercase fingerprints and path in `trust.json`, and set its
status to `provisioned`. Check a candidate before registering it:

```sh
python3 -B tools/trust.py verify-key --channel stable --file /path/to/stable.gpg --primary FULL_PRIMARY_FINGERPRINT --subkey FULL_SIGNING_SUBKEY_FINGERPRINT
```

Validate the registered keys and compare them with the other repository's two
primary and two signing-subkey fingerprints:

```sh
python3 -B tools/trust.py validate --other-fingerprints F1,F2,F3,F4
```

Run the local validation without cross-repository fingerprints with:

```sh
python3 -B tools/trust.py validate
```

The verifier uses a fresh, isolated GnuPG home. It checks the declared public
keys, capabilities, fingerprints, revocation and expiry. Its report contains
public metadata only.

## Rotation and revocation

Keys expire after one year. Create new identities and update `trust.json` each
year, or rotate immediately after a suspected leak using the stored revocation
certificate. Keep the previous trust bundle outside `trust.json` during an
overlap so existing consumers can switch; the schema holds one identity per
channel. Store each revocation certificate outside the repositories and tell
consumers to refresh their trust data. There is no automatic freshness
mechanism, and local validation does not prove consumers receive revocations.

This verifier checks the registry and public key files. It does not establish
how consumers apply trust or verify installed packages.
