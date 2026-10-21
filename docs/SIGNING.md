# Signing keys

This repository's signing policy is in `signing-policy.json`. Its format and
channels are fixed here, while production trust remains `unprovisioned`. No
production fingerprints or public keys have been registered. This local guide
does not configure GitHub environments, secrets, or repository protections.

## Local checks

From the repository root, run:

```sh
python3 -B tools/signing.py validate
python3 -B tools/signing.py rehearse
/tmp/opencode/luminus-contract-venv/bin/python -B -m unittest discover -s tests -p 'test_*.py' -v
```

`validate` checks the closed policy. `rehearse` creates four independent,
disposable GnuPG identities under `/tmp/opencode`, one for each format and
channel. It checks signing-subkey use, isolated public verification, CI export
contents, tampering, and revocation. It does not use the user's keyring or make
network requests. Temporary fixture material is removed when the command ends.
Fixture keys have no passphrase so the test can run unattended. This exception
applies only to disposable keys created by `rehearse`.

The revocation check imports a fixture certificate into an isolated public
keyring and checks that an earlier valid fixture signature then fails. This
records behavior in that test. It does not prove that future production
consumers will receive fresh revocation information.

## Production key ceremony

Do not run the following steps until T06a has been independently reviewed and
the user has approved the ceremony. Choose the final user ID and key expiration
at that time. Use a new private home outside the checkout for each format and
channel. Never send a passphrase through chat, a command argument, or an
environment variable. Enter it only through GnuPG's interactive PINENTRY
prompt. Do not enable loopback pinentry for production keys.

For example, set a private path and user ID chosen by the key custodian, then
create a certification-only primary key and one signing-only subkey. The sample
algorithm follows the current RSA 3072/SHA-256 proposal; the key custodian must
choose the expiry and identity values.

```sh
umask 077
export KEY_HOME="$HOME/.local/private/luminus-flatpak-stable"
install -d -m 700 "$KEY_HOME"
export KEY_UID='USER-CHOSEN NAME <USER-CHOSEN ADDRESS>'
gpg --homedir "$KEY_HOME" --no-options --quick-generate-key "$KEY_UID" rsa3072 cert 1y
gpg --homedir "$KEY_HOME" --no-options --with-colons --fingerprint --list-keys
```

Read the full primary fingerprint from the `fpr` record, then add the signing
subkey. Replace the placeholder with that full fingerprint; do not use a short
key ID or a UID as a key selector.

```sh
export PRIMARY_FPR='FULL_PRIMARY_FINGERPRINT_FROM_GPG'
gpg --homedir "$KEY_HOME" --no-options --quick-add-key "$PRIMARY_FPR" rsa3072 sign 1y
gpg --homedir "$KEY_HOME" --no-options --with-colons --fingerprint --fingerprint --list-keys
```

Keep the primary private key and its backup under the custodian's control.
Create an encrypted offline backup, store the revocation certificate separately
and securely, then verify restoration into a new offline test home. Confirm that
the restored primary is a real secret key and can certify a test key there. Never
restore the primary private key into CI. Keep T02 credentials out of this
ceremony.

Only after backup and restore checks, export the public key and the selected
signing subkey for review. The export command contains fingerprints and output
paths only; PINENTRY handles the passphrase.

```sh
export SIGNING_FPR='FULL_SIGNING_SUBKEY_FINGERPRINT_FROM_GPG'
gpg --homedir "$KEY_HOME" --no-options --output flatpak-stable-public.gpg --export "$PRIMARY_FPR"
gpg --homedir "$KEY_HOME" --no-options --output flatpak-stable-subkey.gpg \
  --export-secret-subkeys "${SIGNING_FPR}!"
gpg --homedir "$KEY_HOME" --no-options --digest-algo SHA256 \
  --local-user "${SIGNING_FPR}!" --detach-sign --output release.sig release-artifact
```

These are examples for the custodian to perform later, not commands run by this
local helper. Do not send private exports or passphrases in chat. Delivery to CI
requires separate approval and a protected-environment design. The helper's
subkey-export test uses disposable fixtures only; it does not establish
production CI access controls. A real consumer must also obtain updated
revocation data and reject revoked or expired keys.

Testing keys follow the same process in a separate home and use their own
identity. Stable and testing must not share signing keys. Production key
generation, secret transport, GitHub configuration, and publication remain
outside T06a.
