# Using the Luminus Flatpak remotes

The descriptors under `descriptors/` are generated from `catalog.json` and the
pinned channel keys in `trust/`. Run `python3 tools/descriptors.py write` after
either changes; `python3 tools/descriptors.py check` and the test suite fail when
the files drift.

| Channel | Remote name | URL | Branch |
| --- | --- | --- | --- |
| stable | `luminus` | `https://flatpak.luminusos.org/stable/` | `stable` |
| testing | `luminus-testing` | `https://flatpak.luminusos.org/testing/` | `testing` |

Each `.flatpakrepo` carries the channel's public key, so Flatpak verifies the
signed summary and every commit of that channel only. The stable and testing keys
are different, and a remote that uses the wrong key is refused. Each
`.flatpakref` points at the channel's remote and at the Flathub runtime
repository, so runtimes are resolved from Flathub.

The catalog lists two applications, ZapTide and Aetheris, for `x86_64` and
`aarch64`. Both share one repository per channel, so one remote offers both and
publishing one application never removes the other.

## Add a remote

```sh
flatpak remote-add --user luminus-testing descriptors/testing/luminus-testing.flatpakrepo
flatpak remote-add --user luminus descriptors/stable/luminus-stable.flatpakrepo
```

## Install an application

```sh
flatpak install --user --from descriptors/stable/dev.luminusos.ZapTide.flatpakref
flatpak install --user --from descriptors/testing/org.luminusos.Aetheris.flatpakref
```

Once a remote is added you can also use its name, for example
`flatpak install --user luminus-testing org.luminusos.Aetheris//testing`.

## Move a bundle to a remote

An application installed from a GitHub release bundle keeps the origin it came
with, for example `aetheris-origin`. A plain install from the remote refuses with
"already installed from remote". Reinstall instead:

```sh
flatpak install --user --reinstall luminus-testing org.luminusos.Aetheris//testing
```

The application is removed and installed again from the remote. Your data under
`~/.var/app/<id>` is kept, because an uninstall only deletes it when you pass
`--delete-data`. Flatpak also drops the unused bundle origin. The bundle's branch
must exist on the remote you move to: a `stable` bundle moves to the `luminus`
remote, and a release candidate moves to `luminus-testing`.

## Switch channels

Each channel is its own branch, so both can be installed at the same time:

```sh
flatpak install --user luminus org.luminusos.Aetheris//stable
flatpak install --user luminus-testing org.luminusos.Aetheris//testing
flatpak run org.luminusos.Aetheris//stable
```

Both branches use the same data directory. To leave testing, install the stable
branch and uninstall the testing one. To return to testing, do the opposite:

```sh
# leave testing
flatpak install --user luminus org.luminusos.Aetheris//stable
flatpak uninstall --user org.luminusos.Aetheris//testing

# return to testing
flatpak install --user luminus-testing org.luminusos.Aetheris//testing
flatpak uninstall --user org.luminusos.Aetheris//stable
```

Installing the new branch first keeps the application available the whole time.

A newer testing build can write data that an older stable build does not read.
Nothing downgrades an application automatically; keep a copy of
`~/.var/app/<id>` before going back to stable.

## What has been checked

- The testing channel is live with both applications. A fresh profile lists
  both for `x86_64` and `aarch64`, and the AppStream data for each architecture
  contains both, with icons and release notes.
- Installing from the testing remote through the public domain verifies the
  signed commit and the application starts. The `aarch64` ref installs and its
  binary is an `aarch64` executable; it has not been run on `aarch64`.
- `tests/test_client_profile.py` runs the same Flatpak operations against a
  disposable profile and a local signed repository built from the catalog
  (the `.flatpakref` and `.flatpakrepo` files themselves are covered by
  `tests/test_descriptors.py`): both
  applications on both architectures, updating one application while the other
  stays untouched, moving a bundle to a remote with `--reinstall`, running
  both channels side by side, and refusing a remote with the wrong key.
- Flatpak cannot refresh AppStream data for a foreign architecture with
  `flatpak update --appstream --arch=...`. Flathub behaves the same way.
- The stable channel has no published application yet, so the stable commands
  are covered by the local repository test only.
- GNOME Software has not been exercised.
