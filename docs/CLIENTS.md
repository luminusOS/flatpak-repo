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
signed summary of that channel only. The stable and testing keys are different.
Each `.flatpakref` points at the channel's remote and at the Flathub runtime
repository, so runtimes are resolved from Flathub.

## Add a remote

```sh
flatpak remote-add --user luminus-testing descriptors/testing/luminus-testing.flatpakrepo
flatpak remote-add --user luminus descriptors/stable/luminus-stable.flatpakrepo
```

## Install an application

```sh
flatpak install --user --from descriptors/stable/dev.luminusos.ZapTide.flatpakref
flatpak install --user --from descriptors/testing/dev.luminusos.ZapTide.flatpakref
```

A bundle installed earlier from GitHub Releases keeps its own origin. To move
to a remote, install from the remote explicitly and uninstall the bundle
afterwards; user data under `~/.var/app/<id>` is not removed by an uninstall
unless you ask for it.

## What has been checked

The descriptors are accepted by the installed `flatpak` command, which stores
exactly the pinned primary key and signing subkey of the channel. A published
repository, an installation through the public domain, updates and GNOME
Software have not been exercised yet, and no application has been published.
