#!/usr/bin/env python3
import argparse
import base64
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import trust

ROOT = Path(__file__).resolve().parents[1]
DESCRIPTOR_DIR = ROOT / "descriptors"
DOMAIN = "flatpak.luminusos.org"
HOMEPAGE = "https://luminusos.org"
RUNTIME_REPO = "https://dl.flathub.org/repo/flathub.flatpakrepo"
CHANNELS = ("stable", "testing")
APP_ID = re.compile(r"[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*){2,}\Z")
TITLES = {"dev.luminusos.ZapTide": "ZapTide", "org.luminusos.Aetheris": "Aetheris"}


class DescriptorError(Exception):
    pass


def _crc24(data):
    value = 0xB704CE
    for byte in data:
        value ^= byte << 16
        for _ in range(8):
            value <<= 1
            if value & 0x1000000:
                value ^= 0x1864CFB
    return value & 0xFFFFFF


def armor_to_binary(text):
    lines = text.replace("\r\n", "\n").split("\n")
    try:
        begin = lines.index("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        end = lines.index("-----END PGP PUBLIC KEY BLOCK-----")
    except ValueError as error:
        raise DescriptorError("public key is not an armored public key block") from error
    body = lines[begin + 1:end]
    try:
        body = body[body.index("") + 1:]
    except ValueError as error:
        raise DescriptorError("public key armor has no body") from error
    checksum = None
    if body and body[-1].startswith("="):
        checksum = body.pop()[1:]
    try:
        data = base64.b64decode("".join(body), validate=True)
        if checksum is not None and base64.b64decode(checksum, validate=True) != _crc24(data).to_bytes(3, "big"):
            raise DescriptorError("public key armor checksum does not match")
    except ValueError as error:
        raise DescriptorError("public key armor is invalid") from error
    if not data:
        raise DescriptorError("public key is empty")
    return data


def channel_key(channel, root=ROOT):
    if channel not in CHANNELS:
        raise DescriptorError("channel is not allowed")
    manifest = trust.load_manifest(root / "trust.json")
    if manifest["status"] != "provisioned":
        raise DescriptorError("channel trust is not provisioned")
    path = trust.resolve_key_path(root, manifest["channels"][channel]["public_key"])
    return base64.b64encode(armor_to_binary(path.read_text(encoding="utf-8"))).decode("ascii")


def remote_name(channel):
    return "luminus" if channel == "stable" else "luminus-" + channel


def flatpakrepo(channel, root=ROOT):
    return "\n".join([
        "[Flatpak Repo]",
        f"Title=Luminus OS ({channel})",
        f"Url=https://{DOMAIN}/{channel}/",
        f"Homepage={HOMEPAGE}",
        f"Comment=Applications from Luminus OS, {channel} channel",
        f"DefaultBranch={channel}",
        f"SuggestRemoteName={remote_name(channel)}",
        f"GPGKey={channel_key(channel, root)}",
        "",
    ])


def flatpakref(application, channel, root=ROOT):
    if not isinstance(application, str) or not APP_ID.fullmatch(application):
        raise DescriptorError("application ID is invalid")
    catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    if application not in {item["id"] for item in catalog["applications"]}:
        raise DescriptorError("application is not in the catalog")
    return "\n".join([
        "[Flatpak Ref]",
        "Title=" + TITLES.get(application, application) + ("" if channel == "stable" else f" ({channel})"),
        f"Name={application}",
        f"Branch={channel}",
        "IsRuntime=false",
        f"Url=https://{DOMAIN}/{channel}/",
        f"SuggestRemoteName={remote_name(channel)}",
        f"Homepage={HOMEPAGE}",
        f"RuntimeRepo={RUNTIME_REPO}",
        f"GPGKey={channel_key(channel, root)}",
        "",
    ])


def render_all(root=ROOT):
    catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    files = {}
    for channel in CHANNELS:
        files[f"{channel}/luminus-{channel}.flatpakrepo"] = flatpakrepo(channel, root)
        for item in catalog["applications"]:
            files[f"{channel}/{item['id']}.flatpakref"] = flatpakref(item["id"], channel, root)
    return files


def check(root=ROOT, directory=DESCRIPTOR_DIR):
    expected = render_all(root)
    present = {path.relative_to(directory).as_posix() for path in Path(directory).rglob("*") if path.is_file()}
    if present != set(expected):
        raise DescriptorError("descriptor files differ from the catalog")
    for name, content in expected.items():
        if (Path(directory) / name).read_text(encoding="utf-8") != content:
            raise DescriptorError("descriptor content differs from its source")
    return True


def write(root=ROOT, directory=DESCRIPTOR_DIR):
    for name, content in render_all(root).items():
        target = Path(directory) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Render or check Flatpak remote and ref descriptors")
    parser.add_argument("action", choices=("write", "check"))
    args = parser.parse_args(argv)
    try:
        if args.action == "write":
            write()
        else:
            check()
    except (DescriptorError, OSError, KeyError, ValueError):
        print("descriptor check failed", file=sys.stderr)
        return 1
    print(json.dumps({"status": "ok", "files": len(render_all())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
