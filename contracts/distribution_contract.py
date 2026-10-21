import copy
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator


VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?")
SCHEMA = json.loads(Path(__file__).with_name("distribution.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def _validate_shape(document, kind):
    error = next(VALIDATOR.iter_errors(document), None)
    if error is not None:
        raise ValueError(f"invalid {kind}: {error.message}")
    if document["kind"] != kind:
        raise ValueError(f"expected {kind} document")


def _version_key(version):
    match = VERSION.fullmatch(version) if isinstance(version, str) else None
    if match is None:
        raise ValueError("invalid normalized version")
    major, minor, patch, rc = match.groups()
    return int(major), int(minor), int(patch), rc is None, int(rc or 0)


def channel_for(version):
    return "stable" if _version_key(version)[3] else "testing"


def validate_release(release):
    _validate_shape(release, "release")
    normalized_tag = re.sub(r"-rc\.?([1-9][0-9]*)$", r"-rc.\1", release["source"]["tag"][1:])
    if normalized_tag != release["version"]:
        raise ValueError("release version and source tag disagree")
    artifacts = list(release["artifacts"].values())
    if len({artifact["artifact_id"] for artifact in artifacts}) != 2:
        raise ValueError("architectures must identify distinct build artifacts")
    return release


def release_digest(release):
    validate_release(release)
    canonical = json.dumps(release, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _checked_releases(releases):
    result = {}
    for release in releases:
        validate_release(release)
        key = release["format"], release["application"], release["version"]
        if key in result and result[key] != release:
            raise ValueError("conflicting releases for one identity")
        result[key] = release
    return list(result.values())


def select_testing(candidates, approved_stable=()):
    candidates = _checked_releases(candidates)
    approved = _checked_releases(approved_stable)
    all_releases = _checked_releases(candidates + approved)
    if len({release["application"] for release in all_releases}) > 1:
        raise ValueError("selection must target one application")
    if any(channel_for(release["version"]) != "stable" for release in approved):
        raise ValueError("stable approvals cannot contain rc releases")
    finals = [release for release in all_releases if channel_for(release["version"]) == "stable"]
    latest_final = max((_version_key(release["version"]) for release in finals), default=None)
    applicable = [release for release in candidates
                  if channel_for(release["version"]) == "testing"
                  and (latest_final is None or _version_key(release["version"]) > latest_final)]
    if applicable:
        chosen = max(applicable, key=lambda release: _version_key(release["version"]))
        fallback = "none"
    elif approved:
        chosen = max(approved, key=lambda release: _version_key(release["version"]))
        fallback = "stable-approved"
    else:
        raise ValueError("no applicable rc or approved stable fallback")
    return {"release": copy.deepcopy(chosen), "channel": "testing", "fallback": fallback}


def _identity(release, channel):
    return f'{release["format"]}:{channel}:{release["version"]}'


def _validate_catalog(catalog):
    if not isinstance(catalog, dict) or set(catalog) - {"releases"}:
        raise ValueError("invalid local catalog")
    releases = catalog.get("releases", {})
    if not isinstance(releases, dict):
        raise ValueError("invalid catalog releases")
    for application, entries in releases.items():
        if application not in SCHEMA["$defs"]["application"]["enum"] or not isinstance(entries, dict):
            raise ValueError("invalid catalog application")
        for identity, release in entries.items():
            validate_release(release)
            if application != release["application"]:
                raise ValueError("catalog application disagrees with release")
            allowed = [_identity(release, channel_for(release["version"]))]
            if channel_for(release["version"]) == "stable":
                allowed.append(_identity(release, "testing"))
            if identity not in allowed:
                raise ValueError("invalid catalog identity")


def merge_release(catalog, release, channel=None, approved_stable=()):
    _validate_catalog(catalog)
    validate_release(release)
    natural_channel = channel_for(release["version"])
    channel = natural_channel if channel is None else channel
    if channel not in ("stable", "testing") or (natural_channel == "testing" and channel == "stable"):
        raise ValueError("release cannot be published in requested channel")
    if natural_channel == "stable":
        approved = _checked_releases(approved_stable)
        if release not in approved or any(channel_for(item["version"]) != "stable" for item in approved):
            raise ValueError("final releases require the exact protected stable approval")
    result = copy.deepcopy(catalog)
    entries = result.setdefault("releases", {}).setdefault(release["application"], {})
    identity = _identity(release, channel)
    if identity in entries and entries[identity] != release:
        raise ValueError("release identity already exists with different content")
    entries[identity] = copy.deepcopy(release)
    return result


def validate_pins(document):
    _validate_shape(document, "image-pins")
    image = document["image"]
    identities = set()
    for pin in document["pins"]:
        identity = pin["format"], pin["application"]
        if identity in identities:
            raise ValueError("duplicate pin for application")
        identities.add(identity)
        natural_channel = channel_for(pin["version"])
        if natural_channel == "testing" and pin["channel"] == "stable":
            raise ValueError("rc cannot be pinned from stable")
        fallback = image["channel"] == "testing" and natural_channel == "stable"
        if pin["channel"] != image["channel"] and not fallback:
            raise ValueError("image and pin channels disagree")
        if pin["fallback"] != ("stable-approved" if fallback else "none"):
            raise ValueError("fallback must be recorded explicitly and consistently")
        url = urlsplit(pin["url"])
        if url.netloc != f'{pin["format"]}.luminusos.org' or url.query or url.fragment:
            raise ValueError("pin must use its approved public origin")
        segments = url.path.split("/")[1:]
        if any(segment in ("", ".", "..") for segment in segments):
            raise ValueError("pin URL contains unsafe path segments")
        if pin["format"] == "rpm":
            prefix = [pin["channel"], "45", image["architecture"]]
            if segments[:3] != prefix or len(segments) < 4 or not segments[-1].endswith(".rpm"):
                raise ValueError("RPM URL disagrees with channel, Fedora or architecture")
            if pin["rpm"]["version"] != pin["version"].replace("-rc.", "~rc."):
                raise ValueError("RPM and normalized versions disagree")
        else:
            flatpak = pin["flatpak"]
            expected_ref = f'app/{pin["application"]}/{image["architecture"]}/{pin["channel"]}'
            commit = flatpak["commit"]
            expected_path = f'/{pin["channel"]}/objects/{commit[:2]}/{commit[2:]}.commit'
            if flatpak["ref"] != expected_ref or url.path != expected_path:
                raise ValueError("Flatpak ref or object URL disagrees with pin")
    return document
