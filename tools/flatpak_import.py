#!/usr/bin/env python3

import argparse
import configparser
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ElementTree
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contracts import distribution_contract
import issuer
import r2_probe
import trust
from publish_plan import ImportError as PublishError, build_upload_plan, is_mutable_key, publish_uploads


CHANNELS = ("stable", "testing")
ARCHITECTURES = ("x86_64", "aarch64")
CHECKSUMS_NAME = "checksums.txt"
MAX_CHECKSUMS_BYTES = 64 * 1024
ARTIFACT_NAME = "flatpak-{arch}"
MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
DOWNLOAD_TIMEOUT = 30
PUBLIC_VERIFY_TIMEOUT = 120
USER_AGENT = "luminus-flatpak-publisher/1"
REDIRECT_ASSET_HOSTS = {"objects.githubusercontent.com", "release-assets.githubusercontent.com"}
ALLOWED_ASSET_HOSTS = {"github.com"} | REDIRECT_ASSET_HOSTS
TAG_PATTERN = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.?[1-9][0-9]*)?\Z")
APP_ID_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*){2,}\Z")
IMPORTS_LEDGER = "luminus-imports.json"
SUMMARY_DETACHED_SIGNATURE = "summary.detached.sig"
MUTABLE_PHASE_BUDGET_SECONDS = 120
MAX_LIST_PAGES = 2000


class ImporterError(Exception):
    pass


@dataclass(frozen=True)
class FetchPlan:
    repository: str
    tag: str
    checksums_url: str
    asset_urls: dict


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def validate_descriptor(descriptor):
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "format", "channel", "package_id", "version", "tag", "git_sha", "source_run_id",
        "source_run_attempt",
    }:
        raise ImporterError("release descriptor is invalid")
    try:
        basic = {key: value for key, value in descriptor.items() if key != "tag"}
        issuer.validate_descriptor(basic, issuer.FORMAT, descriptor["channel"])
    except (issuer.IssuerError, KeyError, TypeError) as error:
        raise ImporterError("release descriptor is invalid") from error
    tag = descriptor["tag"]
    if not isinstance(tag, str) or not TAG_PATTERN.fullmatch(tag):
        raise ImporterError("release tag is invalid")
    normalized = re.sub(r"-rc\.?([1-9][0-9]*)$", r"-rc.\1", tag[1:])
    if normalized != descriptor["version"]:
        raise ImporterError("release tag and version disagree")
    return {**descriptor, "git_sha": descriptor["git_sha"].lower()}


def fetch_plan(descriptor):
    checked = validate_descriptor(descriptor)
    repository = issuer.SOURCE_RELEASES[checked["package_id"]][0]
    slug = repository.rsplit("/", 1)[1]
    base = f"https://github.com/{repository}/releases/download/{checked['tag']}"
    return FetchPlan(
        repository, checked["tag"], f"{base}/{CHECKSUMS_NAME}",
        {arch: f"{base}/{slug}-{checked['tag']}-{arch}.flatpak" for arch in ARCHITECTURES},
    )


def validate_manifest(manifest, descriptor):
    checked = validate_descriptor(descriptor)
    try:
        distribution_contract.validate_release(manifest)
    except (ValueError, KeyError, TypeError) as error:
        raise ImporterError("release manifest is invalid") from error
    source = manifest["source"]
    expected_repo = issuer.SOURCE_RELEASES[checked["package_id"]][0]
    expected_workflow = issuer.SOURCE_RELEASES[checked["package_id"]][2]
    if (manifest["format"] != "flatpak" or manifest["application"] != checked["package_id"]
            or manifest["version"] != checked["version"]
            or source["repository"] != expected_repo or source["workflow"] != expected_workflow
            or source["tag"] != checked["tag"] or source["revision"] != checked["git_sha"]
            or str(source["run_id"]) != checked["source_run_id"]
            or source["run_attempt"] != checked["source_run_attempt"]):
        raise ImporterError("manifest provenance does not match the release descriptor")
    validate_rc_channel(checked)
    plan = fetch_plan(checked)
    for arch in ARCHITECTURES:
        artifact = manifest["artifacts"][arch]
        expected_filename = urlsplit(plan.asset_urls[arch]).path.rsplit("/", 1)[1]
        if artifact["filename"] != expected_filename or artifact["size_bytes"] > MAX_BUNDLE_BYTES:
            raise ImporterError("manifest artifact name or size is invalid")
    if len({item["filename"] for item in manifest["artifacts"].values()}) != 2:
        raise ImporterError("architecture artifacts must have distinct filenames")
    return manifest


def validate_rc_channel(descriptor):
    if "-rc." in descriptor.get("version", "") and descriptor.get("channel") != "testing":
        raise ImporterError("pre-release versions are testing-only")


def verify_tmpfs(path):
    home = Path(path)
    try:
        filesystem = subprocess.run(["stat", "-f", "-c", "%T", str(home)], check=True,
                                    capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ImporterError("GnuPG home filesystem could not be verified") from error
    if filesystem != "tmpfs":
        raise ImporterError("GnuPG home must reside on tmpfs")
    if home.exists() and home.stat().st_mode & 0o077:
        raise ImporterError("GnuPG home permissions are too broad")
    return home


_CHECKSUM_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,199})\Z")


def parse_checksums(content):
    try:
        lines = content.decode("utf-8", "strict").split("\n")
    except UnicodeError as error:
        raise ImporterError("release checksums are invalid") from error
    if lines and lines[-1] == "":
        lines.pop()
    result = {}
    for line in lines:
        match = _CHECKSUM_LINE.fullmatch(line)
        if not match or match.group(2) in result:
            raise ImporterError("release checksums are invalid")
        result[match.group(2)] = match.group(1)
    if not result:
        raise ImporterError("release checksums are invalid")
    return result


def list_flatpak_artifacts(repository, run_id, fetcher=None):
    listing = (fetcher or issuer.fetch_github_json)(f"/repos/{repository}/actions/runs/{run_id}/artifacts")
    entries = listing.get("artifacts") if isinstance(listing, dict) else None
    if not isinstance(entries, list):
        raise ImporterError("source run artifact listing is invalid")
    found = {}
    for arch in ARCHITECTURES:
        name = ARTIFACT_NAME.format(arch=arch)
        matches = [item for item in entries if isinstance(item, dict) and item.get("name") == name
                   and item.get("expired") is False]
        if len(matches) != 1 or type(matches[0].get("id")) is not int or matches[0]["id"] < 1:
            raise ImporterError("source run does not list exactly one bundle artifact per architecture")
        found[arch] = matches[0]["id"]
    if len(set(found.values())) != len(found):
        raise ImporterError("source run artifact identifiers are not distinct")
    return found


def build_manifest(descriptor, bundles, artifact_ids):
    checked = validate_descriptor(descriptor)
    repository, _caller, contract_workflow, _ = issuer.SOURCE_RELEASES[checked["package_id"]]
    return {
        "schema_version": 1, "kind": "release", "format": "flatpak", "application": checked["package_id"],
        "version": checked["version"],
        "source": {"repository": repository, "workflow": contract_workflow, "tag": checked["tag"],
                   "revision": checked["git_sha"], "run_id": int(checked["source_run_id"]),
                   "run_attempt": checked["source_run_attempt"]},
        "artifacts": {arch: {"artifact_id": artifact_ids[arch], "filename": bundles[arch]["filename"],
                             "sha256": bundles[arch]["sha256"], "size_bytes": len(bundles[arch]["data"])}
                      for arch in ARCHITECTURES},
    }


def verify_artifact(content, artifact):
    if not isinstance(content, bytes) or len(content) != artifact["size_bytes"]:
        raise ImporterError("release artifact size does not match manifest")
    if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), artifact["sha256"]):
        raise ImporterError("release artifact checksum does not match manifest")
    return content


def _read_limited(response, limit):
    length = response.headers.get("Content-Length")
    if length is not None and (not length.isdigit() or int(length) > limit):
        raise ImporterError("release asset exceeds size limit")
    data = response.read(limit + 1)
    if len(data) > limit:
        raise ImporterError("release asset exceeds size limit")
    return data


def download_asset(url, *, limit, opener=None):
    original = urlsplit(url)
    if original.scheme != "https" or original.hostname != "github.com" or original.username or original.password:
        raise ImporterError("release asset URL is outside the fixed host allowlist")
    client = opener or build_opener(_NoRedirect())
    try:
        response = client.open(Request(url, method="GET"), timeout=DOWNLOAD_TIMEOUT)
    except HTTPError as error:
        if error.code not in (301, 302, 303, 307, 308):
            error.close()
            raise ImporterError("release asset download failed") from None
        location = error.headers.get("Location", "")
        error.close()
        target = urlsplit(location)
        if (original.hostname != "github.com" or target.scheme != "https"
                or target.hostname not in REDIRECT_ASSET_HOSTS or target.username
                or target.password or target.port not in (None, 443)):
            raise ImporterError("release asset redirect is not allowed") from None
        try:
            response = client.open(Request(location, method="GET"), timeout=DOWNLOAD_TIMEOUT)
        except (HTTPError, URLError, OSError, TimeoutError) as nested:
            raise ImporterError("release asset download failed") from nested
    except (URLError, OSError, TimeoutError) as error:
        raise ImporterError("release asset download failed") from error
    try:
        final_url = urlsplit(response.geturl())
        if (getattr(response, "status", 200) != 200 or final_url.scheme != "https"
                or final_url.hostname not in ALLOWED_ASSET_HOSTS or final_url.username
                or final_url.password or final_url.port not in (None, 443)):
            raise ImporterError("release asset download failed")
        return _read_limited(response, limit)
    finally:
        response.close()


def _command_name(command):
    words = [Path(str(command[0])).name] if command else []
    for word in command[1:3]:
        if re.fullmatch(r"[a-z][a-z-]*", str(word)):
            words.append(str(word))
    return " ".join(words)


def _run(command, *, timeout=120):
    try:
        result = subprocess.run(command, capture_output=True, check=False, timeout=timeout,
                                env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        failure = ImporterError("Flatpak repository inspection failed")
        failure.detail = _command_name(command)
        raise failure from error
    if result.returncode:
        failure = ImporterError("Flatpak repository inspection failed")
        failure.detail = _command_name(command)
        raise failure
    return result.stdout


def _repo_refs(repo):
    output = _run(["ostree", "refs", "--repo", str(repo), "--list"])
    return {line.decode("utf-8", "strict") for line in output.splitlines() if line}


def _commit_metadata(repo, ref):
    checksum = _run(["ostree", "rev-parse", "--repo", str(repo), ref]).decode().strip()
    raw = _run(["ostree", "cat", "--repo", str(repo), checksum, "metadata"])
    metadata = configparser.ConfigParser()
    try:
        metadata.read_string(raw.decode("utf-8", "strict"))
    except (UnicodeError, configparser.Error) as error:
        raise ImporterError("bundle application metadata is invalid") from error
    return checksum, metadata


BASE_AUTH_DIR = "base-auth"
BASE_AUTH_FILES = ("summary", "summary.sig", SUMMARY_DETACHED_SIGNATURE, IMPORTS_LEDGER,
                   IMPORTS_LEDGER + ".sig")
EMPTY_BASE_MARKER = "EMPTY"
STAGED_TOP_LEVEL = {".lock", "delta-indexes", "config", "objects", "refs", "state", "tmp", "extensions", "deltas", "appstream",
                    "summary", "summary.sig", SUMMARY_DETACHED_SIGNATURE, "summary.idx",
                    "summary.idx.sig", "summaries", IMPORTS_LEDGER, IMPORTS_LEDGER + ".sig", "repo"}


def _verify_signed_metadata(directory, channel, root):
    directory = Path(directory)
    summary = directory / "summary"
    ledger = directory / IMPORTS_LEDGER
    ledger_signature = directory / (IMPORTS_LEDGER + ".sig")
    if not (directory / "summary.sig").is_file() or not (directory / SUMMARY_DETACHED_SIGNATURE).is_file():
        raise ImporterError("channel summary signature is missing")
    try:
        manifest = trust.load_manifest(root / "trust.json")
        if manifest["status"] != "provisioned":
            raise ValueError("channel trust is not provisioned")
        identity = manifest["channels"][channel]
        public_key = trust.resolve_key_path(root, identity["public_key"])
        if not trust.verify_signature(public_key, directory / SUMMARY_DETACHED_SIGNATURE, summary,
                                      identity["primary_fingerprint"],
                                      identity["signing_subkey_fingerprint"]):
            raise ValueError("channel summary signature is invalid")
        if ledger.exists():
            if not ledger_signature.is_file():
                raise ValueError("channel imports ledger signature is missing")
            if not trust.verify_signature(public_key, ledger_signature, ledger,
                                          identity["primary_fingerprint"],
                                          identity["signing_subkey_fingerprint"]):
                raise ValueError("channel imports ledger signature is invalid")
            _load_imports_ledger(directory)
        elif ledger_signature.exists():
            raise ValueError("imports ledger signature has no ledger")
    except (OSError, KeyError, TypeError, ValueError, RuntimeError) as error:
        raise ImporterError("channel repository authentication failed") from error
    return identity


def _verified_summary_refs(repo, identity):
    try:
        view = _run(["ostree", "summary", "--repo", str(repo), "--view"]).decode("utf-8", "strict")
    except (UnicodeError, ImporterError) as error:
        raise ImporterError("verified channel summary cannot be read") from error
    summary_refs = {}
    lines = view.splitlines()
    for index, line in enumerate(lines):
        match = re.fullmatch(r"\* (.+)", line.strip())
        if match:
            ref = match.group(1)
            checksum = None
            for candidate in lines[index + 1:]:
                if candidate.startswith("*"):
                    break
                found = re.fullmatch(r"\s+([a-f0-9]{64})", candidate)
                if found:
                    checksum = found.group(1)
                    break
            if checksum is None or ref in summary_refs:
                raise ImporterError("verified channel summary refs are invalid")
            summary_refs[ref] = checksum
    return summary_refs


def verify_mirrored_repo(repo, channel, *, trust_root=None, allow_empty=False):
    if channel not in CHANNELS:
        raise ImporterError("repository channel is invalid")
    repo = Path(repo)
    root = Path(trust_root) if trust_root is not None else Path(__file__).resolve().parents[1]
    summary = repo / "summary"
    local_refs = _repo_refs(repo)
    if not summary.exists():
        if allow_empty and not (repo / "summary.sig").exists() and not (repo / IMPORTS_LEDGER).exists() \
                and not (repo / (IMPORTS_LEDGER + ".sig")).exists() and not local_refs:
            return True
        raise ImporterError("channel summary is missing")
    identity = _verify_signed_metadata(repo, channel, root)
    summary_refs = _verified_summary_refs(repo, identity)
    if set(summary_refs) != local_refs:
        raise ImporterError("mirrored repository refs do not match its verified summary")
    for ref, checksum in summary_refs.items():
        try:
            local = _run(["ostree", "rev-parse", "--repo", str(repo), ref]).decode().strip()
        except ImporterError as error:
            raise ImporterError("verified summary ref is missing from mirror") from error
        if local != checksum:
            raise ImporterError("mirrored repository ref differs from its verified summary")
    return True


def snapshot_base_auth(repo, destination):
    repo, destination = Path(repo), Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if not (repo / "summary").exists():
        (destination / EMPTY_BASE_MARKER).write_bytes(b"")
        return
    for name in BASE_AUTH_FILES:
        if (repo / name).is_file():
            (destination / name).write_bytes((repo / name).read_bytes())


def public_request(url):
    return Request(url, method="GET", headers={"User-Agent": USER_AGENT})


def _public_status(url):
    try:
        with build_opener(_NoRedirect()).open(public_request(url), timeout=DOWNLOAD_TIMEOUT) as response:
            return response.status
    except HTTPError as error:
        error.close()
        return error.code
    except (OSError, TimeoutError, URLError) as error:
        raise ImporterError("public repository state cannot be read") from error


def verify_public_empty(channel):
    base = f"https://flatpak.luminusos.org/{channel}/"
    return _public_status(base + "summary") == 404 and _public_status(base + "refs/") == 404


def _version_rules(base_refs, base_ledger, inspected, descriptor):
    for item in inspected:
        if item["no_op"] or item["ref"] not in base_refs:
            continue
        entry = base_ledger.get(item["ref"])
        if entry is None:
            raise ImporterError("existing ref is missing from import ledger; bootstrap required")
        try:
            current_key = distribution_contract._version_key(entry["version"])
            target_key = distribution_contract._version_key(descriptor["version"])
        except ValueError as error:
            raise ImporterError("import ledger contains an unrecognized application version") from error
        if current_key >= target_key:
            raise ImporterError("application version is not newer than the current ref")


REPO_SKELETON = ("objects", "refs/heads", "refs/remotes", "refs/mirrors", "tmp", "state", "extensions")


def restore_repo_skeleton(repo):
    repo = Path(repo)
    if not repo.is_dir() or repo.is_symlink():
        raise ImporterError("staged repository is missing")
    for name in REPO_SKELETON:
        target = repo / name
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            raise ImporterError("staged repository layout is invalid")
        target.mkdir(parents=True, exist_ok=True)


def verify_stage(repo, work_dir, descriptor, bundle_paths, *, trust_root=None, public_empty=None):
    restore_repo_skeleton(repo)
    channel = descriptor.get("channel")
    if channel not in CHANNELS or set(bundle_paths) != set(ARCHITECTURES):
        raise ImporterError("staged repository inputs are invalid")
    root = Path(trust_root) if trust_root is not None else Path(__file__).resolve().parents[1]
    base = Path(work_dir) / BASE_AUTH_DIR
    if not base.is_dir():
        raise ImporterError("authenticated base record is missing")
    names = {path.name for path in base.iterdir()}
    with tempfile.TemporaryDirectory(prefix="flatpak-verify-", dir="/tmp/opencode") as scratch:
        scratch = Path(scratch)
        if EMPTY_BASE_MARKER in names:
            if names != {EMPTY_BASE_MARKER} or not (public_empty or verify_public_empty)(channel):
                raise ImporterError("empty base claim is not confirmed by the public repository")
            base_refs, base_ledger = {}, {}
        else:
            if not names <= set(BASE_AUTH_FILES) or "summary" not in names:
                raise ImporterError("authenticated base record is invalid")
            identity = _verify_signed_metadata(base, channel, root)
            summary_repo = scratch / "base-summary"
            _run(["ostree", "init", "--repo", str(summary_repo), "--mode", "archive-z2"])
            for name in ("summary", "summary.sig"):
                (summary_repo / name).write_bytes((base / name).read_bytes())
            base_refs = _verified_summary_refs(summary_repo, identity)
            base_ledger = _load_imports_ledger(base)
        inspected = []
        for arch in ARCHITECTURES:
            item = inspect_bundle(bundle_paths[arch], app_id=descriptor["package_id"], architecture=arch,
                                  channel=channel, version=descriptor["version"],
                                  work_dir=scratch / arch)
            item.pop("repo", None)
            item["architecture"] = arch
            item["no_op"] = base_refs.get(item["ref"]) == item["commit"]
            inspected.append(item)
        _version_rules(base_refs, base_ledger, inspected, descriptor)
        expected_refs = dict(base_refs)
        expected_refs.update({item["ref"]: item["commit"] for item in inspected})
        staged_refs = {ref: _run(["ostree", "rev-parse", "--repo", str(repo), ref]).decode().strip()
                       for ref in _repo_refs(repo)}
        if staged_refs != expected_refs:
            raise ImporterError("staged repository refs differ from the authenticated base and verified bundles")
        if _load_imports_ledger(repo) != _updated_ledger(base_ledger, inspected, descriptor):
            raise ImporterError("staged import ledger differs from the authenticated base and verified bundles")
        _verify_repo_config(repo)
        unexpected = {path.name for path in Path(repo).iterdir()} - STAGED_TOP_LEVEL
        if unexpected:
            raise ImporterError("staged repository contains unexpected top-level entries")
        _run(["ostree", "fsck", "--repo", str(repo), "--quiet"], timeout=900)
    return inspected


def _verify_repo_config(repo):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string((Path(repo) / "config").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, configparser.Error) as error:
        raise ImporterError("staged repository config is invalid") from error
    if set(parser.sections()) != {"core"} or parser["core"].get("mode") != "archive-z2" \
            or parser["core"].get("repo_version") != "1" or set(parser["core"]) - {"repo_version", "mode", "indexed-deltas"} \
            or parser["core"].get("indexed-deltas", "true") != "true":
        raise ImporterError("staged repository config is not the plain archive configuration")


def _updated_ledger(ledger, inspected, checked):
    updated = dict(ledger)
    digest = _manifest_digest(checked)
    for item in inspected:
        if item["ref"] not in updated or not item.get("no_op"):
            updated[item["ref"]] = {"commit": item["commit"], "version": checked["version"],
                                    "source_run_id": str(checked.get("source_run_id", "unknown")),
                                    "manifest_sha256": digest}
    return updated


def _validate_tree_paths(repo, checksum):
    output = _run(["ostree", "ls", "--repo", str(repo), "--recursive", "--nul-filenames-only", checksum])
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        try:
            decoded = raw_path.decode("utf-8", "strict")
            if not decoded.startswith("/") or decoded.startswith("//"):
                raise ImporterError("bundle contains an unsafe path")
            path = PurePosixPath(decoded.lstrip("/"))
        except UnicodeError as error:
            raise ImporterError("bundle contains an invalid path") from error
        if any(part in ("", ".", "..") for part in path.parts):
            raise ImporterError("bundle contains an unsafe path")


def inspect_bundle(bundle, *, app_id, architecture, channel, version, work_dir=None):
    if architecture not in ARCHITECTURES or channel not in CHANNELS:
        raise ImporterError("bundle target is invalid")
    bundle_path = Path(bundle)
    if not bundle_path.is_file() or bundle_path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ImporterError("bundle is missing or exceeds size limit")
    base = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="flatpak-inspect-", dir="/tmp/opencode"))
    base.mkdir(parents=True, exist_ok=True)
    repo = base / "repo"
    _run(["ostree", "init", "--repo", str(repo), "--mode", "archive-z2"])
    _run(["flatpak", "build-import-bundle", "--no-update-summary", str(repo), str(bundle_path)])
    refs = _repo_refs(repo)
    expected_ref = f"app/{app_id}/{architecture}/{channel}"
    if refs != {expected_ref}:
        raise ImporterError("bundle contains unexpected or missing refs")
    checksum, metadata = _commit_metadata(repo, expected_ref)
    _validate_tree_paths(repo, checksum)
    if not metadata.has_section("Application") or metadata.get("Application", "name", fallback="") != app_id:
        raise ImporterError("bundle application ID does not match descriptor")
    runtime = metadata.get("Application", "runtime", fallback="")
    runtime_parts = runtime.split("/")
    if len(runtime_parts) != 3 or not all(runtime_parts) or runtime_parts[1] != architecture:
        raise ImporterError("bundle runtime metadata is missing")
    return {"ref": expected_ref, "commit": checksum, "runtime": runtime,
            "version": version, "repo": repo}


def _load_imports_ledger(repo):
    path = Path(repo) / IMPORTS_LEDGER
    if not path.exists():
        return {}
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ImporterError("import ledger is invalid") from error
    if not isinstance(ledger, dict) or set(ledger) != {"schema_version", "refs"} or ledger["schema_version"] != 1 or not isinstance(ledger["refs"], dict):
        raise ImporterError("import ledger is invalid")
    for ref, entry in ledger["refs"].items():
        if (not isinstance(ref, str) or not isinstance(entry, dict)
                or set(entry) != {"commit", "version", "source_run_id", "manifest_sha256"}
                or not re.fullmatch(r"[a-f0-9]{64}", entry["commit"])
                or not isinstance(entry["version"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", entry["manifest_sha256"])):
            raise ImporterError("import ledger is invalid")
    return ledger["refs"]


def _manifest_digest(descriptor):
    supplied = descriptor.get("manifest_sha256")
    if supplied is not None:
        if not isinstance(supplied, str) or not re.fullmatch(r"[a-f0-9]{64}", supplied):
            raise ImporterError("release manifest digest is invalid")
        return supplied
    canonical = json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def check_existing_version(repo, inspected, descriptor):
    existing_refs = _repo_refs(repo)
    ledger = _load_imports_ledger(repo)
    for item in inspected:
        entry = ledger.get(item["ref"])
        exists = item["ref"] in existing_refs
        if not exists:
            continue
        current, _metadata = _commit_metadata(repo, item["ref"])
        if current == item["commit"]:
            item["no_op"] = True
        elif entry is None:
            raise ImporterError("existing ref is missing from import ledger; bootstrap required")
        else:
            try:
                current_key = distribution_contract._version_key(entry["version"])
                target_key = distribution_contract._version_key(descriptor["version"])
            except ValueError as error:
                raise ImporterError("import ledger contains an unrecognized application version") from error
            if current_key > target_key:
                raise ImporterError("older application version cannot replace the current ref")
            if current_key == target_key:
                raise ImporterError("same application version already has different content")
            item["no_op"] = False
    return inspected


def merge_bundles(repo, bundles, descriptor, *, gpg_home=None, signing_fingerprint=None, sign=True):
    if (not isinstance(descriptor, dict) or descriptor.get("format") != "flatpak"
            or descriptor.get("channel") not in CHANNELS
            or not isinstance(descriptor.get("package_id"), str)
            or not APP_ID_PATTERN.fullmatch(descriptor["package_id"])
            or not isinstance(descriptor.get("version"), str)
            or not distribution_contract.VERSION.fullmatch(descriptor["version"])):
        raise ImporterError("bundle import target is invalid")
    checked = descriptor
    validate_rc_channel(checked)
    if sign and not re.fullmatch(r"[A-F0-9]{40,64}", signing_fingerprint or ""):
        raise ImporterError("channel signing fingerprint is invalid")
    if not isinstance(bundles, dict) or set(bundles) != set(ARCHITECTURES):
        raise ImporterError("both architecture bundles are required")
    inspected = []
    with tempfile.TemporaryDirectory(prefix="flatpak-stage-", dir="/tmp/opencode") as staging:
        for arch in ARCHITECTURES:
            item = inspect_bundle(bundles[arch], app_id=checked["package_id"],
                                  architecture=arch, channel=checked["channel"],
                                  version=checked["version"], work_dir=Path(staging) / arch)
            item.pop("repo", None)
            inspected.append(item)
        check_existing_version(repo, inspected, checked)
        changed = [item for item in inspected if not item.get("no_op")]
        for arch, item in zip(ARCHITECTURES, inspected):
            if item.get("no_op"):
                continue
            _run(["flatpak", "build-import-bundle", "--no-update-summary", str(repo), str(bundles[arch])])
        if changed and sign:
            verify_tmpfs(gpg_home)
            _run(["flatpak", "build-update-repo", "--gpg-sign=" + signing_fingerprint + "!",
                  "--gpg-homedir=" + str(gpg_home), str(repo)], timeout=600)
            _run(["ostree", "summary", "--repo", str(repo), "--update", "--gpg-sign",
                  signing_fingerprint + "!", "--gpg-homedir", str(gpg_home)], timeout=600)
        original_ledger = _load_imports_ledger(repo)
        ledger = _updated_ledger(original_ledger, inspected, checked)
        if ledger != original_ledger:
            (Path(repo) / IMPORTS_LEDGER).write_text(
                json.dumps({"schema_version": 1, "refs": dict(sorted(ledger.items()))},
                           sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return inspected


def fetch_release(descriptor, work_dir, *, artifact_lister=None):
    plan = fetch_plan(descriptor)
    checksums = parse_checksums(download_asset(plan.checksums_url, limit=MAX_CHECKSUMS_BYTES))
    bundles = {}
    for arch, url in plan.asset_urls.items():
        filename = urlsplit(url).path.rsplit("/", 1)[1]
        data = download_asset(url, limit=MAX_BUNDLE_BYTES)
        digest = hashlib.sha256(data).hexdigest()
        if filename not in checksums or not hmac.compare_digest(digest, checksums[filename]):
            raise ImporterError("release asset does not match the published checksums")
        bundles[arch] = {"filename": filename, "sha256": digest, "data": data}
    artifact_ids = (artifact_lister or list_flatpak_artifacts)(plan.repository, descriptor["source_run_id"])
    manifest = validate_manifest(build_manifest(descriptor, bundles, artifact_ids), descriptor)
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    checked = {**descriptor, "manifest_sha256": hashlib.sha256(canonical).hexdigest()}
    bundle_paths = {}
    Path(work_dir).mkdir(parents=True, exist_ok=True)
    for arch in ARCHITECTURES:
        artifact = manifest["artifacts"][arch]
        verify_artifact(bundles[arch]["data"], artifact)
        bundle_paths[arch] = Path(work_dir) / artifact["filename"]
        bundle_paths[arch].write_bytes(bundles[arch]["data"])
    return checked, bundle_paths


def prepare_release(descriptor_path, repo, work_dir, *, allow_empty_repo=False):
    descriptor = json.loads(Path(descriptor_path).read_text(encoding="utf-8"))
    if allow_empty_repo and not verify_public_empty(descriptor.get("channel")):
        raise ImporterError("first publish was claimed but the public repository is not empty")
    verify_mirrored_repo(repo, descriptor.get("channel"),
                         allow_empty=allow_empty_repo)
    snapshot_base_auth(repo, Path(work_dir) / BASE_AUTH_DIR)
    checked, bundle_paths = fetch_release(descriptor, work_dir)
    inspected = merge_bundles(repo, bundle_paths, checked, sign=False)
    for item in inspected:
        item["architecture"] = item["ref"].split("/")[2]
    return checked, inspected


def drop_static_deltas(repo):
    for name in ("deltas", "delta-indexes"):
        target = Path(repo) / name
        if target.is_symlink():
            raise ImporterError("staged repository layout is invalid")
        if target.is_dir():
            shutil.rmtree(target)


def sign_commits(repo, gpg_home, signing_fingerprint):
    for ref in sorted(_repo_refs(repo)):
        if not (ref.startswith("app/") or ref.startswith("runtime/")):
            continue
        commit = _run(["ostree", "rev-parse", "--repo", str(repo), ref]).decode().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", commit):
            raise ImporterError("staged commit checksum is invalid")
        _run(["ostree", "gpg-sign", "--repo", str(repo), "--gpg-homedir", str(gpg_home),
              commit, signing_fingerprint], timeout=120)


def sign_staged_repo(repo, gpg_home, signing_fingerprint):
    verify_tmpfs(gpg_home)
    if not re.fullmatch(r"[A-F0-9]{40,64}", signing_fingerprint or ""):
        raise ImporterError("channel signing fingerprint is invalid")
    sign_commits(repo, gpg_home, signing_fingerprint)
    drop_static_deltas(repo)
    _run(["flatpak", "build-update-repo", "--gpg-sign=" + signing_fingerprint + "!",
          "--gpg-homedir=" + str(gpg_home), str(repo)], timeout=600)
    _run(["ostree", "summary", "--repo", str(repo), "--update", "--gpg-sign",
          signing_fingerprint + "!", "--gpg-homedir", str(gpg_home)], timeout=600)
    summary = Path(repo) / "summary"
    _run(["gpg", "--batch", "--yes", "--homedir", str(gpg_home), "--no-options",
          "--local-user", signing_fingerprint + "!", "--detach-sign", "--output",
          str(Path(repo) / SUMMARY_DETACHED_SIGNATURE), str(summary)], timeout=120)
    ledger = Path(repo) / IMPORTS_LEDGER
    if ledger.is_file():
        _run(["gpg", "--batch", "--yes", "--homedir", str(gpg_home), "--no-options",
              "--local-user", signing_fingerprint + "!", "--detach-sign", "--output",
              str(ledger) + ".sig", str(ledger)], timeout=120)
    else:
        (Path(repo) / (IMPORTS_LEDGER + ".sig")).unlink(missing_ok=True)


def changed_files(repo, previous_files=()):
    previous = previous_files if isinstance(previous_files, dict) else {}
    result = {}
    for path in sorted(Path(repo).rglob("*")):
        if path.is_file():
            relative = path.relative_to(repo).as_posix()
            if relative == ".lock" or relative.startswith("tmp/"):
                continue
            content = path.read_bytes()
            if relative not in previous or hashlib.sha256(content).hexdigest() != previous[relative]:
                result[relative] = content
    return result


def snapshot_repo(repo):
    return {path.relative_to(repo).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(repo).rglob("*")) if path.is_file()}


class SigV4Storage:
    def __init__(self, bucket, endpoint, credentials):
        self.bucket = bucket
        self.client = r2_probe.SigV4Client(credentials, host=urlsplit(endpoint).hostname)

    def put(self, key, content):
        from publish_plan import _checked_key

        channel = key.split("/", 1)[0]
        _checked_key(channel, key)
        response = self.client._request("PUT", self.bucket, key, body=content)
        if response.status not in (200, 201, 204):
            raise ImporterError("R2 object upload failed")

    def list_keys(self, prefix):
        sizes = {}
        token = None
        for _ in range(MAX_LIST_PAGES):
            query = {"list-type": "2", "prefix": prefix, "max-keys": "1000"}
            if token:
                query["continuation-token"] = token
            response = self.client._request("GET", self.bucket, query=query)
            if response.status != 200:
                raise ImporterError("R2 listing failed")
            try:
                root = ElementTree.fromstring(response.body)
            except ElementTree.ParseError as error:
                raise ImporterError("R2 listing is invalid") from error
            truncated, token = False, None
            for element in root:
                name = element.tag.rsplit("}", 1)[-1]
                if name == "Contents":
                    fields = {child.tag.rsplit("}", 1)[-1]: child.text for child in element}
                    if not fields.get("Key", "").startswith(prefix) or not (fields.get("Size") or "").isdigit():
                        raise ImporterError("R2 listing is invalid")
                    sizes[fields["Key"]] = int(fields["Size"])
                elif name == "IsTruncated":
                    truncated = (element.text or "").strip().lower() == "true"
                elif name == "NextContinuationToken":
                    token = element.text
            if not truncated:
                return sizes
            if not token:
                raise ImporterError("R2 listing is invalid")
        raise ImporterError("R2 listing is too large")


def plan_upload_files(repo, channel, remote_sizes):
    files = {}
    for relative, content in changed_files(repo, {}).items():
        key = channel + "/" + relative
        if is_mutable_key(key):
            files[key] = content
        elif key in remote_sizes:
            if remote_sizes[key] != len(content):
                raise ImporterError("a published immutable object differs from the staged object")
        else:
            files[key] = content
    return files


def prune_unreachable(repo):
    _run(["ostree", "prune", "--repo", str(repo), "--refs-only"], timeout=900)


def verify_public_object(key, content):
    url = f"https://flatpak.luminusos.org/{key}"
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "flatpak.luminusos.org":
        return False
    for attempt in range(3):
        try:
            with build_opener(_NoRedirect()).open(public_request(url),
                                                  timeout=PUBLIC_VERIFY_TIMEOUT) as response:
                if response.status != 200 or response.geturl() != url:
                    return False
                observed = response.read(len(content) + 1)
            return len(observed) == len(content) and hmac.compare_digest(
                hashlib.sha256(observed).digest(), hashlib.sha256(content).digest())
        except (OSError, TimeoutError, URLError):
            if attempt == 2:
                return False
            time.sleep(attempt + 1)
    return False


def publish_repo(repo, channel, credentials_path, *, storage=None, public_verify=None,
                 mutable_phase_budget=MUTABLE_PHASE_BUDGET_SECONDS):
    credentials = r2_probe.load_credentials(credentials_path)
    if credentials.get("bucket") != issuer.BUCKET or credentials.get("prefix") != channel + "/":
        raise ImporterError("temporary credential scope does not match channel")
    account = "89e6fc75aed6d04cd84a0c7d11a5594e"
    if storage is None:
        storage = SigV4Storage(issuer.BUCKET, f"https://{account}.r2.cloudflarestorage.com", credentials)
    verify = public_verify or verify_public_object
    files = plan_upload_files(repo, channel, storage.list_keys(channel + "/"))
    plan = build_upload_plan(channel, files)
    publish_uploads(channel, files, storage, verify,
                    expires_at=credentials["expires_at"],
                    minimum_mutable_budget=mutable_phase_budget)
    if not all(verify(item.key, item.content) for item in plan if item.mutable):
        raise ImporterError("public metadata verification failed")
    return plan


def catalog_update_document(descriptor, inspected, uploads):
    checked = validate_descriptor(descriptor)
    if len(inspected) != len(ARCHITECTURES):
        raise ImporterError("catalog update requires both architectures")
    refs = []
    for item in inspected:
        expected_ref = f"app/{checked['package_id']}/{item.get('architecture')}/{checked['channel']}"
        if (item.get("ref") not in (expected_ref, None) or
                not isinstance(item.get("commit"), str) or not re.fullmatch(r"[a-f0-9]{64}", item["commit"])):
            raise ImporterError("catalog update ref or commit is invalid")
        architecture = item.get("architecture")
        if architecture not in ARCHITECTURES:
            raise ImporterError("catalog update architecture is invalid")
        refs.append({"ref": f"app/{checked['package_id']}/{architecture}/{checked['channel']}",
                     "commit": item["commit"]})
    if {item["ref"].split("/")[2] for item in refs} != set(ARCHITECTURES):
        raise ImporterError("catalog update architectures are incomplete")
    return {
        "schema_version": 1, "format": "flatpak", "channel": checked["channel"],
        "application": checked["package_id"], "version": checked["version"], "tag": checked["tag"],
        "source": {"repository": issuer.SOURCE_RELEASES[checked["package_id"]][0],
                   "run_id": checked["source_run_id"], "run_attempt": checked["source_run_attempt"],
                   "revision": checked["git_sha"]},
        "refs": sorted(refs, key=lambda item: item["ref"]),
        "objects": [{"key": item.key, "sha256": item.sha256, "mutable": item.mutable}
                    for item in uploads],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Import a verified Flatpak release into a channel repository")
    parser.add_argument("--mode", choices=("prepare", "publish"), default="publish")
    parser.add_argument("--descriptor", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--gpg-home")
    parser.add_argument("--signing-fingerprint")
    parser.add_argument("--credentials")
    parser.add_argument("--work-dir", default=".")
    parser.add_argument("--inspected")
    parser.add_argument("--allow-empty-repo", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.mode == "prepare":
            descriptor, inspected = prepare_release(args.descriptor, args.repo, args.work_dir,
                                                    allow_empty_repo=args.allow_empty_repo)
            if args.inspected:
                Path(args.inspected).write_text(json.dumps(inspected, sort_keys=True, indent=2) + "\n",
                                                encoding="utf-8")
            return 0
        descriptor = json.loads(Path(args.descriptor).read_text(encoding="utf-8"))
        checked, bundle_paths = fetch_release(descriptor, Path(args.work_dir) / "publisher-bundles")
        inspected = verify_stage(args.repo, args.work_dir, checked, bundle_paths)
        prune_unreachable(args.repo)
        sign_staged_repo(args.repo, args.gpg_home, args.signing_fingerprint)
        upload_plan = publish_repo(args.repo, checked["channel"], args.credentials)
        update = catalog_update_document(
            {key: value for key, value in checked.items() if key != "manifest_sha256"},
            inspected, upload_plan)
        Path("catalog-update.json").write_text(json.dumps(update, sort_keys=True, indent=2) + "\n",
                                                encoding="utf-8")
        result_refs = [{key: item[key] for key in ("ref", "commit", "runtime", "version", "no_op")
                        if key in item} for item in inspected]
        print(json.dumps({"status": "imported", "refs": result_refs}, sort_keys=True))
        return 0
    except (ImporterError, PublishError) as error:
        detail = getattr(error, "detail", "")
        print("Flatpak import failed:", error, *(["(" + detail + ")"] if detail else []), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        frame = error.__traceback__
        while frame is not None and frame.tb_next is not None:
            frame = frame.tb_next
        where = f"{Path(frame.tb_frame.f_code.co_filename).name}:{frame.tb_lineno}" if frame else "unknown"
        print("Flatpak import failed:", type(error).__name__, "at", where, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
