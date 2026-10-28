#!/usr/bin/env python3
# Copyright (c) 2026 KyuubiRan
# SPDX-License-Identifier: BSD-3-Clause
"""Publish a complete CLI release, or reuse its published assets on a CI retry."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

REPOSITORY = "KyuubiRan/tailscale-android-cli"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def gh(*arguments):
    subprocess.run(["gh", *arguments], check=True)


def api(endpoint, missing_ok=False):
    response = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True)
    if response.returncode:
        if missing_ok and "(HTTP 404)" in response.stderr:
            return None
        raise SystemExit(f"GitHub API request failed for {endpoint}: {response.stderr.strip()}")
    return json.loads(response.stdout)


def find_release(prefix, tag, missing_ok=False):
    # The REST tag endpoint sees only published releases. The official CLI also
    # resolves pending draft tags, then this script fetches their numeric ID.
    response = subprocess.run(["gh", "release", "view", tag, "--json", "databaseId"], capture_output=True, text=True)
    if response.returncode:
        if missing_ok and "release not found" in response.stderr.lower():
            return None
        raise SystemExit(f"Cannot look up release {tag}: {response.stderr.strip()}")
    identifier = json.loads(response.stdout)["databaseId"]
    if type(identifier) is not int or identifier <= 0:
        raise SystemExit("GitHub returned an invalid release ID")
    return api(f"{prefix}/releases/{identifier}")


def validate_manifest(path, expected):
    manifest = json.loads(path.read_text())
    if set(manifest) != set(expected) | {"binarySHA256", "packageSHA256"}:
        raise SystemExit("Unexpected binary manifest fields")
    for key, value in expected.items():
        if manifest[key] != value:
            raise SystemExit(f"Binary manifest {key} does not match this release")
    for key in ["binarySHA256", "packageSHA256"]:
        if not re.fullmatch(r"[0-9a-f]{64}", manifest[key]):
            raise SystemExit(f"Invalid binary manifest {key}")
    return manifest


def validate_assets(release, files):
    assets = {asset["name"]: asset for asset in release["assets"]}
    if len(assets) != len(release["assets"]) or set(assets) != {path.name for path in files}:
        raise SystemExit("Release assets are incomplete or contain unexpected files")
    for path in files:
        asset = assets[path.name]
        if asset["state"] != "uploaded" or asset["size"] != path.stat().st_size:
            raise SystemExit(f"Release asset is incomplete: {path.name}")
        if asset.get("digest") and asset["digest"] != "sha256:" + digest(path):
            raise SystemExit(f"Release asset digest differs: {path.name}")


def verify_tag(prefix, reference, source_commit):
    current = reference["object"]
    for _ in range(4):
        if current["type"] == "commit" and current["sha"] == source_commit:
            return
        if current["type"] != "tag" or not re.fullmatch(r"[0-9a-f]{40}", current["sha"]):
            break
        current = api(f"{prefix}/git/tags/{current['sha']}")["object"]
    raise SystemExit("The existing release tag points to another commit; it will not be changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--checksum", required=True, type=Path)
    parser.add_argument("--github-output", required=True, type=Path)
    args = parser.parse_args()
    branch = os.environ.get("GITHUB_REF_NAME")
    source_commit = os.environ.get("GITHUB_SHA", "")
    revision = os.environ.get("GITHUB_RUN_NUMBER", "")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GH_REPO") != REPOSITORY:
        raise SystemExit("Publishing is restricted to this repository's GitHub Actions workflow")
    if branch not in {"main", "dev"} or os.environ.get("GITHUB_REF") != f"refs/heads/{branch}":
        raise SystemExit("Only main and dev branches may publish Android CLI packages")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit) or not re.fullmatch(r"[1-9][0-9]*", revision):
        raise SystemExit("Invalid workflow source commit or run number")
    version = (Path(__file__).resolve().parents[1] / "VERSION.txt").read_text().strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("Expected a three-part Tailscale version")
    prerelease = branch == "dev"
    channel = "prerelease" if prerelease else "stable"
    suffix = f"dev.{revision}" if prerelease else f"r{revision}"
    tag = f"android-v{version}-{suffix}"
    prefix = f"repos/{REPOSITORY}"
    package = args.package.resolve()
    manifest_file = args.manifest.resolve()
    checksum = args.checksum.resolve()
    expected_package = f"Tailscale-{version}-r{revision}-arm64.zip"
    if package.name != expected_package or manifest_file.name != expected_package.removesuffix(".zip") + ".binary.json" or checksum.name != expected_package + ".sha256":
        raise SystemExit("Package asset names do not match this workflow run")
    expected = {
        "schema": 1, "compatibility": 1, "releaseChannel": channel,
        "tailscaleVersion": version, "sourceCommit": source_commit,
        "architecture": "arm64", "packageName": package.name,
    }
    manifest = validate_manifest(manifest_file, expected)
    if digest(package) != manifest["packageSHA256"] or checksum.read_text() != f"{manifest['packageSHA256']}  {package.name}\n":
        raise SystemExit("Local package or checksum differs from the binary manifest")
    release = find_release(prefix, tag, missing_ok=True)
    tag_ref = api(f"{prefix}/git/ref/tags/{tag}", missing_ok=True)
    if tag_ref:
        verify_tag(prefix, tag_ref, source_commit)
    if release and (release["target_commitish"] != source_commit or release["prerelease"] != prerelease or release["tag_name"] != tag):
        raise SystemExit("The existing release source or channel does not match this workflow run")
    files = [package, manifest_file, checksum]
    if release and not release["draft"]:
        if not tag_ref:
            raise SystemExit("The published release has no verified source tag")
        # Rebuilt bytes may differ after a runner/NDK update. The published manifest
        # is the authoritative input for a retried module sync, never the rebuild.
        published = Path.cwd() / ".work/android-cli/published-assets"
        if published.exists():
            shutil.rmtree(published)
        published.mkdir(parents=True)
        gh("release", "download", tag, "--dir", str(published), *[item for path in files for item in ("--pattern", path.name)])
        files = [published / path.name for path in files]
        validate_assets(release, files)
        package, manifest_file, checksum = files
        manifest = validate_manifest(manifest_file, expected)
        if digest(package) != manifest["packageSHA256"] or checksum.read_text() != f"{manifest['packageSHA256']}  {package.name}\n":
            raise SystemExit("Published package or checksum differs from its binary manifest")
        print(f"Reusing published {tag}; release assets and tags remain unchanged", flush=True)
    else:
        if tag_ref and not release:
            raise SystemExit("The release tag already exists without a release; it will not be reused")
        if not release:
            notes = Path.cwd() / ".work/android-cli/release-notes.md"
            notes.parent.mkdir(parents=True, exist_ok=True)
            notes.write_text(
                f"Android ARM64 Tailscale {version} ({'Pre-release' if prerelease else 'Release'}).\n\n"
                "Contains the native `tailscaled` daemon and `tailscale` CLI wrapper, licenses, build information, and checksums. "
                "This is a CLI payload, not a Magisk/KernelSU module installer.\n\n"
                f"Source: `{source_commit}`.\n\n"
                "ARM64 PIE and 16 KiB load alignment are statically verified. Android runtime checks use an emulator.\n"
            )
            gh("release", "create", tag, "--target", source_commit, "--title", f"Tailscale {version} Android ARM64 ({suffix})",
               "--draft", f"--prerelease={str(prerelease).lower()}", "--latest=false", "--notes-file", str(notes))
            release = find_release(prefix, tag)
        existing = {asset["name"]: asset for asset in release["assets"]}
        if len(existing) != len(release["assets"]) or not set(existing) <= {path.name for path in files}:
            raise SystemExit("The draft contains unexpected or duplicate assets; it remains unpublished")
        for path in files:
            asset = existing.get(path.name)
            if asset:
                # Never overwrite an uploaded asset, including during draft retries.
                if asset["state"] != "uploaded" or asset["size"] != path.stat().st_size or asset.get("digest") != "sha256:" + digest(path):
                    raise SystemExit(f"An existing draft asset differs: {path.name}; start a fresh workflow run")
            else:
                gh("release", "upload", tag, str(path))
        release = api(f"{prefix}/releases/{release['id']}")
        validate_assets(release, files)
        gh("release", "edit", tag, "--draft=false", f"--prerelease={str(prerelease).lower()}", f"--latest={str(not prerelease).lower()}")
        release = api(f"{prefix}/releases/{release['id']}")
        if release["draft"]:
            raise SystemExit("The release was not published; module sync is not allowed")
        print(f"Published {tag}", flush=True)
    with args.github_output.open("a") as stream:
        stream.write(f"tag={tag}\nmanifest={manifest_file}\n")


if __name__ == "__main__":
    main()
