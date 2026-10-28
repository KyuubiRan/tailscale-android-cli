#!/usr/bin/env python3
# Copyright (c) 2026 KyuubiRan
# SPDX-License-Identifier: BSD-3-Clause
"""Cross-compile and package the Android ARM64 CLI with installed Go and NDK."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TAGS = (
    "ts_include_cli,ts_omit_aws,ts_omit_kube,ts_omit_bird,ts_omit_tap,"
    "ts_omit_systray,ts_omit_syspolicy,ts_omit_logtail,ts_omit_netlog,"
    "ts_omit_tpm,ts_omit_ssh,ts_omit_clientupdate,ts_omit_linuxdnsfight"
)
WRAPPER = """#!/system/bin/sh
bindir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd) || exit 1
export TS_BE_CLI=1
exec "$bindir/tailscaled" "$@"
"""


def output(command, **kwargs):
    return subprocess.check_output(command, cwd=ROOT, text=True, **kwargs).strip()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def installed_ndk():
    explicit = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    candidates = [Path(explicit)] if explicit else []
    if sdk:
        candidates += sorted((Path(sdk) / "ndk").glob("*"), reverse=True)
    if not candidates:
        adb = shutil.which("adb")
        if adb:
            candidates += sorted((Path(adb).resolve().parents[1] / "ndk").glob("*"), reverse=True)
    for ndk in candidates:
        for compiler in (ndk / "toolchains/llvm/prebuilt").glob("*/bin/aarch64-linux-android23-clang"):
            properties = (ndk / "source.properties").read_text()
            revision = re.search(r"^Pkg.Revision\s*=\s*(\S+)", properties, re.MULTILINE)
            if not revision:
                raise SystemExit("The installed NDK does not declare its version")
            return compiler, revision.group(1)
    raise SystemExit("Install an Android NDK or set ANDROID_NDK_HOME; SDK/NDK downloads are never automatic")


def inspect_elf(binary):
    """Read ELF headers; never execute an Android program on the build host."""
    data = binary.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise SystemExit("Expected a little-endian ELF64 binary")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[1:3] != (3, 183):
        raise SystemExit("Expected an AArch64 PIE (ET_DYN) binary")
    offset, entry_size, count = header[5], header[9], header[10]
    if entry_size != 56 or not count or offset + entry_size * count > len(data):
        raise SystemExit("Invalid ELF program headers")
    interpreter = None
    alignments = []
    for index in range(count):
        program = struct.unpack_from("<IIQQQQQQ", data, offset + index * entry_size)
        kind, _, file_offset, address, _, file_size, _, alignment = program
        if file_offset + file_size > len(data):
            raise SystemExit("An ELF segment exceeds the binary size")
        if kind == 3:
            interpreter = data[file_offset:file_offset + file_size].rstrip(b"\x00").decode("ascii")
        if kind == 1:
            if alignment < 16384 or alignment & (alignment - 1) or (address - file_offset) % 16384:
                raise SystemExit("An ELF load segment is incompatible with 16 KiB pages")
            alignments.append(alignment)
    if interpreter != "/system/bin/linker64" or not alignments:
        raise SystemExit("Expected Android's 64-bit dynamic linker and loadable segments")
    return {"type": "PIE", "machine": "AArch64", "interpreter": interpreter, "loadSegmentAlignments": alignments}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", type=int, default=1, help="positive package revision; CI uses GITHUB_RUN_NUMBER")
    parser.add_argument("--release-channel", choices=["prerelease", "stable"], default="prerelease")
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".work/android-cli")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist/android-cli")
    parser.add_argument("--go", default=os.environ.get("SHELLSCALED_GO", "go"), help="installed Go executable matching go.mod")
    parser.add_argument("--github-output", type=Path, help="append build outputs to a GitHub Actions output file")
    args = parser.parse_args()
    if args.revision < 1:
        parser.error("revision must be positive")
    version = (ROOT / "VERSION.txt").read_text().strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("Expected a three-part Tailscale VERSION.txt")
    source_commit = output(["git", "rev-parse", "HEAD"])
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise SystemExit("Expected a full Git source commit")
    if output(["git", "status", "--porcelain"]):
        raise SystemExit("Commit the source changes before building a release package")
    go_directive = re.search(r"^go\s+(\d+\.\d+\.\d+)\s*$", (ROOT / "go.mod").read_text(), re.MULTILINE)
    if not go_directive:
        raise SystemExit("Expected an exact Go version in go.mod")
    work = args.work_dir.resolve()
    destination = args.output_dir.resolve()
    env = os.environ.copy()
    env["GOTOOLCHAIN"] = "local"
    go_version = output([args.go, "env", "GOVERSION"], env=env)
    if go_version != "go" + go_directive.group(1):
        raise SystemExit(f"Install Go {go_directive.group(1)} or select it with --go; toolchains are never downloaded automatically")
    compiler, ndk_version = installed_ndk()
    env.update({"GOOS": "android", "GOARCH": "arm64", "CGO_ENABLED": "1", "CC": str(compiler)})
    env.setdefault("GOCACHE", str(work / "cache/go-build"))
    env.setdefault("GOMODCACHE", str(work / "cache/gomod"))
    stage = work / "package"
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "bin").mkdir(parents=True)
    binary = stage / "bin/tailscaled"
    ldflags = (
        f"-s -w -X tailscale.com/version.shortStamp={version} "
        f"-X tailscale.com/version.longStamp={version}-shellscaled-{source_commit[:12]} "
        f"-X tailscale.com/version.gitCommitStamp={source_commit} "
        "-extldflags=-Wl,-z,max-page-size=16384"
    )
    print(f"Building Tailscale {version}, source {source_commit}, {go_version}, NDK {ndk_version}", flush=True)
    subprocess.run([
        args.go, "build", "-trimpath", "-buildvcs=false", "-buildmode=pie",
        f"-tags={TAGS}", f"-ldflags={ldflags}", "-o", str(binary), "./cmd/tailscaled",
    ], cwd=ROOT, env=env, check=True)
    elf = inspect_elf(binary)
    binary_hash = digest(binary)
    (stage / "bin/tailscale").write_text(WRAPPER)
    for name in ["tailscaled", "tailscale"]:
        (stage / "bin" / name).chmod(0o755)
    for name in ["LICENSE", "PATENTS"]:
        shutil.copyfile(ROOT / name, stage / name)
    build_info = {
        "tailscaleVersion": version, "sourceCommit": source_commit, "architecture": "arm64",
        "binarySHA256": binary_hash, "binaryCompatibility": 1, "releaseChannel": args.release_channel,
        "packageRevision": args.revision, "goVersion": go_version, "ndkVersion": ndk_version,
        "minimumAndroidAPI": 23, "cgoEnabled": True, "buildTags": TAGS.split(","), "elf": elf,
    }
    (stage / "build-info.json").write_text(json.dumps(build_info, indent=2) + "\n")
    files = sorted(path for path in stage.rglob("*") if path.is_file())
    (stage / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.relative_to(stage).as_posix()}\n" for path in files))
    destination.mkdir(parents=True, exist_ok=True)
    package = destination / f"Tailscale-{version}-r{args.revision}-arm64.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                info = zipfile.ZipInfo(path.relative_to(stage).as_posix(), date_time=(2020, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (0o100755 if path.parent.name == "bin" else 0o100644) << 16
                archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    package_hash = digest(package)
    manifest = package.with_suffix(".binary.json")
    manifest.write_text(json.dumps({
        "schema": 1, "compatibility": 1, "releaseChannel": args.release_channel,
        "tailscaleVersion": version, "sourceCommit": source_commit, "architecture": "arm64",
        "binarySHA256": binary_hash, "packageName": package.name, "packageSHA256": package_hash,
    }, indent=2) + "\n")
    checksum = package.with_suffix(".zip.sha256")
    checksum.write_text(f"{package_hash}  {package.name}\n")
    if args.github_output:
        with args.github_output.open("a") as stream:
            for key, value in {"version": version, "package": package, "manifest": manifest, "checksum": checksum}.items():
                stream.write(f"{key}={value}\n")
    shutil.rmtree(stage)
    print(f"Built {package.name} ({package.stat().st_size // 1024 // 1024} MiB), sha256 {package_hash}")
    print("Static verification passed: Android ARM64 PIE, CGO, 16 KiB load alignment. No Android binary was executed.")


if __name__ == "__main__":
    main()
