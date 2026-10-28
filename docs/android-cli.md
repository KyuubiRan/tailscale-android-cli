# Android ARM64 CLI packages

This fork provides a native Android TUN daemon and command line client for rooted Android. It does not use Android VpnService. The ZIP is a CLI payload, not a Magisk/KernelSU installer.

## Local build

Use Python 3.11+, the exact Go version declared in `go.mod`, and an installed Android NDK. The script discovers the NDK through `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, the Android SDK variables, or an installed `adb`. It never installs an SDK, NDK, or Go toolchain. Go module downloads inherit the environment's proxy settings.

```sh
python3 scripts/build-android-cli.py --revision 1
```

Select an existing Go installation with `--go /path/to/go`. Optional `--work-dir` and `--output-dir` select the staging/cache and final package directories. Existing `GOCACHE` and `GOMODCACHE` are respected. Defaults stay inside ignored `.work/android-cli/` and `dist/android-cli/`; staging is removed after a successful package.

The build uses Android API 23, ARM64, CGO, PIE, 16 KiB load alignment, the combined daemon/CLI build, and the Shellscaled Android feature tags. ELF verification reads headers on the host; it never executes the Android binary or runs Android tests. Runtime checks belong on the Android emulator.

Each build produces:

- `Tailscale-<VERSION.txt>-r<revision>-arm64.zip`, containing `bin/tailscaled`, a generic `bin/tailscale` wrapper, `LICENSE`, `PATENTS`, `build-info.json`, and `SHA256SUMS`.
- A matching `.binary.json` compatibility manifest and `.zip.sha256` checksum.

Extract the ZIP on Android and preserve executable permissions on both files in `bin/`. The wrapper sets `TS_BE_CLI=1`; daemon arguments and `--socket` selection remain available to the caller. Account state is not bundled.

## Branch releases

The dedicated [Android CLI workflow](../.github/workflows/android-cli-release.yml) accepts pushes to `dev` and `main`, plus manual runs on those two branches. `VERSION.txt` supplies the Tailscale version; the workflow run number supplies the package revision without a two-digit limit.

CI uses the hosted Ubuntu 24.04 runner's preinstalled NDK `30.0.16248370` and fails clearly if that installation is unavailable. It does not download another SDK or silently change the compiler version.

- `dev`: Pre-release, tag `android-v<version>-dev.<run_number>`, never marked Latest.
- `main`: Release, tag `android-v<version>-r<run_number>`, marked Latest after publication.

All three assets are uploaded to a draft and checked for completeness before publication. Existing release tags and assets are never overwritten. A retry reuses a verified published release and its original manifest, then retries module synchronization. An interrupted draft can resume missing uploads if its existing asset hashes match; conflicting assets require a new workflow run.

After publication, the workflow checks out the corresponding `main` or `dev` branch of `KyuubiRan/Shellscaled`, runs its `scripts/ci-release.py sync` command, and pushes the source/version update. The module repository's own workflow then publishes its matching release. Repeating the same CLI release does not advance the module revision again.

Set `SHELLSCALED_SYNC_KEY` to a dedicated SSH deploy key with write access only to the module repository. Set the `RELEASE_AUTHOR_NAME` and `RELEASE_AUTHOR_EMAIL` repository variables for the synchronization commit. Personal access tokens and personal signing keys are not used. Missing configuration fails clearly after the CLI release is available; rerun that workflow after correcting it to retry synchronization.

Only this Android workflow is intended for this fork. Keep unrelated inherited upstream workflows disabled. CI and the branch release policy must be authorized by the repository owner before enabling the workflow. A CI-only bootstrap commit can use `[skip ci]`; a subsequent `dev` commit or manual run starts the first preview without publishing a stable build from the bootstrap.

The upstream [Tailscale license](../LICENSE) and [patent notice](../PATENTS) remain included in every package.
