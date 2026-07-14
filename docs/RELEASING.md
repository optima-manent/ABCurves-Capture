# Building a Windows participant release

Release packaging is deliberately separate from normal engineering builds.
The portable package contains only the participant application, its narrow
capture/probe helpers, the offline session and research-export tools,
participant-facing documents, license notices, and media folders. Tests,
libraries, object files, PDBs, build trees, and source files are not installed.

## Integrated release plumbing

Release support is already integrated in the root `CMakeLists.txt`. Configure
time resolves the Git revision and dirty state, every shipped executable gets
Windows version metadata, and `cmake/ABCTRelease.cmake` registers the audited
`abct_package` target when `ABCT_ENABLE_PACKAGING=ON`.

The participant filename `ABCurves Capture Trainer.exe` and the sibling helper
filenames are part of the tested public interface. If a target is renamed, its
application lookup, install rule, build manifest, and package smoke assertions
must be updated together.

## Build and verify

From a clean checkout or source snapshot:

```powershell
cmake --preset windows-x64 -DABCT_BUILD_APP=ON -DABCT_ENABLE_PACKAGING=ON
cmake --build --preset release
ctest --preset release
cmake --build build/windows-x64 --config Release --target abct_package
```

The final ZIP is written below `build/windows-x64/package`. It is first built
under a sibling `.partial` name, checked by the same independent verifier that
study organizers can run later, and only then atomically published under the
final name:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-ReleasePackage.ps1 `
  -PackagePath build/windows-x64/package/ABCurves-Capture-Trainer-0.4.1-windows-x64.zip
```

Do not distribute a package whose `BUILD_INFO.json` reports `unversioned`, a
dirty source tree, or a revision other than the release tag's commit.

## Publish through GitHub

The `windows-release.yml` workflow repeats the Release build, hardware-free
tests, package construction, and smoke verification on a GitHub-hosted Windows
runner. A version tag matching the CMake project version then creates a GitHub
Release and attaches both the participant ZIP and its external `.sha256` file.

From a clean `main` branch whose commit is already on GitHub:

```powershell
git status --short
git tag -a v0.4.1 -m "ABCurves Capture Trainer v0.4.1"
git push origin v0.4.1
```

The tag check is exact: a `v0.4.1` tag requires
`project(ABCurvesCaptureTrainer VERSION 0.4.1 ...)`. A manual workflow dispatch
builds and retains an Actions artifact for inspection but does not publish a
GitHub Release. Do not push the release tag until the public release gate in
`docs/TESTING.md` is satisfied for the exact candidate package.

## Audit and reproducibility properties

- Every ZIP has one versioned top-level directory and a fixed, sorted member
  order.
- ZIP timestamps come from `SOURCE_DATE_EPOCH`, the Git commit timestamp, or a
  documented 1980 fallback for an unversioned snapshot.
- `BUILD_INFO.json` records source identity, dirty state at configure/package
  time, a canonical source-tree SHA-256, toolchain identity, artifact roles,
  and the hash and size of every installed payload file.
- Packaging refuses to continue if Git `HEAD` changed after CMake configured
  the source ID, preventing a stale revision stamp.
- A failed build or smoke test removes its `.partial` candidate and leaves any
  previously verified final ZIP untouched.
- Required third-party BSD license terms are installed beside the notices and
  are covered by both package inventories.
- `SHA256SUMS` independently inventories every package file except itself.
- The smoke test validates safe ZIP paths, exact inventory, hashes, x64 PE
  machine type, Windows version resources, tool `--version` output, session-tool
  usage behavior, required documentation/media, and absence of build debris.

Compression bytes are expected to be stable for the same PowerShell/.NET
runtime and identical inputs. The embedded inventories are the authoritative
audit mechanism across different .NET compression implementations.
