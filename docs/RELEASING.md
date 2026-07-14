# Building a Windows release

Release packages are portable Windows x64 ZIPs. They contain the trainer, its
capture helpers, the session and export tools, participant documentation, media
folders, and license notices. Source files, tests, PDBs, and build intermediates
are left out.

## Build and test

Start from a clean commit:

```powershell
cmake --preset windows-x64 -DABCT_BUILD_APP=ON -DABCT_ENABLE_PACKAGING=ON
cmake --build --preset release
ctest --preset release
cmake --build build/windows-x64 --config Release --target abct_package
```

The package is written to:

```text
build/windows-x64/package/ABCurves-Capture-Trainer-<version>-windows-x64.zip
```

The package target runs the same smoke test used in CI before replacing the
final ZIP. You can run it again directly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-ReleasePackage.ps1 `
  -PackagePath build/windows-x64/package/ABCurves-Capture-Trainer-0.4.1-windows-x64.zip `
  -RequireProbeHelper
```

Check `BUILD_INFO.json` inside the ZIP before publishing. The revision should be
the commit you intend to tag, and both dirty fields should be `false`.

## Publish on GitHub

The release workflow checks that the Git tag matches the version in
`CMakeLists.txt`, builds on a fresh Windows runner, runs the tests, creates the
ZIP and external SHA-256 file, and attaches both to a GitHub Release.

From the qualified commit:

```powershell
git status --short
git tag -a v0.4.1 -m "ABCurves Capture Trainer v0.4.1"
git push origin v0.4.1
```

A manual run of the workflow creates an Actions artifact for inspection without
publishing a GitHub Release.

## What the package checks

- One versioned top-level folder and an exact file inventory
- SHA-256 hashes for every installed file
- Windows x64 executables with matching version resources
- Expected `--version` and command-line behavior
- Required documentation, media placeholders, and third-party licenses
- No source, test, debug, or build files in the participant ZIP
- A source revision that still matches the commit used at configure time

ZIP timestamps are normalized from the commit time, and `BUILD_INFO.json`
records the compiler, source-tree hash, payload files, and artifact roles. The
same commit and inputs should therefore produce an equivalent, auditable
package even when compression bytes differ between .NET versions.
