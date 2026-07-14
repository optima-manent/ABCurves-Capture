[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildParent = Join-Path $repository 'build'
$build = Join-Path $buildParent 'packaging-fixture'
$buildParentPrefix = [System.IO.Path]::GetFullPath($buildParent).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
$buildFull = [System.IO.Path]::GetFullPath($build)
if (-not $buildFull.StartsWith($buildParentPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Fixture build path escaped the repository build directory"
}
if (Test-Path -LiteralPath $buildFull) {
    Remove-Item -LiteralPath $buildFull -Recurse -Force
}

& cmake -S (Join-Path $repository 'tests\release_fixture') -B $buildFull `
    -G 'Visual Studio 17 2022' -A x64 -DABCT_ENABLE_PACKAGING=ON
if ($LASTEXITCODE -ne 0) { throw "Packaging fixture configure failed" }

& cmake --build $buildFull --config Release --target abct_package
if ($LASTEXITCODE -ne 0) { throw "Packaging fixture build failed" }

$archives = @(Get-ChildItem -LiteralPath (Join-Path $buildFull 'package') -Filter '*.zip' -File)
if ($archives.Count -ne 1) {
    throw "Packaging fixture expected exactly one release ZIP"
}
Write-Host "PASS packaging-infrastructure archive=$($archives[0].FullName)"
