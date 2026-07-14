[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $CMakeCommand,
    [Parameter(Mandatory = $true)][string] $SourceDirectory,
    [Parameter(Mandatory = $true)][string] $BuildDirectory,
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [Parameter(Mandatory = $true)][string] $Configuration,
    [Parameter(Mandatory = $true)][string] $Version,
    [Parameter(Mandatory = $true)][int] $Protocol,
    [Parameter(Mandatory = $true)][string] $SourceId,
    [Parameter(Mandatory = $true)][string] $SourceRevision,
    [Parameter(Mandatory = $true)][string] $SourceDirty,
    [Parameter(Mandatory = $true)][long] $SourceEpoch,
    [Parameter(Mandatory = $true)][string] $Generator,
    [Parameter(Mandatory = $true)][string] $Toolchain,
    [Parameter(Mandatory = $true)][string] $ParticipantApp,
    [Parameter(Mandatory = $true)][string] $CaptureHelper,
    [Parameter(Mandatory = $true)][string] $SessionTool,
    [Parameter(Mandatory = $true)][string] $ResearchExporter,
    [string] $ProbeHelper = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-FullPath([string] $Path) {
    return [System.IO.Path]::GetFullPath($Path)
}

function Assert-DescendantPath([string] $Child, [string] $Parent, [string] $Label) {
    $childFull = Get-FullPath $Child
    $parentFull = (Get-FullPath $Parent).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $childFull.StartsWith($parentFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must remain below '$Parent': '$Child'"
    }
}

function Assert-LeafExecutable([string] $Name, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Name) -or
        [System.IO.Path]::IsPathRooted($Name) -or
        [System.IO.Path]::GetFileName($Name) -cne $Name -or
        [System.IO.Path]::GetExtension($Name) -ine ".exe") {
        throw "$Label must be a single .exe filename, got '$Name'"
    }
}

function Get-RelativeSlashPath([string] $Root, [string] $Path) {
    $rootPrefix = (Get-FullPath $Root).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $full = Get-FullPath $Path
    if (-not $full.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escaped inventory root: '$Path'"
    }
    return $full.Substring($rootPrefix.Length).Replace('\', '/')
}

function Get-LowerSha256([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-Utf8Lf([string] $Path, [string] $Text) {
    $normalized = $Text.Replace("`r`n", "`n").Replace("`r", "`n")
    if (-not $normalized.EndsWith("`n", [System.StringComparison]::Ordinal)) {
        $normalized += "`n"
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $normalized, $encoding)
}

function Get-SortedFiles([string] $Root) {
    $items = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File)
    [string[]] $paths = @($items | ForEach-Object { Get-RelativeSlashPath $Root $_.FullName })
    [System.Array]::Sort($paths, [System.StringComparer]::Ordinal)
    return $paths
}

function Test-SourceInventoryFile([string] $Relative) {
    if ($Relative -match '^(?:\.git|\.vs|build|out|dist|package|Testing|local|sessions)(?:/|$)') {
        return $false
    }
    if ($Relative -match '(?i)(?:^|/)(?:CMakeCache\.txt|CMakeUserPresets\.json|cmake_install\.cmake|CTestTestfile\.cmake|install_manifest\.txt)$') {
        return $false
    }
    if ($Relative -match '(?i)\.(?:obj|lib|exp|exe|dll|pdb|ilk|idb|tlog|lastbuildstate|log|zip|7z|tmp|partial)$') {
        return $false
    }
    return $true
}

function Get-SourceTreeSha256([string] $Root) {
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        foreach ($relative in (Get-SortedFiles $Root)) {
            if (-not (Test-SourceInventoryFile $relative)) { continue }
            $path = Join-Path $Root ($relative.Replace('/', '\'))
            $length = (Get-Item -LiteralPath $path).Length
            $fileHash = Get-LowerSha256 $path
            $record = $relative + "`0" + $length + "`0" + $fileHash + "`n"
            $bytes = $encoding.GetBytes($record)
            [void] $hash.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)
        }
        [void] $hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
        return ([System.BitConverter]::ToString($hash.Hash)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hash.Dispose()
    }
}

function Get-GitStateAtPackage([string] $Root, [bool] $DirtyFallback) {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $git -or -not (Test-Path -LiteralPath (Join-Path $Root '.git'))) {
        return [pscustomobject]@{ Available = $false; Revision = $null; Dirty = $DirtyFallback }
    }
    $priorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $revisionLines = @(& $git.Source -C $Root rev-parse --verify HEAD 2>$null)
        $revisionExit = $LASTEXITCODE
        $status = @(& $git.Source -C $Root status --porcelain=v1 --untracked-files=normal 2>$null)
        $statusExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($statusExit -ne 0) {
        return [pscustomobject]@{ Available = $false; Revision = $null; Dirty = $DirtyFallback }
    }
    $revision = 'unversioned'
    if ($revisionExit -eq 0 -and $revisionLines.Count -eq 1 -and
        [string]$revisionLines[0] -match '^[0-9a-fA-F]{40}$') {
        $revision = ([string]$revisionLines[0]).ToLowerInvariant()
    }
    return [pscustomobject]@{
        Available = $true
        Revision = $revision
        Dirty = $status.Count -ne 0
    }
}

function New-PayloadInventory([string] $Root) {
    $result = @()
    foreach ($relative in (Get-SortedFiles $Root)) {
        if ($relative -eq 'BUILD_INFO.json' -or $relative -eq 'SHA256SUMS') { continue }
        $path = Join-Path $Root ($relative.Replace('/', '\'))
        $result += [ordered]@{
            path = $relative
            size = [long](Get-Item -LiteralPath $path).Length
            sha256 = Get-LowerSha256 $path
        }
    }
    return @($result)
}

function Get-NormalizedArchiveTime([long] $Epoch) {
    $minimum = [long]315532800
    $maximum = [long]4354819198
    if ($Epoch -lt $minimum) { $Epoch = $minimum }
    if ($Epoch -gt $maximum) { $Epoch = $maximum }
    $utc = [datetime]::SpecifyKind(([datetime]'1970-01-01').AddSeconds($Epoch), [DateTimeKind]::Utc)
    return [pscustomobject]@{
        Epoch = $Epoch
        Offset = [DateTimeOffset]$utc
        Text = $utc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    }
}

function Write-DeterministicZip([string] $Root, [string] $RootName,
                                [string] $Destination, [DateTimeOffset] $Timestamp) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Destination) {
        if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
            throw "Package destination is not a file: '$Destination'"
        }
        Remove-Item -LiteralPath $Destination -Force
    }

    $stream = [System.IO.File]::Open(
        $Destination,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None)
    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $stream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        foreach ($relative in (Get-SortedFiles $Root)) {
            $entry = $archive.CreateEntry(
                "$RootName/$relative",
                [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $Timestamp
            $input = [System.IO.File]::OpenRead((Join-Path $Root ($relative.Replace('/', '\'))))
            $output = $null
            try {
                $output = $entry.Open()
                $input.CopyTo($output)
            }
            finally {
                if ($null -ne $output) { $output.Dispose() }
                $input.Dispose()
            }
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        else { $stream.Dispose() }
    }
}

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$') {
    throw "Version is not a numeric release version: '$Version'"
}
if ($Protocol -le 0) { throw "Protocol must be positive" }
if ([string]::IsNullOrWhiteSpace($SourceId) -or $SourceId -match '\s') {
    throw "SourceId must be a nonempty token"
}
Assert-LeafExecutable $ParticipantApp 'ParticipantApp'
Assert-LeafExecutable $CaptureHelper 'CaptureHelper'
Assert-LeafExecutable $SessionTool 'SessionTool'
Assert-LeafExecutable $ResearchExporter 'ResearchExporter'
if (-not [string]::IsNullOrWhiteSpace($ProbeHelper)) {
    Assert-LeafExecutable $ProbeHelper 'ProbeHelper'
}

$sourceRoot = Get-FullPath $SourceDirectory
$buildRoot = Get-FullPath $BuildDirectory
if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) {
    throw "Source directory does not exist: '$sourceRoot'"
}
if (-not (Test-Path -LiteralPath $buildRoot -PathType Container)) {
    throw "Build directory does not exist: '$buildRoot'"
}

$stagingParent = Join-Path $buildRoot '_abct_package'
Assert-DescendantPath $stagingParent $buildRoot 'Staging directory'
if (Test-Path -LiteralPath $stagingParent) {
    Remove-Item -LiteralPath $stagingParent -Recurse -Force
}
[void](New-Item -ItemType Directory -Path $stagingParent)

$rootName = "ABCurves-Capture-Trainer-$Version-windows-x64"
$packageRoot = Join-Path $stagingParent $rootName
[void](New-Item -ItemType Directory -Path $packageRoot)

& $CMakeCommand --install $buildRoot --config $Configuration --prefix $packageRoot
if ($LASTEXITCODE -ne 0) {
    throw "cmake --install failed with exit code $LASTEXITCODE"
}

$artifacts = [ordered]@{
    participant_app = $ParticipantApp
    capture_helper = $CaptureHelper
    session_tool = $SessionTool
    research_exporter = $ResearchExporter
}
if (-not [string]::IsNullOrWhiteSpace($ProbeHelper)) {
    $artifacts.probe_helper = $ProbeHelper
}
foreach ($artifact in $artifacts.GetEnumerator()) {
    $artifactPath = Join-Path $packageRoot $artifact.Value
    if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        throw "Installed package is missing $($artifact.Key): '$($artifact.Value)'"
    }
}

$configureDirty = $SourceDirty -match '^(?i:true|on|yes|1)$'
$gitState = Get-GitStateAtPackage $sourceRoot $configureDirty
if ($gitState.Available -and $gitState.Revision -cne $SourceRevision) {
    throw "Git HEAD changed after CMake configuration ('$SourceRevision' -> '$($gitState.Revision)'). Reconfigure before packaging."
}
$packageDirty = [bool]$gitState.Dirty
$treeHash = Get-SourceTreeSha256 $sourceRoot
$archiveTime = Get-NormalizedArchiveTime $SourceEpoch
$payload = New-PayloadInventory $packageRoot

$buildInfo = [ordered]@{
    schema = 'abcurves.release.build.v1'
    product = 'ABCurves Capture Trainer'
    version = $Version
    protocol = $Protocol
    platform = 'windows-x64'
    configuration = $Configuration
    source = [ordered]@{
        id = $SourceId
        revision = $SourceRevision
        revision_at_package = $gitState.Revision
        dirty_at_configure = $configureDirty
        dirty_at_package = $packageDirty
        tree_sha256 = $treeHash
    }
    toolchain = [ordered]@{
        cmake_generator = $Generator
        compiler = $Toolchain.Trim()
    }
    archive = [ordered]@{
        normalized_timestamp_epoch = $archiveTime.Epoch
        normalized_timestamp_utc = $archiveTime.Text
    }
    artifacts = $artifacts
    payload = @($payload)
}
Write-Utf8Lf (Join-Path $packageRoot 'BUILD_INFO.json') ($buildInfo | ConvertTo-Json -Depth 8)

$checksumLines = @()
foreach ($relative in (Get-SortedFiles $packageRoot)) {
    if ($relative -eq 'SHA256SUMS') { continue }
    $path = Join-Path $packageRoot ($relative.Replace('/', '\'))
    $checksumLines += "$(Get-LowerSha256 $path)  $relative"
}
Write-Utf8Lf (Join-Path $packageRoot 'SHA256SUMS') ($checksumLines -join "`n")

$outputRoot = Get-FullPath $OutputDirectory
if (-not (Test-Path -LiteralPath $outputRoot)) {
    [void](New-Item -ItemType Directory -Path $outputRoot)
}
if (-not (Test-Path -LiteralPath $outputRoot -PathType Container)) {
    throw "OutputDirectory is not a directory: '$outputRoot'"
}
$archivePath = Join-Path $outputRoot ($rootName + '.zip')
$archivePartialPath = $archivePath + '.partial'
$archiveBackupPath = $archivePath + '.previous.' + [guid]::NewGuid().ToString('N')
Assert-DescendantPath $archivePath $outputRoot 'Archive path'
Assert-DescendantPath $archivePartialPath $outputRoot 'Partial archive path'
Assert-DescendantPath $archiveBackupPath $outputRoot 'Backup archive path'

$smokeScript = Join-Path $sourceRoot 'scripts\Test-ReleasePackage.ps1'
$smokeArguments = @{ PackagePath = $archivePartialPath }
if (-not [string]::IsNullOrWhiteSpace($ProbeHelper)) {
    $smokeArguments.RequireProbeHelper = $true
}

$replaceCompleted = $false
try {
    # Never publish a canonical release filename until the complete candidate
    # has passed the same smoke checks used by CI. Both paths share a parent so
    # the final rename/replace is an atomic filesystem operation.
    Write-DeterministicZip $packageRoot $rootName $archivePartialPath $archiveTime.Offset
    & $smokeScript @smokeArguments

    if (Test-Path -LiteralPath $archivePath) {
        if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
            throw "Package destination is not a file: '$archivePath'"
        }
        # File.Replace is the supported same-volume atomic replacement on
        # Windows. A unique backup path avoids collisions with crash residue;
        # it is removed only after replacement succeeds.
        [System.IO.File]::Replace(
            $archivePartialPath, $archivePath, $archiveBackupPath, $true)
        $replaceCompleted = $true
    }
    else {
        [System.IO.File]::Move($archivePartialPath, $archivePath)
    }
}
finally {
    if (Test-Path -LiteralPath $archivePartialPath) {
        Remove-Item -LiteralPath $archivePartialPath -Force
    }
    if ($replaceCompleted -and (Test-Path -LiteralPath $archiveBackupPath)) {
        Remove-Item -LiteralPath $archiveBackupPath -Force
    }
}

$archiveHash = Get-LowerSha256 $archivePath
Write-Host "PACKAGE $archivePath"
Write-Host "SHA256  $archiveHash"
