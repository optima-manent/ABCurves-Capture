[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PackagePath,
    [switch] $RequireProbeHelper,
    [switch] $KeepExtracted
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
        throw "$Label escaped '$Parent': '$Child'"
    }
}

function Get-RelativeSlashPath([string] $Root, [string] $Path) {
    $rootPrefix = (Get-FullPath $Root).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $full = Get-FullPath $Path
    if (-not $full.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escaped package root: '$Path'"
    }
    return $full.Substring($rootPrefix.Length).Replace('\', '/')
}

function Get-SortedFiles([string] $Root) {
    $items = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File)
    [string[]] $paths = @($items | ForEach-Object { Get-RelativeSlashPath $Root $_.FullName })
    [System.Array]::Sort($paths, [System.StringComparer]::Ordinal)
    return $paths
}

function Get-LowerSha256([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-SafeRelativePath([string] $Relative, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Relative) -or
        $Relative.Contains('\') -or
        $Relative.StartsWith('/', [System.StringComparison]::Ordinal) -or
        $Relative.Contains(':')) {
        throw "$Label is not a canonical relative path: '$Relative'"
    }
    $parts = $Relative.Split('/')
    if ($parts.Count -eq 0 -or $parts -contains '' -or
        $parts -contains '.' -or $parts -contains '..') {
        throw "$Label contains an unsafe path component: '$Relative'"
    }
}

function Assert-LeafExecutable([string] $Name, [string] $Label) {
    Assert-SafeRelativePath $Name $Label
    if ($Name.Contains('/') -or [System.IO.Path]::GetExtension($Name) -ine '.exe') {
        throw "$Label must be one .exe filename, got '$Name'"
    }
}

function Get-Artifact([object] $Info, [string] $Name, [bool] $Required) {
    $property = $Info.artifacts.PSObject.Properties[$Name]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        if ($Required) { throw "BUILD_INFO.json is missing artifact '$Name'" }
        return $null
    }
    return [string]$property.Value
}

function Assert-X64Pe([string] $Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    $reader = $null
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) {
            throw "Not a PE executable: '$Path'"
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt $stream.Length - 6) {
            throw "Invalid PE header offset: '$Path'"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "Missing PE signature: '$Path'"
        }
        $machine = $reader.ReadUInt16()
        if ($machine -ne 0x8664) {
            throw ("Executable is not Windows x64 (machine=0x{0:x4}): '{1}'" -f $machine, $Path)
        }
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        else { $stream.Dispose() }
    }
}

function Invoke-Captured([string] $Executable, [string[]] $Arguments) {
    $priorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $Executable @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorPreference
    }
    $text = (($lines | ForEach-Object { $_.ToString() }) -join "`n").Trim()
    return [pscustomobject]@{ ExitCode = $exitCode; Text = $text }
}

function Assert-VersionCommand([string] $Executable, [string] $CommandName,
                               [string] $Version, [int] $Protocol,
                               [string] $SourceId) {
    $result = Invoke-Captured $Executable @('--version')
    $expected = "$CommandName $Version protocol=$Protocol source=$SourceId"
    if ($result.ExitCode -ne 0 -or $result.Text -cne $expected) {
        throw "Unexpected --version output from '$Executable'. Expected '$expected', exit 0; got '$($result.Text)', exit $($result.ExitCode)"
    }
}

function Expand-SafePackage([string] $ArchivePath, [string] $Destination) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    $seen = @{}
    [long] $totalLength = 0
    try {
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            if ([string]::IsNullOrWhiteSpace($name) -or
                $name.EndsWith('/', [System.StringComparison]::Ordinal) -or
                $name.Contains('\')) {
                throw "ZIP contains a noncanonical member: '$name'"
            }
            Assert-SafeRelativePath $name 'ZIP member'
            $key = $name.ToLowerInvariant()
            if ($seen.ContainsKey($key)) {
                throw "ZIP contains a duplicate or case-colliding member: '$name'"
            }
            $seen[$key] = $true

            $unixType = (($entry.ExternalAttributes -shr 16) -band 0xf000)
            if ($unixType -eq 0xa000) {
                throw "ZIP symbolic links are prohibited: '$name'"
            }
            if ($entry.Length -gt 536870912) {
                throw "ZIP member exceeds the 512 MiB smoke-test limit: '$name'"
            }
            $totalLength += $entry.Length
            if ($totalLength -gt 1073741824) {
                throw "ZIP expands beyond the 1 GiB smoke-test limit"
            }

            $target = Join-Path $Destination ($name.Replace('/', '\'))
            Assert-DescendantPath $target $Destination 'ZIP member'
            $parent = Split-Path -Parent $target
            [void](New-Item -ItemType Directory -Path $parent -Force)
            $input = $entry.Open()
            $output = $null
            try {
                $output = [System.IO.File]::Open(
                    $target,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None)
                $input.CopyTo($output)
            }
            finally {
                if ($null -ne $output) { $output.Dispose() }
                $input.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
    }

    $rootFiles = @(Get-ChildItem -LiteralPath $Destination -Force -File)
    $rootDirectories = @(Get-ChildItem -LiteralPath $Destination -Force -Directory)
    if ($rootFiles.Count -ne 0 -or $rootDirectories.Count -ne 1) {
        throw "ZIP must contain exactly one top-level package directory"
    }
    return $rootDirectories[0].FullName
}

function Assert-ChecksumInventory([string] $Root) {
    $checksumPath = Join-Path $Root 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw "Package is missing SHA256SUMS"
    }
    $listed = @{}
    foreach ($line in @(Get-Content -LiteralPath $checksumPath)) {
        if ($line -notmatch '^([0-9a-f]{64})  (.+)$') {
            throw "Malformed SHA256SUMS line: '$line'"
        }
        $hash = $Matches[1]
        $relative = $Matches[2]
        Assert-SafeRelativePath $relative 'SHA256SUMS member'
        $key = $relative.ToLowerInvariant()
        if ($listed.ContainsKey($key)) {
            throw "Duplicate SHA256SUMS member: '$relative'"
        }
        $listed[$key] = [pscustomobject]@{ Path = $relative; Hash = $hash }
    }

    $actual = @((Get-SortedFiles $Root) | Where-Object { $_ -ne 'SHA256SUMS' })
    if ($listed.Count -ne $actual.Count) {
        throw "SHA256SUMS inventory count does not match package files"
    }
    foreach ($relative in $actual) {
        $key = $relative.ToLowerInvariant()
        if (-not $listed.ContainsKey($key)) {
            throw "SHA256SUMS does not inventory '$relative'"
        }
        $path = Join-Path $Root ($relative.Replace('/', '\'))
        $hash = Get-LowerSha256 $path
        if ($hash -cne $listed[$key].Hash) {
            throw "SHA256 mismatch for '$relative'"
        }
    }
}

function Assert-BuildPayload([string] $Root, [object] $Info) {
    $listed = @{}
    foreach ($item in @($Info.payload)) {
        $relative = [string]$item.path
        Assert-SafeRelativePath $relative 'BUILD_INFO payload member'
        $key = $relative.ToLowerInvariant()
        if ($listed.ContainsKey($key) -or
            [string]$item.sha256 -notmatch '^[0-9a-f]{64}$' -or
            [long]$item.size -lt 0) {
            throw "Malformed or duplicate BUILD_INFO payload member '$relative'"
        }
        $listed[$key] = $item
    }
    $actual = @((Get-SortedFiles $Root) | Where-Object {
        $_ -ne 'BUILD_INFO.json' -and $_ -ne 'SHA256SUMS'
    })
    if ($listed.Count -ne $actual.Count) {
        throw "BUILD_INFO payload count does not match installed payload"
    }
    foreach ($relative in $actual) {
        $key = $relative.ToLowerInvariant()
        if (-not $listed.ContainsKey($key)) {
            throw "BUILD_INFO does not inventory '$relative'"
        }
        $path = Join-Path $Root ($relative.Replace('/', '\'))
        $file = Get-Item -LiteralPath $path
        if ([long]$listed[$key].size -ne $file.Length -or
            [string]$listed[$key].sha256 -cne (Get-LowerSha256 $path)) {
            throw "BUILD_INFO payload metadata does not match '$relative'"
        }
    }
}

$inputPath = Get-FullPath $PackagePath
if (-not (Test-Path -LiteralPath $inputPath)) {
    throw "Package path does not exist: '$inputPath'"
}

$temporaryRoot = $null
$packageRoot = $null
try {
    if (Test-Path -LiteralPath $inputPath -PathType Container) {
        $packageRoot = $inputPath
    }
    elseif ([System.IO.Path]::GetExtension($inputPath) -ieq '.zip' -or
            $inputPath.EndsWith('.zip.partial', [System.StringComparison]::OrdinalIgnoreCase)) {
        $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('abct-release-smoke-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $temporaryRoot)
        $packageRoot = Expand-SafePackage $inputPath $temporaryRoot
    }
    else {
        throw "PackagePath must be a release directory or ZIP"
    }

    $reparse = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force | Where-Object {
        ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    })
    if ($reparse.Count -ne 0) {
        throw "Package directories and files must not contain reparse points"
    }

    $requiredFiles = @(
        'BUILD_INFO.json',
        'SHA256SUMS',
        'README.md',
        'LICENSE',
        'THIRD_PARTY_NOTICES.md',
        'licenses/HIDAPI-BSD-3-Clause.txt',
        'licenses/USBPcap-BSD-2-Clause.txt',
        'docs/INSTALLATION.md',
        'docs/USER_GUIDE.md',
        'docs/PRIVACY.md',
        'docs/ARCHITECTURE.md',
        'docs/DATA_CONTRACT.md',
        'docs/FAILURE_POLICY.md',
        'docs/TESTING.md',
        'docs/RESEARCH_EXPORT.md',
        'media/README.md',
        'media/sfx/README.txt'
    )
    foreach ($relative in $requiredFiles) {
        $path = Join-Path $packageRoot ($relative.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Package is missing required file '$relative'"
        }
    }

    $info = Get-Content -LiteralPath (Join-Path $packageRoot 'BUILD_INFO.json') -Raw | ConvertFrom-Json
    if ([string]$info.schema -cne 'abcurves.release.build.v1' -or
        [string]$info.product -cne 'ABCurves Capture Trainer' -or
        [string]$info.platform -cne 'windows-x64' -or
        [string]$info.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$' -or
        [int]$info.protocol -le 0 -or
        [string]$info.source.id -match '\s' -or
        [string]$info.source.tree_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "BUILD_INFO.json has an invalid release identity"
    }

    $participant = Get-Artifact $info 'participant_app' $true
    $capture = Get-Artifact $info 'capture_helper' $true
    $session = Get-Artifact $info 'session_tool' $true
    $research = Get-Artifact $info 'research_exporter' $true
    $probe = Get-Artifact $info 'probe_helper' $RequireProbeHelper.IsPresent
    if ($participant -cne 'ABCurves Capture Trainer.exe' -or
        $capture -cne 'abct_capture_helper.exe' -or
        $session -cne 'abct_session_tool.exe' -or
        $research -cne 'abct_research_export.exe' -or
        ($null -ne $probe -and $probe -cne 'abct_probe_helper.exe')) {
        throw "Release executable filenames do not match the public layout"
    }

    $artifactNames = @($participant, $capture, $session, $research)
    if ($null -ne $probe) { $artifactNames += $probe }
    $artifactSet = @{}
    foreach ($name in $artifactNames) {
        Assert-LeafExecutable $name 'Artifact'
        $key = $name.ToLowerInvariant()
        if ($artifactSet.ContainsKey($key)) { throw "Duplicate release executable '$name'" }
        $artifactSet[$key] = $true
        $path = Join-Path $packageRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Package is missing executable '$name'"
        }
        Assert-X64Pe $path
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        if ($versionInfo.ProductName -cne 'ABCurves Capture Trainer' -or
            ($versionInfo.FileVersion -cne [string]$info.version -and
             $versionInfo.FileVersion -cne ([string]$info.version + '.0'))) {
            throw "Windows version metadata does not match BUILD_INFO for '$name'"
        }
    }

    foreach ($relative in (Get-SortedFiles $packageRoot)) {
        if ($relative -match '(?i)(?:^|/)(?:tests?|CMakeFiles|_CPack_Packages|\.git)(?:/|$)' -or
            $relative -match '(?i)\.(?:obj|lib|exp|pdb|ilk|idb|tlog|lastbuildstate)$' -or
            $relative -match '(?i)(?:^|/)(?:CMakeCache\.txt|cmake_install\.cmake|CTestTestfile\.cmake)$') {
            throw "Package contains build or test debris: '$relative'"
        }
        if ([System.IO.Path]::GetExtension($relative) -ieq '.exe' -and
            -not $artifactSet.ContainsKey(([System.IO.Path]::GetFileName($relative)).ToLowerInvariant())) {
            throw "Package contains an unexpected executable: '$relative'"
        }
    }

    Assert-ChecksumInventory $packageRoot
    Assert-BuildPayload $packageRoot $info

    Assert-VersionCommand (Join-Path $packageRoot $capture) 'abct_capture_helper' ([string]$info.version) ([int]$info.protocol) ([string]$info.source.id)
    Assert-VersionCommand (Join-Path $packageRoot $session) 'abct_session_tool' ([string]$info.version) ([int]$info.protocol) ([string]$info.source.id)
    Assert-VersionCommand (Join-Path $packageRoot $research) 'abct_research_export' ([string]$info.version) ([int]$info.protocol) ([string]$info.source.id)
    if ($null -ne $probe) {
        Assert-VersionCommand (Join-Path $packageRoot $probe) 'abct_probe_helper' ([string]$info.version) ([int]$info.protocol) ([string]$info.source.id)
    }

    $usage = Invoke-Captured (Join-Path $packageRoot $session) @()
    if ($usage.ExitCode -ne 64 -or
        $usage.Text -notmatch 'ABCurves session tool' -or
        $usage.Text -notmatch 'validate <session-directory-or-zip>') {
        throw "abct_session_tool usage smoke check failed"
    }

    if ($null -ne $temporaryRoot) {
        $expectedRoot = "ABCurves-Capture-Trainer-$($info.version)-windows-x64"
        if ((Split-Path -Leaf $packageRoot) -cne $expectedRoot) {
            throw "ZIP root name does not match BUILD_INFO version"
        }
    }

    Write-Host "PASS release=$([string]$info.version) source=$([string]$info.source.id) files=$((Get-SortedFiles $packageRoot).Count)"
}
finally {
    if ($null -ne $temporaryRoot) {
        if ($KeepExtracted) {
            Write-Host "EXTRACTED $temporaryRoot"
        }
        elseif (Test-Path -LiteralPath $temporaryRoot) {
            $tempBase = Get-FullPath ([System.IO.Path]::GetTempPath())
            Assert-DescendantPath $temporaryRoot $tempBase 'Temporary extraction directory'
            # A just-exited native process or an antivirus scanner can retain
            # the extracted EXE for a few milliseconds. Cleanup is bounded and
            # never broadens beyond the GUID-owned temporary directory.
            for ($attempt = 1; $attempt -le 20; ++$attempt) {
                try {
                    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
                    break
                }
                catch {
                    if ($attempt -eq 20) { throw }
                    Start-Sleep -Milliseconds 100
                }
            }
        }
    }
}
