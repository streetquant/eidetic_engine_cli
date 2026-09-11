<#
.SYNOPSIS
Materialize ee's sibling path dependencies at their exact locked revisions.

.DESCRIPTION
Reads franken-stack.lock, prepares every sibling checkout in a private staging
root, validates the complete bundle, and publishes the prepared directories only
after all checks pass. Existing clean managed checkouts are reused. This helper
never rewrites a sibling Cargo.toml or overwrites an unrelated checkout.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DestinationRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$KnownRepositories = @(
    "asupersync",
    "franken_agent_detection",
    "franken_networkx",
    "frankensearch",
    "frankensqlite",
    "sqlmodel_rust",
    "toon_rust"
)
$StagingMarkerName = "ee-franken-stack-staging-v1"
$ManagedMarkerName = "ee-franken-stack-managed"

function Invoke-Git {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & git @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Invoke-GitCaptureResult {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $savedNativePreference = $false
    $nativePreference = Get-Variable -Name PSNativeCommandUseErrorActionPreference `
        -ErrorAction SilentlyContinue
    if ($null -ne $nativePreference) {
        $savedNativePreference = $PSNativeCommandUseErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $false
    }
    try {
        $output = & git @Arguments 2>$null
        $exitCode = $LASTEXITCODE
    } finally {
        if ($null -ne $nativePreference) {
            $PSNativeCommandUseErrorActionPreference = $savedNativePreference
        }
    }

    return [pscustomobject]@{
        Success = ($exitCode -eq 0)
        Output = (($output | Out-String).Trim())
    }
}

function Test-ReparsePoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return $false
    }
    return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Assert-NoSymlinkComponents {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $current = [IO.Path]::GetFullPath($Path)
    while ($true) {
        if (Test-ReparsePoint -Path $current) {
            throw "$current is a symlink or reparse point; refusing to modify it"
        }
        $root = [IO.Path]::GetPathRoot($current)
        if ($current -eq $root) {
            break
        }
        $parent = [IO.Directory]::GetParent($current)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) {
            break
        }
        $current = $parent
    }
}

function Test-OriginMatches {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedUrl,
        [Parameter(Mandatory = $true)]
        [string]$ActualUrl
    )

    $accepted = @(
        $ExpectedUrl,
        $ExpectedUrl.Substring(0, $ExpectedUrl.Length - 4),
        "git@github.com:Dicklesworthstone/$Repository.git"
    )
    return $accepted -contains $ActualUrl
}

function Test-CheckoutIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$Revision,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedUrl
    )

    $actualRevision = Invoke-GitCaptureResult -Arguments @(
        "-C", $Destination, "rev-parse", "HEAD"
    )
    if (-not $actualRevision.Success -or $actualRevision.Output -ne $Revision) {
        return $false
    }

    $actualUrl = Invoke-GitCaptureResult -Arguments @(
        "-C", $Destination, "remote", "get-url", "origin"
    )
    return $actualUrl.Success -and (Test-OriginMatches -Repository $Repository `
        -ExpectedUrl $ExpectedUrl -ActualUrl $actualUrl.Output)
}

function Test-CleanCheckout {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$Revision,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedUrl
    )

    if (-not (Test-CheckoutIdentity -Repository $Repository -Revision $Revision `
            -Destination $Destination -ExpectedUrl $ExpectedUrl)) {
        return $false
    }

    $status = Invoke-GitCaptureResult -Arguments @(
        "-C", $Destination, "-c", "core.longpaths=true",
        "status", "--porcelain", "--untracked-files=normal"
    )
    return $status.Success -and [string]::IsNullOrEmpty($status.Output)
}

function Write-AtomicText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [string]$Contents
    )

    if (Test-ReparsePoint -Path $Destination) {
        throw "$Destination is a symlink or reparse point; refusing to replace it"
    }
    if (Test-Path -LiteralPath $Destination) {
        throw "$Destination already exists; refusing to replace it"
    }

    $temporary = "$Destination.tmp.$([guid]::NewGuid().ToString('N'))"
    $encoding = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false
    try {
        [IO.File]::WriteAllText($temporary, $Contents, $encoding)
        $stream = $null
        try {
            $stream = [IO.File]::Open($temporary, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $stream.Flush($true)
        } finally {
            if ($null -ne $stream) {
                $stream.Dispose()
            }
        }
        [IO.File]::Move($temporary, $Destination)
    } finally {
        if ([IO.File]::Exists($temporary)) {
            [IO.File]::Delete($temporary)
        }
    }
}

function Get-StagingMarkerContents {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$Revision,
        [Parameter(Mandatory = $true)]
        [string]$RepositoryUrl
    )

    return "$StagingMarkerName`nrepository=$Repository`nrevision=$Revision`norigin=$RepositoryUrl"
}

function Get-ManagedMarkerContents {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$Revision
    )

    return "$Repository`t$Revision"
}

function Assert-StagingMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$Revision,
        [Parameter(Mandatory = $true)]
        [string]$RepositoryUrl
    )

    $marker = Join-Path $Stage ".git\$StagingMarkerName"
    if (Test-ReparsePoint -Path $marker) {
        throw "$marker is a symlink or reparse point; refusing to trust it"
    }
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw "$Stage has no staging attestation; refusing to resume it"
    }
    $actual = [IO.File]::ReadAllText($marker).Trim()
    $expected = Get-StagingMarkerContents -Repository $Repository -Revision $Revision `
        -RepositoryUrl $RepositoryUrl
    if ($actual -ne $expected) {
        throw "$Stage has an unexpected staging attestation; refusing to resume it"
    }
}

function Assert-StagingOrigin {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedUrl
    )

    $actual = Invoke-GitCaptureResult -Arguments @(
        "-C", $Stage, "remote", "get-url", "origin"
    )
    if (-not $actual.Success -or -not (Test-OriginMatches -Repository $Repository `
            -ExpectedUrl $ExpectedUrl -ActualUrl $actual.Output)) {
        throw "$Stage has unexpected origin; refusing to fetch from it"
    }
}

function Assert-StagingTree {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StagingRoot
    )

    if (Test-ReparsePoint -Path $StagingRoot) {
        throw "$StagingRoot is a symlink or reparse point; refusing to inspect it"
    }
    if (-not (Test-Path -LiteralPath $StagingRoot)) {
        return
    }
    if (-not (Test-Path -LiteralPath $StagingRoot -PathType Container)) {
        throw "$StagingRoot is not a directory"
    }

    foreach ($entry in @(Get-ChildItem -LiteralPath $StagingRoot -Force)) {
        if ($KnownRepositories -notcontains $entry.Name) {
            throw "$StagingRoot contains unknown staged tree: $($entry.Name)"
        }
        if ((Test-ReparsePoint -Path $entry.FullName) -or -not $entry.PSIsContainer) {
            throw "$($entry.FullName) is not a regular staged directory"
        }
    }
}

function Get-LockEntries {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LockFile
    )

    $entries = @()
    $seen = @{}
    foreach ($line in [IO.File]::ReadAllLines($LockFile)) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith("#")) {
            continue
        }
        $fields = $line.Split([char]"`t")
        if ($fields.Count -ne 2) {
            throw "malformed lock row: $line"
        }
        $repository = $fields[0]
        $revision = $fields[1]
        if ($KnownRepositories -notcontains $repository) {
            throw "unknown repository in lock: $repository"
        }
        if ($revision -notmatch '^[0-9a-f]{40}$') {
            throw "revision for $repository is not a full lowercase hexadecimal commit ID"
        }
        if ($seen.ContainsKey($repository)) {
            throw "duplicate repository in lock: $repository"
        }
        $seen[$repository] = $true
        $entries += [pscustomobject]@{ Repository = $repository; Revision = $revision }
    }

    if ($entries.Count -ne $KnownRepositories.Count) {
        throw "expected $($KnownRepositories.Count) locked repositories, found $($entries.Count)"
    }
    foreach ($required in $KnownRepositories) {
        if (-not $seen.ContainsKey($required)) {
            throw "required repository missing from lock: $required"
        }
    }
    return $entries
}

function Prepare-Repository {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$Revision,
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string]$StagingRoot
    )

    $destination = Join-Path $Root $Repository
    $stage = Join-Path $StagingRoot $Repository
    $repositoryUrl = "https://github.com/Dicklesworthstone/$Repository.git"

    if (Test-ReparsePoint -Path $destination) {
        throw "$destination is a symlink or reparse point; refusing to modify it"
    }
    if (Test-ReparsePoint -Path $stage) {
        throw "$stage is a symlink or reparse point; refusing to modify it"
    }

    if (Test-Path -LiteralPath $destination) {
        if (Test-Path -LiteralPath $stage) {
            throw "$destination and its resumable staging both exist; refusing to choose between them"
        }
        $gitDirectory = Join-Path $destination ".git"
        if ((Test-ReparsePoint -Path $gitDirectory) -or
            -not (Test-Path -LiteralPath $gitDirectory -PathType Container)) {
            throw "$destination already exists and is not a regular Git checkout"
        }
        $marker = Join-Path $gitDirectory $ManagedMarkerName
        if ((Test-ReparsePoint -Path $marker) -or
            -not (Test-Path -LiteralPath $marker -PathType Leaf)) {
            throw "$destination has no managed checkout marker; refusing to modify it"
        }
        $markerValue = [IO.File]::ReadAllText($marker).Trim()
        $expectedMarker = Get-ManagedMarkerContents -Repository $Repository -Revision $Revision
        if ($markerValue -ne $expectedMarker) {
            throw "$destination does not exactly match $Repository@$Revision; refusing to modify it"
        }
        $stagingMarker = Join-Path $gitDirectory $StagingMarkerName
        if (Test-Path -LiteralPath $stagingMarker) {
            Assert-StagingMarker -Stage $destination -Repository $Repository -Revision $Revision `
                -RepositoryUrl $repositoryUrl
        }
        if (-not (Test-CleanCheckout -Repository $Repository -Revision $Revision `
                -Destination $destination -ExpectedUrl $repositoryUrl)) {
            throw "$destination is dirty or has unexpected provenance; refusing to modify it"
        }
        Write-Host "franken-stack: reuse $Repository@$Revision"
        return $null
    }

    if (Test-Path -LiteralPath $StagingRoot) {
        if (Test-ReparsePoint -Path $StagingRoot) {
            throw "$StagingRoot is a symlink or reparse point; refusing to modify it"
        }
        if (-not (Test-Path -LiteralPath $StagingRoot -PathType Container)) {
            throw "$StagingRoot is not a directory"
        }
    } else {
        New-Item -ItemType Directory -Path $StagingRoot | Out-Null
    }

    if (Test-Path -LiteralPath $stage) {
        if (-not (Test-Path -LiteralPath $stage -PathType Container)) {
            throw "$stage is not a directory; refusing to resume it"
        }
        $gitDirectory = Join-Path $stage ".git"
        if ((Test-ReparsePoint -Path $gitDirectory) -or
            -not (Test-Path -LiteralPath $gitDirectory -PathType Container)) {
            throw "$stage has no regular Git metadata; refusing to resume it"
        }
        Assert-StagingMarker -Stage $stage -Repository $Repository -Revision $Revision `
            -RepositoryUrl $repositoryUrl
    } else {
        New-Item -ItemType Directory -Path $stage | Out-Null
        Invoke-Git -Arguments @("-C", $stage, "init", "-q")
        Invoke-Git -Arguments @("-C", $stage, "remote", "add", "origin", $repositoryUrl)
        Invoke-Git -Arguments @("-C", $stage, "config", "core.longpaths", "true")
        Write-AtomicText -Destination (Join-Path $stage ".git\$StagingMarkerName") `
            -Contents (Get-StagingMarkerContents -Repository $Repository -Revision $Revision `
                -RepositoryUrl $repositoryUrl)
    }

    $status = Invoke-GitCaptureResult -Arguments @(
        "-C", $stage, "status", "--porcelain", "--untracked-files=normal"
    )
    if (-not $status.Success) {
        throw "$stage is not a usable Git checkout; refusing to resume it"
    }
    if (-not [string]::IsNullOrEmpty($status.Output)) {
        throw "$stage has unknown local changes; refusing to overwrite staged files"
    }

    # Validate a resumed stage's configured origin before any fetch can use it.
    Assert-StagingOrigin -Repository $Repository -Stage $stage -ExpectedUrl $repositoryUrl
    if (-not (Test-CheckoutIdentity -Repository $Repository -Revision $Revision `
            -Destination $stage -ExpectedUrl $repositoryUrl)) {
        Invoke-Git -Arguments @("-C", $stage, "fetch", "--depth", "1", "origin", $Revision)
        Invoke-Git -Arguments @(
            "-C", $stage, "-c", "advice.detachedHead=false",
            "checkout", "--detach", "FETCH_HEAD"
        )
    }

    if (-not (Test-CleanCheckout -Repository $Repository -Revision $Revision `
            -Destination $stage -ExpectedUrl $repositoryUrl)) {
        throw "$Repository staging is dirty or has unexpected provenance after checkout"
    }
    $managedMarker = Join-Path $stage ".git\$ManagedMarkerName"
    if (Test-Path -LiteralPath $managedMarker) {
        if (Test-ReparsePoint -Path $managedMarker) {
            throw "$managedMarker is a symlink or reparse point; refusing to trust it"
        }
        $managedValue = [IO.File]::ReadAllText($managedMarker).Trim()
        $expectedManaged = Get-ManagedMarkerContents -Repository $Repository -Revision $Revision
        if ($managedValue -ne $expectedManaged) {
            throw "$stage has an unexpected managed checkout marker; refusing to resume it"
        }
    } else {
        Write-AtomicText -Destination $managedMarker -Contents (
            Get-ManagedMarkerContents -Repository $Repository -Revision $Revision)
    }

    Write-Host "franken-stack: staged $Repository@$Revision"
    return [pscustomobject]@{
        Repository = $Repository
        Revision = $Revision
        Stage = $stage
        Destination = $destination
    }
}

function Get-MaterializedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string]$StagingRoot
    )

    $destination = Join-Path $Root $Repository
    $stage = Join-Path $StagingRoot $Repository
    if (Test-Path -LiteralPath $destination -PathType Container) {
        return $destination
    }
    if (Test-Path -LiteralPath $stage -PathType Container) {
        return $stage
    }
    throw "missing materialized checkout for $Repository"
}

function Test-CargoCaretCompatible {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Requirement,
        [Parameter(Mandatory = $true)]
        [string]$LockedVersion
    )

    $normalized = $Requirement
    if ($normalized.StartsWith("^")) {
        $normalized = $normalized.Substring(1)
    }
    if ($normalized -notmatch '^([0-9]+)\.([0-9]+)\.([0-9]+)$') {
        return $false
    }
    $reqMajor = [int]$Matches[1]
    $reqMinor = [int]$Matches[2]
    $reqPatch = [int]$Matches[3]
    if ($LockedVersion -notmatch '^([0-9]+)\.([0-9]+)\.([0-9]+)$') {
        return $false
    }
    $lockedMajor = [int]$Matches[1]
    $lockedMinor = [int]$Matches[2]
    $lockedPatch = [int]$Matches[3]

    if ($reqMajor -eq 0) {
        if ($lockedMajor -ne 0 -or $lockedMinor -ne $reqMinor) {
            return $false
        }
        if ($reqMinor -eq 0) {
            return $lockedPatch -eq $reqPatch
        }
        return $lockedPatch -ge $reqPatch
    }
    if ($lockedMajor -ne $reqMajor) {
        return $false
    }
    if ($lockedMinor -gt $reqMinor) {
        return $true
    }
    return $lockedMinor -eq $reqMinor -and $lockedPatch -ge $reqPatch
}

function Assert-SqlmodelAsupersyncCompatibility {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AsupersyncRoot,
        [Parameter(Mandatory = $true)]
        [string]$SqlmodelRoot
    )

    $asuToml = Join-Path $AsupersyncRoot "Cargo.toml"
    $sqlToml = Join-Path $SqlmodelRoot "Cargo.toml"
    if (-not (Test-Path -LiteralPath $asuToml -PathType Leaf) -or
        -not (Test-Path -LiteralPath $sqlToml -PathType Leaf)) {
        throw "missing asupersync or SQLModel manifest after checkout"
    }

    $asuVersion = $null
    foreach ($line in [IO.File]::ReadAllLines($asuToml)) {
        if ($line -match '^\s*version\s*=\s*"([0-9][0-9.]*)"\s*$') {
            $asuVersion = $Matches[1]
            break
        }
    }
    if ([string]::IsNullOrEmpty($asuVersion)) {
        throw "could not determine the locked asupersync version"
    }

    $requirements = @()
    foreach ($line in [IO.File]::ReadAllLines($sqlToml)) {
        $dependencyLine = $line.Split([char]'#')[0]
        if ($dependencyLine -match '^\s*asupersync\s*=\s*"([^"]*)"\s*$') {
            $requirements += $Matches[1]
        } elseif ($dependencyLine -match '^\s*asupersync\s*=\s*\{(.*)\}\s*$') {
            $inlineTable = $Matches[1]
            if ($inlineTable -match '(^|[,\s])version\s*=\s*"([^"]*)"') {
                $requirements += $Matches[2]
            }
        }
    }
    if ($requirements.Count -gt 1) {
        throw "SQLModel has multiple asupersync requirements; refusing ambiguous materialization"
    }
    if ($requirements.Count -eq 0) {
        return
    }

    $requirement = $requirements[0]
    if ($requirement.StartsWith("=")) {
        if ($requirement.Substring(1) -ne $asuVersion) {
            throw "locked SQLModel requires asupersync $requirement but locked asupersync is $asuVersion; refusing to rewrite Cargo.toml"
        }
        Write-Host "franken-stack: verified SQLModel exact asupersync pin =$asuVersion"
        return
    }
    if ($requirement.StartsWith("^") -or $requirement -match '^[0-9]') {
        if (-not (Test-CargoCaretCompatible -Requirement $requirement -LockedVersion $asuVersion)) {
            throw "locked SQLModel requirement $requirement is incompatible with asupersync $asuVersion; refusing to rewrite Cargo.toml"
        }
        Write-Host "franken-stack: verified SQLModel asupersync requirement $requirement against $asuVersion"
        return
    }
    throw "locked SQLModel uses unsupported asupersync requirement $requirement; refusing to rewrite Cargo.toml"
}

function Remove-StagedWork {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Pending,
        [Parameter(Mandatory = $true)]
        [string]$StagingRoot
    )

    foreach ($entry in $Pending) {
        if (Test-Path -LiteralPath $entry.Stage) {
            if (Test-ReparsePoint -Path $entry.Stage) {
                throw "$($entry.Stage) became a symlink or reparse point during rollback"
            }
            [IO.Directory]::Delete($entry.Stage, $true)
        }
    }
    if (Test-Path -LiteralPath $StagingRoot) {
        $children = @(Get-ChildItem -LiteralPath $StagingRoot -Force)
        if ($children.Count -eq 0) {
            [IO.Directory]::Delete($StagingRoot)
        }
    }
}

function Publish-One {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Entry
    )

    if (Test-ReparsePoint -Path $Entry.Destination) {
        throw "$($Entry.Destination) is a symlink or reparse point; refusing to overwrite it"
    }
    if (Test-Path -LiteralPath $Entry.Destination) {
        throw "$($Entry.Destination) appeared while staging; refusing to overwrite it"
    }
    if (Test-ReparsePoint -Path $Entry.Stage) {
        throw "$($Entry.Stage) is a symlink or reparse point; refusing to publish it"
    }
    [IO.Directory]::Move($Entry.Stage, $Entry.Destination)
    Write-Host "franken-stack: checked out $($Entry.Repository)@$($Entry.Revision)"
}

function Undo-Published {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Published
    )

    for ($index = $Published.Count - 1; $index -ge 0; $index--) {
        $entry = $Published[$index]
        if ((Test-Path -LiteralPath $entry.Destination) -and
            -not (Test-Path -LiteralPath $entry.Stage)) {
            try {
                [IO.Directory]::Move($entry.Destination, $entry.Stage)
            } catch {
                Write-Error "could not roll back published $($entry.Repository): $($_.Exception.Message)"
            }
        }
    }
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required"
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$lockFile = Join-Path $repositoryRoot "franken-stack.lock"
if (-not (Test-Path -LiteralPath $lockFile -PathType Leaf)) {
    throw "missing lock file: $lockFile"
}

Assert-NoSymlinkComponents -Path $DestinationRoot
$resolvedRoot = [IO.Path]::GetFullPath($DestinationRoot)
$filesystemRoot = [IO.Path]::GetPathRoot($resolvedRoot)
if ($resolvedRoot.TrimEnd([char[]]@('\', '/')) -eq
    $filesystemRoot.TrimEnd([char[]]@('\', '/'))) {
    throw "refusing to populate the filesystem root"
}
New-Item -ItemType Directory -Force -Path $resolvedRoot | Out-Null
Assert-NoSymlinkComponents -Path $resolvedRoot
$resolvedRoot = (Get-Item -LiteralPath $resolvedRoot -Force).FullName

$stagingRoot = Join-Path $resolvedRoot ".ee-franken-stack-staging"
$lockPath = Join-Path $resolvedRoot ".ee-franken-stack-materializer.lock"
if (Test-ReparsePoint -Path $lockPath) {
    throw "$lockPath is a symlink or reparse point; refusing to modify it"
}
$lockStream = $null
while ($null -eq $lockStream) {
    try {
        $lockStream = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch [IO.IOException] {
        Start-Sleep -Milliseconds 100
    }
}

try {
    $lockEntries = Get-LockEntries -LockFile $lockFile
    Assert-StagingTree -StagingRoot $stagingRoot
    $pending = @()
    foreach ($entry in $lockEntries) {
        $prepared = Prepare-Repository -Repository $entry.Repository -Revision $entry.Revision `
            -Root $resolvedRoot -StagingRoot $stagingRoot
        if ($null -ne $prepared) {
            $pending += $prepared
        }
    }
    Assert-StagingTree -StagingRoot $stagingRoot

    # Bundle compatibility is a preflight over staged or reused paths. No final
    # destination rename occurs until this check succeeds.
    $preflightFailed = $true
    try {
        $asuPath = Get-MaterializedPath -Repository "asupersync" -Root $resolvedRoot `
            -StagingRoot $stagingRoot
        $sqlPath = Get-MaterializedPath -Repository "sqlmodel_rust" -Root $resolvedRoot `
            -StagingRoot $stagingRoot
        Assert-SqlmodelAsupersyncCompatibility -AsupersyncRoot $asuPath -SqlmodelRoot $sqlPath
        $preflightFailed = $false

        $published = @()
        try {
            foreach ($prepared in $pending) {
                Publish-One -Entry $prepared
                $published += $prepared
            }
        } catch {
            Undo-Published -Published $published
            throw
        }
    } catch {
        if ($preflightFailed) {
            Remove-StagedWork -Pending $pending -StagingRoot $stagingRoot
        }
        throw
    }
} finally {
    if ($null -ne $lockStream) {
        $lockStream.Dispose()
    }
}
