#!/usr/bin/env pwsh
# Common PowerShell functions analogous to common.sh

# Find repository root by searching upward for .specify directory
# This is the primary marker for spec-kit projects
function Find-SpecifyRoot {
    param([string]$StartDir = (Get-Location).Path)

    # Normalize to absolute path to prevent issues with relative paths
    # Use -LiteralPath to handle paths with wildcard characters ([, ], *, ?)
    $resolved = Resolve-Path -LiteralPath $StartDir -ErrorAction SilentlyContinue
    $current = if ($resolved) { $resolved.Path } else { $null }
    if (-not $current) { return $null }

    while ($true) {
        $marker = Join-Path $current ".specify"
        if (Test-Path -LiteralPath $marker -PathType Container) {
            $null = Resolve-SafeRepositoryPath -RepoRoot $current -Candidate $marker
            return $current
        }
        $parent = Split-Path $current -Parent
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) {
            return $null
        }
        $current = $parent
    }
}

# Resolve a repository-owned path without following a symlink/reparse point.
# Missing leaf paths are allowed only when their nearest existing parent is
# also a real, contained directory. Callers use this for both reads and writes.
function Resolve-SafeRepositoryPath {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Candidate,
        [switch]$AllowMissing
    )

    $rootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    $rootItem = Get-Item -LiteralPath $rootFull -Force -ErrorAction Stop
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "repository root must not be a symlink or reparse point: $RepoRoot"
    }
    $candidatePath = if ([System.IO.Path]::IsPathRooted($Candidate)) {
        $Candidate
    } else {
        Join-Path $rootFull $Candidate
    }
    $candidateFull = [System.IO.Path]::GetFullPath($candidatePath)
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $rootPrefix = $rootFull.TrimEnd($separator, [System.IO.Path]::AltDirectorySeparatorChar) + $separator
    $comparison = if ($PSVersionTable.PSVersion.Major -lt 6 -or $separator -eq '\') {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    if ($candidateFull -ne $rootFull -and -not $candidateFull.StartsWith($rootPrefix, $comparison)) {
        throw "repository path escapes the project root: $Candidate"
    }

    $candidateExists = Test-Path -LiteralPath $candidateFull
    if ($candidateExists) {
        $candidateItem = Get-Item -LiteralPath $candidateFull -Force
        if (($candidateItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "repository path must not be a symlink or reparse point: $Candidate"
        }
    } elseif (-not $AllowMissing) {
        throw "repository path does not exist: $Candidate"
    }

    $probe = if ($candidateExists) { $candidateFull } else { Split-Path $candidateFull -Parent }
    while ($probe -and -not (Test-Path -LiteralPath $probe)) {
        $parent = Split-Path $probe -Parent
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $probe) { break }
        $probe = $parent
    }
    if ($probe -and (Test-Path -LiteralPath $probe)) {
        $probeItem = Get-Item -LiteralPath $probe -Force
        if (($probeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "repository path contains a symlinked or reparse-point parent: $Candidate"
        }
        $resolvedProbe = Resolve-Path -LiteralPath $probe -ErrorAction Stop
        $resolvedFull = [System.IO.Path]::GetFullPath($resolvedProbe.Path)
        if ($resolvedFull -ne $rootFull -and -not $resolvedFull.StartsWith($rootPrefix, $comparison)) {
            throw "repository path resolves outside the project root: $Candidate"
        }
        if ($candidateExists) {
            return $resolvedFull
        }
        return $candidateFull
    }
    if ($AllowMissing) { return $candidateFull }
    throw "repository path could not be resolved safely: $Candidate"
}

function Get-SafeExistingRepositoryPath {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Candidate
    )
    if (-not (Test-Path -LiteralPath $Candidate)) { return $null }
    return (Resolve-SafeRepositoryPath -RepoRoot $RepoRoot -Candidate $Candidate)
}

# Resolve an explicit SPECIFY_INIT_DIR project override (the directory that
# *contains* .specify/), for non-interactive / CI use -- e.g. running a Spec Kit
# command against a member project from a monorepo root without cd.
#
# Precondition: $env:SPECIFY_INIT_DIR is set. Returns the validated project root,
# or writes an error and exits 1. Strict by design: the path must exist and
# contain .specify/, with no silent fallback. (An empty string is falsy, so the
# caller's `if ($env:SPECIFY_INIT_DIR)` guard treats empty as unset.)
#
# This is the single resolver: bundled extensions inherit it by sourcing core
# (e.g. the git extension's create-new-feature-branch) rather than duplicating it.
function Resolve-SpecifyInitDir {
    $initDir = $env:SPECIFY_INIT_DIR
    # Normalize: relative paths resolve against the current directory.
    if (-not [System.IO.Path]::IsPathRooted($initDir)) {
        $initDir = Join-Path (Get-Location).Path $initDir
    }
    $resolved = Resolve-Path -LiteralPath $initDir -ErrorAction SilentlyContinue
    # Resolve-Path also succeeds for files, so check the resolved path is a
    # directory; otherwise a file value would slip through to the less accurate
    # "not a Spec Kit project" error below.
    if (-not $resolved -or -not (Test-Path -LiteralPath $resolved.Path -PathType Container)) {
        [Console]::Error.WriteLine("ERROR: SPECIFY_INIT_DIR does not point to an existing directory: $($env:SPECIFY_INIT_DIR)")
        exit 1
    }
    # Resolve-Path echoes back any trailing separator from the input; trim it so
    # the returned root matches the bash resolver, whose `cd && pwd` never yields
    # one. TrimEndingDirectorySeparator is a no-op on a bare root and on a path
    # that already has no trailing separator.
    $initRoot = [System.IO.Path]::TrimEndingDirectorySeparator($resolved.Path)
    if (-not (Test-Path -LiteralPath (Join-Path $initRoot '.specify') -PathType Container)) {
        [Console]::Error.WriteLine("ERROR: SPECIFY_INIT_DIR is not a Spec Kit project (no .specify/ directory): $initRoot")
        exit 1
    }
    $null = Resolve-SafeRepositoryPath -RepoRoot $initRoot -Candidate (Join-Path $initRoot '.specify')
    return $initRoot
}

# Get repository root, prioritizing .specify directory
# This prevents using a parent repository when spec-kit is initialized in a subdirectory
function Get-RepoRoot {
    # Explicit project override wins (see Resolve-SpecifyInitDir).
    if ($env:SPECIFY_INIT_DIR) {
        return (Resolve-SpecifyInitDir)
    }

    # First, look for .specify directory (spec-kit's own marker)
    $specifyRoot = Find-SpecifyRoot
    if ($specifyRoot) {
        return $specifyRoot
    }

    # Final fallback to script location
    # Use -LiteralPath to handle paths with wildcard characters
    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "../../..")).Path
}

function Get-CurrentBranch {
    # Return feature name from explicit state only.
    # Feature state is set by SPECIFY_FEATURE (from create-new-feature or
    # the git extension) or implicitly via .specify/feature.json.
    if ($env:SPECIFY_FEATURE) {
        return $env:SPECIFY_FEATURE
    }

    # No explicit feature set - return empty to signal "unknown".
    return ""
}

function Resolve-FeatureDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Candidate
    )

    $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    $specsRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRootFull 'specs'))
    $candidatePath = if ([System.IO.Path]::IsPathRooted($Candidate)) {
        $Candidate
    } else {
        Join-Path $repoRootFull $Candidate
    }
    $candidateFull = [System.IO.Path]::GetFullPath($candidatePath)
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $specsPrefix = $specsRoot.TrimEnd($separator, [System.IO.Path]::AltDirectorySeparatorChar) + $separator
    $isWindowsRuntime = if ($PSVersionTable.PSVersion.Major -lt 6) {
        $true
    } elseif (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
        [bool]$IsWindows
    } else {
        [System.IO.Path]::DirectorySeparatorChar -eq '\'
    }
    $comparison = if ($isWindowsRuntime) {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }

    if (-not $candidateFull.StartsWith($specsPrefix, $comparison)) {
        [Console]::Error.WriteLine("ERROR: feature directory must remain beneath the repository specs directory.")
        exit 1
    }

    # Resolve the existing path or nearest existing ancestor so symlink escapes
    # are rejected before any downstream command creates or writes files.
    $probe = $candidateFull
    while (-not (Test-Path -LiteralPath $probe -PathType Container)) {
        $parent = Split-Path -Path $probe -Parent
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $probe) { break }
        $probe = $parent
    }
    $resolvedProbe = Resolve-Path -LiteralPath $probe -ErrorAction SilentlyContinue
    if (-not $resolvedProbe) {
        [Console]::Error.WriteLine("ERROR: feature directory parent cannot be resolved safely.")
        exit 1
    }
    $resolvedProbeFull = [System.IO.Path]::GetFullPath($resolvedProbe.Path)
    $safeUncreatedSpecsRoot = $resolvedProbeFull -eq $repoRootFull -and -not (Test-Path -LiteralPath $specsRoot)
    if (-not $resolvedProbeFull.StartsWith($specsPrefix, $comparison) -and $resolvedProbeFull -ne $specsRoot -and -not $safeUncreatedSpecsRoot) {
        [Console]::Error.WriteLine("ERROR: feature directory resolves outside the repository specs directory.")
        exit 1
    }

    if (Test-Path -LiteralPath $candidateFull -PathType Container) {
        $resolvedCandidate = Resolve-Path -LiteralPath $candidateFull -ErrorAction SilentlyContinue
        if (-not $resolvedCandidate) {
            [Console]::Error.WriteLine("ERROR: feature directory cannot be resolved safely.")
            exit 1
        }
        $resolvedCandidateFull = [System.IO.Path]::GetFullPath($resolvedCandidate.Path)
        if (-not $resolvedCandidateFull.StartsWith($specsPrefix, $comparison)) {
            [Console]::Error.WriteLine("ERROR: feature directory resolves outside the repository specs directory.")
            exit 1
        }
        return $resolvedCandidateFull
    }

    return $candidateFull
}



# Persist a feature_directory value to .specify/feature.json.
# Writes only when the file is missing or the value differs from what's stored.
function Save-FeatureJson {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$FeatureDirectory
    )

    $repoRootFull = [System.IO.Path]::GetFullPath($RepoRoot)
    $FeatureDirectory = Resolve-FeatureDirectory -RepoRoot $repoRootFull -Candidate $FeatureDirectory
    $FeatureDirectory = $FeatureDirectory.Substring($repoRootFull.Length).TrimStart('\', '/')

    $fjPath = Join-Path (Join-Path $RepoRoot '.specify') 'feature.json'
    $null = Resolve-SafeRepositoryPath -RepoRoot $repoRootFull -Candidate $fjPath -AllowMissing

    # Read current value and skip write when unchanged
    if (Test-Path -LiteralPath $fjPath -PathType Leaf) {
        try {
            $raw = Get-Content -LiteralPath $fjPath -Raw
            $cfg = $raw | ConvertFrom-Json
            if ($cfg.feature_directory -eq $FeatureDirectory) {
                return
            }
        } catch {
            # File is corrupt or unreadable - overwrite it
        }
    }

    # Ensure .specify/ directory exists
    $specifyDir = Join-Path $RepoRoot '.specify'
    if (-not (Test-Path -LiteralPath $specifyDir -PathType Container)) {
        New-Item -ItemType Directory -Path $specifyDir -Force | Out-Null
    }

    # Write feature.json
    $json = @{ feature_directory = $FeatureDirectory } | ConvertTo-Json -Compress
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($fjPath, $json, $utf8NoBom)
}

function Get-FeaturePathsEnv {
    $repoRoot = Get-RepoRoot
    $currentBranch = Get-CurrentBranch

    # Resolve feature directory.  Priority:
    #   1. SPECIFY_FEATURE_DIRECTORY env var (explicit override)
    #   2. .specify/feature.json "feature_directory" key (persisted by specify command)
    #   3. Error - no feature context available
    $featureJson = Join-Path $repoRoot '.specify/feature.json'
    $safeFeatureJson = Get-SafeExistingRepositoryPath -RepoRoot $repoRoot -Candidate $featureJson
    if ($env:SPECIFY_FEATURE_DIRECTORY) {
        $featureDir = Resolve-FeatureDirectory -RepoRoot $repoRoot -Candidate $env:SPECIFY_FEATURE_DIRECTORY
        # Persist to feature.json so future sessions without the env var still work
        Save-FeatureJson -RepoRoot $repoRoot -FeatureDirectory $featureDir
    } elseif ($safeFeatureJson) {
        $featureJsonRaw = Get-Content -LiteralPath $safeFeatureJson -Raw
        try {
            $featureConfig = $featureJsonRaw | ConvertFrom-Json
        } catch {
            [Console]::Error.WriteLine("ERROR: Failed to parse .specify/feature.json: $_")
            exit 1
        }
        if ($featureConfig.feature_directory) {
            $featureDir = Resolve-FeatureDirectory -RepoRoot $repoRoot -Candidate $featureConfig.feature_directory
        } else {
            [Console]::Error.WriteLine("ERROR: Feature directory not found. Set SPECIFY_FEATURE_DIRECTORY or ensure .specify/feature.json contains feature_directory.")
            exit 1
        }
    } else {
        [Console]::Error.WriteLine("ERROR: Feature directory not found. Set SPECIFY_FEATURE_DIRECTORY or run the specify command to create .specify/feature.json.")
        exit 1
    }

    [PSCustomObject]@{
        REPO_ROOT     = $repoRoot
        CURRENT_BRANCH = $currentBranch
        FEATURE_DIR   = $featureDir
        FEATURE_SPEC  = Join-Path $featureDir 'spec.md'
        IMPL_PLAN     = Join-Path $featureDir 'plan.md'
        TASKS         = Join-Path $featureDir 'tasks.md'
        RESEARCH      = Join-Path $featureDir 'research.md'
        DATA_MODEL    = Join-Path $featureDir 'data-model.md'
        QUICKSTART    = Join-Path $featureDir 'quickstart.md'
        CONTRACTS_DIR = Join-Path $featureDir 'contracts'
    }
}

function Test-FileExists {
    param([string]$Path, [string]$Description)
    if (Test-Path -Path $Path -PathType Leaf) {
        Write-Output "  [OK] $Description"
        return $true
    } else {
        Write-Output "  [FAIL] $Description"
        return $false
    }
}

function Test-DirHasFiles {
    param([string]$Path, [string]$Description)
    if ((Test-Path -Path $Path -PathType Container) -and (Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Select-Object -First 1)) {
        Write-Output "  [OK] $Description"
        return $true
    } else {
        Write-Output "  [FAIL] $Description"
        return $false
    }
}

function Get-InvokeSeparator {
    param([string]$RepoRoot = (Get-RepoRoot))

    if ($null -eq $script:SpecKitInvokeSeparatorCache) {
        $script:SpecKitInvokeSeparatorCache = @{}
    }
    if ($script:SpecKitInvokeSeparatorCache.ContainsKey($RepoRoot)) {
        return $script:SpecKitInvokeSeparatorCache[$RepoRoot]
    }

    $separator = '.'
    $integrationJson = Join-Path $RepoRoot '.specify/integration.json'
    if (Test-Path -LiteralPath $integrationJson -PathType Leaf) {
        try {
            $state = Get-Content -LiteralPath $integrationJson -Raw | ConvertFrom-Json
            $key = if ($state.default_integration) { [string]$state.default_integration } elseif ($state.integration) { [string]$state.integration } else { '' }
            if ($key -and $state.integration_settings) {
                $settingProperty = $state.integration_settings.PSObject.Properties[$key]
                if ($settingProperty) {
                    $setting = $settingProperty.Value
                    if ($setting -and ($setting.invoke_separator -eq '.' -or $setting.invoke_separator -eq '-')) {
                        $separator = [string]$setting.invoke_separator
                    }
                }
            }
        } catch {
            $separator = '.'
        }
    }

    $script:SpecKitInvokeSeparatorCache[$RepoRoot] = $separator
    return $separator
}

function Format-SpecKitCommand {
    param(
        [Parameter(Mandatory = $true)][string]$CommandName,
        [string]$RepoRoot = (Get-RepoRoot)
    )

    $separator = Get-InvokeSeparator -RepoRoot $RepoRoot
    $name = $CommandName.TrimStart('/')
    if ($name.StartsWith('speckit.')) {
        $name = $name.Substring(8)
    } elseif ($name.StartsWith('speckit-')) {
        $name = $name.Substring(8)
    }
    $name = $name -replace '\.', $separator

    return "/speckit$separator$name"
}

# Find a usable Python 3 executable (python3, python, or py -3).
# Returns the command/arguments as an array, or $null if none found.
function Get-Python3Command {
    if (Get-Command python3 -ErrorAction SilentlyContinue) { return @('python3') }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $ver = & python --version 2>&1
        if ($ver -match 'Python 3') { return @('python') }
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $ver = & py -3 --version 2>&1
        if ($ver -match 'Python 3') { return @('py', '-3') }
    }
    return $null
}

# Resolve a template name to a file path using the priority stack:
#   1. .specify/templates/overrides/
#   2. .specify/presets/<preset-id>/templates/ (sorted by priority from .registry)
#   3. .specify/extensions/<ext-id>/templates/
#   4. .specify/templates/ (core)
function Resolve-Template {
    param(
        [Parameter(Mandatory=$true)][string]$TemplateName,
        [Parameter(Mandatory=$true)][string]$RepoRoot
    )

    $base = Join-Path $RepoRoot '.specify/templates'
    $null = Resolve-SafeRepositoryPath -RepoRoot $RepoRoot -Candidate $base -AllowMissing

    # Priority 1: Project overrides
    $override = Join-Path $base "overrides/$TemplateName.md"
    $safeOverride = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $override
    if ($safeOverride) { return $safeOverride }

    # Priority 2: Installed presets (sorted by priority from .registry)
    $presetsDir = Join-Path $RepoRoot '.specify/presets'
    $safePresetsDir = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $presetsDir
    if ($safePresetsDir) {
        $presetsDir = $safePresetsDir
        $registryFile = Join-Path $presetsDir '.registry'
        $safeRegistryFile = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $registryFile
        $sortedPresets = @()
        if ($safeRegistryFile) {
            try {
                $registryData = Get-Content $safeRegistryFile -Raw | ConvertFrom-Json
                $presets = $registryData.presets
                if ($presets) {
                    $sortedPresets = $presets.PSObject.Properties |
                        Where-Object { $null -eq $_.Value.enabled -or $_.Value.enabled -ne $false } |
                        Sort-Object { if ($null -ne $_.Value.priority) { $_.Value.priority } else { 10 } } |
                        ForEach-Object { $_.Name }
                }
            } catch {
                # Fallback: alphabetical directory order
                $sortedPresets = @()
            }
        }

        if ($sortedPresets.Count -gt 0) {
            foreach ($presetId in $sortedPresets) {
                $candidate = Join-Path $presetsDir "$presetId/templates/$TemplateName.md"
                $safeCandidate = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $candidate
                if ($safeCandidate) { return $safeCandidate }
            }
        } else {
            # Fallback: alphabetical directory order
            foreach ($preset in Get-ChildItem -Path $presetsDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' }) {
                $candidate = Join-Path $preset.FullName "templates/$TemplateName.md"
                $safeCandidate = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $candidate
                if ($safeCandidate) { return $safeCandidate }
            }
        }
    }

    # Priority 3: Extension-provided templates
    $extDir = Join-Path $RepoRoot '.specify/extensions'
    $safeExtDir = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $extDir
    if ($safeExtDir) {
        foreach ($ext in Get-ChildItem -LiteralPath $safeExtDir -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' } | Sort-Object Name) {
            $candidate = Join-Path $ext.FullName "templates/$TemplateName.md"
            $safeCandidate = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $candidate
            if ($safeCandidate) { return $safeCandidate }
        }
    }

    # Priority 4: Core templates
    $core = Join-Path $base "$TemplateName.md"
    $safeCore = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $core
    if ($safeCore) { return $safeCore }

    return $null
}

# Resolve a template name to composed content using composition strategies.
# Reads strategy metadata from preset manifests and composes content
# from multiple layers using prepend, append, or wrap strategies.
function Resolve-TemplateContent {
    param(
        [Parameter(Mandatory=$true)][string]$TemplateName,
        [Parameter(Mandatory=$true)][string]$RepoRoot
    )

    $base = Join-Path $RepoRoot '.specify/templates'
    $null = Resolve-SafeRepositoryPath -RepoRoot $RepoRoot -Candidate $base -AllowMissing

    # Collect all layers (highest priority first)
    $layerPaths = @()
    $layerStrategies = @()

    # Priority 1: Project overrides (always "replace")
    $override = Join-Path $base "overrides/$TemplateName.md"
    $safeOverride = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $override
    if ($safeOverride) {
        $layerPaths += $safeOverride
        $layerStrategies += 'replace'
    }

    # Priority 2: Installed presets (sorted by priority from .registry)
    $presetsDir = Join-Path $RepoRoot '.specify/presets'
    $safePresetsDir = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $presetsDir
    if ($safePresetsDir) {
        $presetsDir = $safePresetsDir
        $registryFile = Join-Path $presetsDir '.registry'
        $safeRegistryFile = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $registryFile
        $sortedPresets = @()
        if ($safeRegistryFile) {
            try {
                $registryData = Get-Content $safeRegistryFile -Raw | ConvertFrom-Json
                $presets = $registryData.presets
                if ($presets) {
                    $sortedPresets = $presets.PSObject.Properties |
                        Where-Object { $null -eq $_.Value.enabled -or $_.Value.enabled -ne $false } |
                        Sort-Object { if ($null -ne $_.Value.priority) { $_.Value.priority } else { 10 } } |
                        ForEach-Object { $_.Name }
                }
            } catch {
                $sortedPresets = @()
            }
        }

        if ($sortedPresets.Count -gt 0) {
            $pyCmd = Get-Python3Command
            if (-not $pyCmd) {
                # Check if any preset has strategy fields that would be ignored
                foreach ($pid in $sortedPresets) {
                    $mf = Join-Path $presetsDir "$pid/preset.yml"
                    $safeManifest = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $mf
                    if ($safeManifest -and (Select-String -LiteralPath $safeManifest -Pattern 'strategy:' -Quiet -ErrorAction SilentlyContinue)) {
                        Write-Warning "No Python 3 found; preset composition strategies will be ignored"
                        break
                    }
                }
            }
            $yamlWarned = $false
            foreach ($presetId in $sortedPresets) {
                # Read strategy and file path from preset manifest
                $strategy = 'replace'
                $manifestFilePath = ''
                $manifest = Join-Path $presetsDir "$presetId/preset.yml"
                $safeManifest = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $manifest
                if ($safeManifest -and $pyCmd) {
                    try {
                        # Use Python to parse YAML manifest for strategy and file path
                        $pyArgs = if ($pyCmd.Count -gt 1) { $pyCmd[1..($pyCmd.Count-1)] } else { @() }
                        $pyStderrFile = [System.IO.Path]::GetTempFileName()
                        $stratResult = & $pyCmd[0] @pyArgs -c @"
import sys
try:
    import yaml
except ImportError:
    print('yaml_missing', file=sys.stderr)
    print('replace\t')
    sys.exit(0)
try:
    with open(sys.argv[1]) as f:
        data = yaml.safe_load(f)
    for t in data.get('provides', {}).get('templates', []):
        if t.get('name') == sys.argv[2] and t.get('type', 'template') == 'template':
            print(t.get('strategy', 'replace') + '\t' + t.get('file', ''))
            sys.exit(0)
    print('replace\t')
except Exception:
    print('replace\t')
"@ $safeManifest $TemplateName 2>$pyStderrFile
                        if ($stratResult) {
                            $parts = $stratResult.Trim() -split "`t", 2
                            $strategy = $parts[0].ToLowerInvariant()
                            if ($parts.Count -gt 1 -and $parts[1]) { $manifestFilePath = $parts[1] }
                        }
                        if (-not $yamlWarned -and (Test-Path -LiteralPath $pyStderrFile) -and (Get-Content -LiteralPath $pyStderrFile -Raw -ErrorAction SilentlyContinue) -match 'yaml_missing') {
                            Write-Warning "PyYAML not available; composition strategies may be ignored"
                            $yamlWarned = $true
                        }
                        Remove-Item $pyStderrFile -Force -ErrorAction SilentlyContinue
                    } catch {
                        $strategy = 'replace'
                        if ($pyStderrFile) { Remove-Item $pyStderrFile -Force -ErrorAction SilentlyContinue }
                    }
                }
                # Try manifest file path first, then convention path
                $candidate = $null
                if ($manifestFilePath) {
                    # Reject absolute paths and parent traversal
                    if ([System.IO.Path]::IsPathRooted($manifestFilePath) -or $manifestFilePath -match '\.\.[\\/]') {
                        $manifestFilePath = ''
                    }
                }
                if ($manifestFilePath) {
                    $mf = Join-Path $presetsDir "$presetId/$manifestFilePath"
                    $safeCandidate = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $mf
                    if ($safeCandidate) { $candidate = $safeCandidate }
                }
                if (-not $candidate) {
                    $cf = Join-Path $presetsDir "$presetId/templates/$TemplateName.md"
                    $safeCandidate = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $cf
                    if ($safeCandidate) { $candidate = $safeCandidate }
                }
                if ($candidate) {
                    $layerPaths += $candidate
                    $layerStrategies += $strategy
                }
            }
        } else {
            # Fallback: alphabetical directory order (no registry or parse failure)
            foreach ($preset in Get-ChildItem -LiteralPath $presetsDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' }) {
                $candidate = Join-Path $preset.FullName "templates/$TemplateName.md"
                $safeCandidate = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $candidate
                if ($safeCandidate) {
                    $layerPaths += $safeCandidate
                    $layerStrategies += 'replace'
                }
            }
        }
    }

    # Priority 3: Extension-provided templates (always "replace")
    $extDir = Join-Path $RepoRoot '.specify/extensions'
    $safeExtDir = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $extDir
    if ($safeExtDir) {
        foreach ($ext in Get-ChildItem -LiteralPath $safeExtDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' } | Sort-Object Name) {
            $candidate = Join-Path $ext.FullName "templates/$TemplateName.md"
            $safeCandidate = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $candidate
            if ($safeCandidate) {
                $layerPaths += $safeCandidate
                $layerStrategies += 'replace'
            }
        }
    }

    # Priority 4: Core templates (always "replace")
    $core = Join-Path $base "$TemplateName.md"
    $safeCore = Get-SafeExistingRepositoryPath -RepoRoot $RepoRoot -Candidate $core
    if ($safeCore) {
        $layerPaths += $safeCore
        $layerStrategies += 'replace'
    }

    if ($layerPaths.Count -eq 0) { return $null }

    # If the top (highest-priority) layer is replace, it wins entirely --
    # lower layers are irrelevant regardless of their strategies.
    if ($layerStrategies[0] -eq 'replace') {
        return (Get-Content $layerPaths[0] -Raw)
    }

    # Check if any layer uses a non-replace strategy
    $hasComposition = $false
    foreach ($s in $layerStrategies) {
        if ($s -ne 'replace') { $hasComposition = $true; break }
    }

    if (-not $hasComposition) {
        return (Get-Content $layerPaths[0] -Raw)
    }

    # Find the effective base: scan from highest priority (index 0) downward
    # to find the nearest replace layer. Only compose layers above that base.
    $baseIdx = -1
    for ($i = 0; $i -lt $layerPaths.Count; $i++) {
        if ($layerStrategies[$i] -eq 'replace') {
            $baseIdx = $i
            break
        }
    }
    if ($baseIdx -lt 0) { return $null }

    $content = Get-Content $layerPaths[$baseIdx] -Raw

    for ($i = $baseIdx - 1; $i -ge 0; $i--) {
        $path = $layerPaths[$i]
        $strat = $layerStrategies[$i]
        $layerContent = Get-Content $path -Raw

        switch ($strat) {
            'replace' { $content = $layerContent }
            'prepend' { $content = "$layerContent`n`n$content" }
            'append'  { $content = "$content`n`n$layerContent" }
            'wrap'    {
                if (-not $layerContent.Contains('{CORE_TEMPLATE}')) {
                    throw "Wrap strategy missing {CORE_TEMPLATE} placeholder"
                }
                $content = $layerContent.Replace('{CORE_TEMPLATE}', $content)
            }
            default { throw "Unknown strategy: $strat" }
        }
    }

    return $content
}
