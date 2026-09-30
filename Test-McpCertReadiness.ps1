<#
.SYNOPSIS
    Checks an MCP server certification package against the documented Microsoft
    requirements before you submit it in Partner Center.

.DESCRIPTION
    Every requirement on "Microsoft MCP server certification overview (preview)"
    that can be verified mechanically, verified mechanically:

      * package completeness   manifest, tool file, intro file, icons
      * manifest schema        v1.30, not the retired devPreview shape
      * connector wiring       remoteMcpServer endpoint, tool file, authorization block
      * referenceId hygiene    a Key Vault URI, never a secret URI
      * ASCII only             manifest and tool file, reported with line and column
      * vault state            (-CheckVault) secrets present with exact casing,
                               RBAC authorization on, and the certification service
                               principal holding a read role

    Source: https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-certification

.PARAMETER PackagePath
    Folder holding manifest.json and its companions.

.PARAMETER ManifestName
    Manifest file name. Defaults to manifest.json.

.PARAMETER IdentityProvider
    Which secret set to require in the vault. OAuth2, OAuth2Refresh, OAuth2Scopes or AzureAD.

.PARAMETER CheckVault
    Also inspect the live Key Vault named by the manifest's referenceId. Needs the Az
    modules and a Connect-AzAccount session.

.PARAMETER VaultName
    Override the vault name instead of deriving it from referenceId.

.EXAMPLE
    ./Test-McpCertReadiness.ps1 -PackagePath ./samples/good-package

.EXAMPLE
    ./Test-McpCertReadiness.ps1 -PackagePath ./package -IdentityProvider AzureAD -CheckVault

.NOTES
    Exits 0 when nothing failed, 1 when anything failed. Warnings do not fail the run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $PackagePath,

    [string] $ManifestName = 'manifest.json',

    [ValidateSet('OAuth2', 'OAuth2Refresh', 'OAuth2Scopes', 'AzureAD')]
    [string] $IdentityProvider = 'OAuth2',

    [switch] $CheckVault,

    [string] $VaultName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The Microsoft certification service application. A constant you copy, not one you generate.
$script:CertServiceAppId = '8e91e74f-afe9-41cd-8c3f-17a9562a74ea'
$script:RequiredSchemaVersion = '1.30'

# Required Key Vault secrets per identity provider, exactly as the article's table lists them.
$script:SecretMatrix = @{
    OAuth2        = @('ClientId', 'ClientSecret', 'AuthorizationUrl', 'TokenUrl')
    OAuth2Refresh = @('ClientId', 'ClientSecret', 'AuthorizationUrl', 'TokenUrl', 'RefreshUrl')
    OAuth2Scopes  = @('ClientId', 'ClientSecret', 'AuthorizationUrl', 'TokenUrl', 'Scopes')
    AzureAD       = @('ClientId', 'ClientSecret', 'TokenUrl', 'AzureActiveDirectoryResourceId')
}

$script:Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string] $Area,
        [Parameter(Mandatory)][string] $Check,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Warn', 'Skip')][string] $Status,
        [string] $Detail = ''
    )
    $script:Results.Add([pscustomobject]@{
            Area   = $Area
            Check  = $Check
            Status = $Status
            Detail = $Detail
        })
}

function Test-AsciiOnly {
    <#
      The article is explicit: Microsoft supports ASCII header names and values only in the
      manifest and tool definition files, and non-ASCII characters might cause validation
      failures. A smart quote pasted out of an email is the usual culprit, so report exactly
      where it is rather than just saying the file is bad.
    #>
    param([Parameter(Mandatory)][string] $Path)

    $lines = [System.IO.File]::ReadAllLines($Path)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        for ($c = 0; $c -lt $line.Length; $c++) {
            if ([int][char]$line[$c] -gt 127) {
                return [pscustomobject]@{
                    Clean  = $false
                    Line   = $i + 1
                    Column = $c + 1
                    Char   = $line[$c]
                    Code   = 'U+{0:X4}' -f [int][char]$line[$c]
                }
            }
        }
    }
    return [pscustomobject]@{ Clean = $true }
}

function Get-PngInfo {
    param([Parameter(Mandatory)][string] $Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 24) { return [pscustomobject]@{ Valid = $false } }

    $signature = @(137, 80, 78, 71, 13, 10, 26, 10)
    for ($i = 0; $i -lt 8; $i++) {
        if ($bytes[$i] -ne $signature[$i]) { return [pscustomobject]@{ Valid = $false } }
    }

    # IHDR width and height are big-endian at offsets 16 and 20.
    $width = [int]$bytes[16] * 16777216 + [int]$bytes[17] * 65536 + [int]$bytes[18] * 256 + [int]$bytes[19]
    $height = [int]$bytes[20] * 16777216 + [int]$bytes[21] * 65536 + [int]$bytes[22] * 256 + [int]$bytes[23]
    return [pscustomobject]@{ Valid = $true; Width = $width; Height = $height }
}

function Get-JsonProperty {
    # Safe nested lookup so a missing branch reports as missing instead of throwing under StrictMode.
    param([Parameter(Mandatory)] $Object, [Parameter(Mandatory)][string] $Path)

    $current = $Object
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        if ($current.PSObject.Properties.Name -notcontains $segment) { return $null }
        $current = $current.$segment
    }
    return $current
}

# ---------------------------------------------------------------- package layout

if (-not (Test-Path -LiteralPath $PackagePath -PathType Container)) {
    throw "Package path not found: $PackagePath"
}
$PackagePath = (Resolve-Path -LiteralPath $PackagePath).Path
Write-Verbose "Package: $PackagePath"

$manifestPath = Join-Path $PackagePath $ManifestName
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    Add-Result 'Package' "manifest present ($ManifestName)" 'Pass'
}
else {
    Add-Result 'Package' "manifest present ($ManifestName)" 'Fail' 'not found'
    $script:Results | Format-Table -AutoSize
    exit 1
}

try {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Add-Result 'Package' 'manifest parses as JSON' 'Pass'
}
catch {
    Add-Result 'Package' 'manifest parses as JSON' 'Fail' $_.Exception.Message
    $script:Results | Format-Table -AutoSize
    exit 1
}

# intro file: the What's changing table calls it required, the section heading below it says
# optional. Warn rather than fail, and say why.
$introPath = @('intro.md', 'Readme.md', 'README.md') |
    ForEach-Object { Join-Path $PackagePath $_ } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1

if ($introPath) {
    Add-Result 'Package' 'intro file present' 'Pass' (Split-Path $introPath -Leaf)
    if ((Get-Content -LiteralPath $introPath -Raw) -match '(?im)^\s*#{1,6}\s*Known issues') {
        Add-Result 'Package' 'intro has Known issues section' 'Pass'
    }
    else {
        Add-Result 'Package' 'intro has Known issues section' 'Warn' 'article recommends one'
    }
}
else {
    Add-Result 'Package' 'intro file present' 'Warn' 'docs disagree on required vs optional; include it'
}

# ---------------------------------------------------------------- schema version

$schema = Get-JsonProperty $manifest '$schema'
if ($schema -and $schema -match [regex]::Escape("/teams/v$script:RequiredSchemaVersion/")) {
    Add-Result 'Schema' '$schema points at v1.30' 'Pass'
}
elseif ($schema -match 'vDevPreview') {
    Add-Result 'Schema' '$schema points at v1.30' 'Fail' 'still on the retired vDevPreview schema'
}
else {
    Add-Result 'Schema' '$schema points at v1.30' 'Fail' "found: $schema"
}

if ($manifest.PSObject.Properties.Name -contains 'manifestVersion') {
    Add-Result 'Schema' 'manifestVersion removed' 'Fail' 'replaced by version in the v1.30 shape'
}
else {
    Add-Result 'Schema' 'manifestVersion removed' 'Pass'
}

$version = Get-JsonProperty $manifest 'version'
if ($version -eq $script:RequiredSchemaVersion) {
    Add-Result 'Schema' "version is $script:RequiredSchemaVersion" 'Pass'
}
else {
    Add-Result 'Schema' "version is $script:RequiredSchemaVersion" 'Fail' "found: $version"
}

# ---------------------------------------------------------------- required metadata

$requiredFields = @(
    'id'
    'developer.name'
    'developer.websiteUrl'
    'developer.privacyUrl'
    'developer.termsOfUseUrl'
    'name.short'
    'name.full'
    'description.short'
    'description.full'
    'icons.outline'
    'icons.color'
    'accentColor'
)
foreach ($field in $requiredFields) {
    $value = Get-JsonProperty $manifest $field
    if ([string]::IsNullOrWhiteSpace([string]$value)) {
        Add-Result 'Metadata' $field 'Fail' 'missing or empty'
    }
    elseif ([string]$value -match '^<.*>$') {
        Add-Result 'Metadata' $field 'Fail' "placeholder left in: $value"
    }
    else {
        Add-Result 'Metadata' $field 'Pass'
    }
}

# ---------------------------------------------------------------- icons

foreach ($slot in @('outline', 'color')) {
    $iconName = Get-JsonProperty $manifest "icons.$slot"
    if ([string]::IsNullOrWhiteSpace([string]$iconName)) { continue }

    $iconPath = Join-Path $PackagePath $iconName
    if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) {
        Add-Result 'Icons' "$slot icon on disk" 'Fail' "$iconName not found"
        continue
    }

    $png = Get-PngInfo $iconPath
    if ($png.Valid) {
        # Teams package guidance governs the exact sizes; report them rather than assert them.
        Add-Result 'Icons' "$slot icon on disk" 'Pass' "$iconName $($png.Width)x$($png.Height)"
    }
    else {
        Add-Result 'Icons' "$slot icon on disk" 'Fail' "$iconName is not a valid PNG"
    }
}

# ---------------------------------------------------------------- connector wiring

$connectors = Get-JsonProperty $manifest 'agentConnectors'
$referenceId = $null

if (-not $connectors -or @($connectors).Count -eq 0) {
    Add-Result 'Connector' 'agentConnectors present' 'Fail' 'none declared'
}
else {
    Add-Result 'Connector' 'agentConnectors present' 'Pass' "$(@($connectors).Count) declared"

    foreach ($connector in @($connectors)) {
        $label = Get-JsonProperty $connector 'id'
        if ([string]::IsNullOrWhiteSpace([string]$label)) { $label = '(unnamed)' }

        $serverUrl = Get-JsonProperty $connector 'toolSource.remoteMcpServer.mcpServerUrl'
        if ([string]::IsNullOrWhiteSpace([string]$serverUrl)) {
            Add-Result 'Connector' "[$label] mcpServerUrl" 'Fail' 'missing'
        }
        elseif ([string]$serverUrl -notmatch '^https://') {
            Add-Result 'Connector' "[$label] mcpServerUrl" 'Fail' 'must be https'
        }
        else {
            Add-Result 'Connector' "[$label] mcpServerUrl" 'Pass'
        }

        $toolFile = Get-JsonProperty $connector 'toolSource.remoteMcpServer.mcpToolDescription.file'
        if ([string]::IsNullOrWhiteSpace([string]$toolFile)) {
            Add-Result 'Connector' "[$label] tool file declared" 'Fail' 'mcpToolDescription.file missing'
        }
        else {
            $toolPath = Join-Path $PackagePath $toolFile
            if (Test-Path -LiteralPath $toolPath -PathType Leaf) {
                try {
                    Get-Content -LiteralPath $toolPath -Raw | ConvertFrom-Json | Out-Null
                    Add-Result 'Connector' "[$label] tool file on disk" 'Pass' $toolFile
                }
                catch {
                    Add-Result 'Connector' "[$label] tool file on disk" 'Fail' "$toolFile is not valid JSON"
                }

                $ascii = Test-AsciiOnly $toolPath
                if ($ascii.Clean) {
                    Add-Result 'Ascii' "$toolFile ASCII only" 'Pass'
                }
                else {
                    Add-Result 'Ascii' "$toolFile ASCII only" 'Fail' "$($ascii.Code) at line $($ascii.Line) col $($ascii.Column)"
                }
            }
            else {
                Add-Result 'Connector' "[$label] tool file on disk" 'Fail' "$toolFile not found"
            }
        }

        $authType = Get-JsonProperty $connector 'toolSource.remoteMcpServer.authorization.type'
        if ($authType -eq 'AzureKeyVault') {
            Add-Result 'Connector' "[$label] authorization.type" 'Pass' 'AzureKeyVault'
        }
        else {
            Add-Result 'Connector' "[$label] authorization.type" 'Fail' "expected AzureKeyVault, found: $authType"
        }

        $ref = Get-JsonProperty $connector 'toolSource.remoteMcpServer.authorization.referenceId'
        if ([string]::IsNullOrWhiteSpace([string]$ref)) {
            Add-Result 'Connector' "[$label] referenceId" 'Fail' 'missing'
        }
        elseif ([string]$ref -match '/secrets/') {
            # The article calls this out twice. It is the single most repeated warning on the page.
            Add-Result 'Connector' "[$label] referenceId is a vault URI" 'Fail' 'this is a SECRET URI, use the vault URI'
        }
        elseif ([string]$ref -match '^https://[A-Za-z0-9-]+\.vault\.azure\.net/?$') {
            Add-Result 'Connector' "[$label] referenceId is a vault URI" 'Pass' $ref
            if (-not $referenceId) { $referenceId = [string]$ref }
        }
        else {
            Add-Result 'Connector' "[$label] referenceId is a vault URI" 'Fail' "not a vault URI: $ref"
        }
    }
}

# ---------------------------------------------------------------- ascii on the manifest

$manifestAscii = Test-AsciiOnly $manifestPath
if ($manifestAscii.Clean) {
    Add-Result 'Ascii' "$ManifestName ASCII only" 'Pass'
}
else {
    Add-Result 'Ascii' "$ManifestName ASCII only" 'Fail' `
        "$($manifestAscii.Code) at line $($manifestAscii.Line) col $($manifestAscii.Column)"
}

# ---------------------------------------------------------------- live vault

if ($CheckVault) {
    if (-not $VaultName -and $referenceId) {
        $VaultName = ([uri]$referenceId).Host.Split('.')[0]
    }

    if (-not $VaultName) {
        Add-Result 'Vault' 'vault identified' 'Skip' 'no usable referenceId and no -VaultName'
    }
    elseif (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
        Add-Result 'Vault' 'Az.KeyVault available' 'Skip' 'module not installed'
    }
    else {
        try {
            $vault = Get-AzKeyVault -VaultName $VaultName -ErrorAction Stop
        }
        catch {
            $vault = $null
        }

        if (-not $vault) {
            Add-Result 'Vault' "vault $VaultName reachable" 'Fail' 'not found, or not signed in'
        }
        else {
            Add-Result 'Vault' "vault $VaultName reachable" 'Pass'

            # An RBAC role assignment grants nothing on a vault still running access policies.
            if ($vault.EnableRbacAuthorization) {
                Add-Result 'Vault' 'RBAC authorization enabled' 'Pass'
            }
            else {
                Add-Result 'Vault' 'RBAC authorization enabled' 'Fail' `
                    'legacy access policies; Update-AzKeyVault -DisableRbacAuthorization $false'
            }

            $required = $script:SecretMatrix[$IdentityProvider]
            try {
                $actual = (Get-AzKeyVaultSecret -VaultName $VaultName -ErrorAction Stop).Name
            }
            catch {
                $actual = @()
                Add-Result 'Vault' 'secrets readable' 'Fail' $_.Exception.Message
            }

            foreach ($name in $required) {
                # Case sensitive on purpose. The article has a whole FAQ entry about it.
                if ($actual -ccontains $name) {
                    Add-Result 'Secrets' $name 'Pass'
                }
                elseif ($actual -contains $name) {
                    $found = $actual | Where-Object { $_ -eq $name } | Select-Object -First 1
                    Add-Result 'Secrets' $name 'Fail' "wrong case: found '$found'"
                }
                else {
                    Add-Result 'Secrets' $name 'Fail' "missing (required for $IdentityProvider)"
                }
            }

            if (Get-Module -ListAvailable -Name Az.Resources) {
                try {
                    $sp = Get-AzADServicePrincipal -ApplicationId $script:CertServiceAppId -ErrorAction Stop
                }
                catch {
                    $sp = $null
                }

                if (-not $sp) {
                    Add-Result 'Rbac' 'certification service principal exists' 'Fail' `
                        "New-AzADServicePrincipal -ApplicationId $script:CertServiceAppId"
                }
                else {
                    Add-Result 'Rbac' 'certification service principal exists' 'Pass'
                    $assignment = Get-AzRoleAssignment -ObjectId $sp.Id -Scope $vault.ResourceId -ErrorAction SilentlyContinue |
                        Where-Object { $_.RoleDefinitionName -in @('Key Vault Secrets User', 'Key Vault Secrets Officer', 'Key Vault Administrator') }

                    if ($assignment) {
                        Add-Result 'Rbac' 'service principal can read secrets' 'Pass' `
                            (@($assignment).RoleDefinitionName -join ', ')
                    }
                    else {
                        Add-Result 'Rbac' 'service principal can read secrets' 'Fail' `
                            'no Key Vault read role on this vault'
                    }
                }
            }
            else {
                Add-Result 'Rbac' 'Az.Resources available' 'Skip' 'module not installed'
            }
        }
    }
}
else {
    Add-Result 'Vault' 'live vault checks' 'Skip' 'pass -CheckVault to run them'
}

# ---------------------------------------------------------------- report

Write-Host ''
Write-Host "MCP certification readiness: $PackagePath" -ForegroundColor Cyan
Write-Host ''

foreach ($row in $script:Results) {
    $color = switch ($row.Status) {
        'Pass' { 'Green' }
        'Fail' { 'Red' }
        'Warn' { 'Yellow' }
        default { 'DarkGray' }
    }
    $line = '{0,-6} {1,-10} {2}' -f $row.Status.ToUpper(), $row.Area, $row.Check
    if ($row.Detail) { $line += "  ($($row.Detail))" }
    Write-Host $line -ForegroundColor $color
}

$failed = @($script:Results | Where-Object Status -eq 'Fail').Count
$warned = @($script:Results | Where-Object Status -eq 'Warn').Count
$passed = @($script:Results | Where-Object Status -eq 'Pass').Count

Write-Host ''
Write-Host "$passed passed, $failed failed, $warned warnings" -ForegroundColor Cyan

if ($failed -gt 0) {
    Write-Host 'Not ready to submit.' -ForegroundColor Red
    exit 1
}

Write-Host 'Ready to submit.' -ForegroundColor Green
exit 0
