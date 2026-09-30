<#
.SYNOPSIS
    Proves the checker works, in both directions.

.DESCRIPTION
    A checker that only ever says "pass" is worse than no checker, so this runs the
    good package and expects a clean exit, then runs the deliberately broken package
    and expects specific failures by name. If a check silently stops working, the
    broken package goes green and this run fails.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$checker = Join-Path $root 'Test-McpCertReadiness.ps1'
$failures = 0

function Assert-Condition {
    param([string] $Name, [bool] $Condition, [string] $Detail = '')
    if ($Condition) {
        Write-Host "  PASS  $Name" -ForegroundColor Green
    }
    else {
        Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red
        $script:failures++
    }
}

# ---------------------------------------------------------------- good package

Write-Host ''
Write-Host 'good-package should be clean' -ForegroundColor Cyan
$goodOut = & pwsh -NoProfile -File $checker -PackagePath (Join-Path $root 'samples/good-package') 2>&1
$goodExit = $LASTEXITCODE
$goodText = $goodOut -join "`n"

Assert-Condition 'exit code is 0' ($goodExit -eq 0) "(got $goodExit)"
Assert-Condition 'reports Ready to submit' ($goodText -match 'Ready to submit')
Assert-Condition 'no FAIL lines' ($goodText -notmatch '(?m)^FAIL')

# ---------------------------------------------------------------- bad package

Write-Host ''
Write-Host 'bad-package should be caught' -ForegroundColor Cyan
$badOut = & pwsh -NoProfile -File $checker -PackagePath (Join-Path $root 'samples/bad-package') 2>&1
$badExit = $LASTEXITCODE
$badText = $badOut -join "`n"

Assert-Condition 'exit code is 1' ($badExit -eq 1) "(got $badExit)"
Assert-Condition 'reports Not ready to submit' ($badText -match 'Not ready to submit')

# Each defect planted in samples/bad-package must be named in the output. These are the
# assertions that would catch a check quietly regressing to always-pass.
$expected = @{
    'retired vDevPreview schema'   = 'vDevPreview'
    'manifestVersion still present' = 'manifestVersion removed'
    'version is not 1.30'          = 'found: 1\.0\.0'
    'placeholder left in metadata' = 'placeholder left in'
    'secret URI in referenceId'    = 'this is a SECRET URI'
    'missing tool file'            = 'mcptools\.json not found'
    'missing icons'                = 'Outline\.png not found'
    'non-ASCII character located'  = 'U\+2019 at line 18 col 55'
}

foreach ($name in $expected.Keys | Sort-Object) {
    Assert-Condition "detects: $name" ($badText -match $expected[$name])
}

# ---------------------------------------------------------------- result

Write-Host ''
if ($failures -eq 0) {
    Write-Host 'All tests passed.' -ForegroundColor Green
    exit 0
}

Write-Host "$failures test(s) failed." -ForegroundColor Red
exit 1
