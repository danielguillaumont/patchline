# One-command Windows PowerShell 5.1 entry point for the isolated synthetic demo.
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 5173
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$runner = Join-Path $repo "apps\web\scripts\serve-demo.mjs"

if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "Demo runner missing: $runner"
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js 22 or newer is required."
}
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    throw "uv is required. Install uv, then retry."
}

Push-Location -LiteralPath $repo
try {
    & node $runner --port $Port
    if ($LASTEXITCODE -ne 0) {
        throw "Patchline demo stopped with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
