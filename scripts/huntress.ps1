# Run the workspace client without installing packages or changing shell settings.
$ErrorActionPreference = 'Stop'
$robotRoot = Split-Path -Parent $PSScriptRoot
$robotPython = Join-Path $robotRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $robotPython -PathType Leaf)) {
    $robotPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
}
if (-not (Test-Path -LiteralPath $robotPython -PathType Leaf)) {
    $robotCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $robotCommand -or $robotCommand.Source -like '*\WindowsApps\*') {
        throw 'A working Python 3.10+ executable is required. Create .venv first; see docs/USAGE.md.'
    }
    $robotPython = $robotCommand.Source
}
$robotPreviousPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $robotRoot 'src'
    if ($robotPreviousPath) {
        $env:PYTHONPATH += [IO.Path]::PathSeparator + $robotPreviousPath
    }
    & $robotPython -m huntress_ctf @args
    $robotExitCode = $LASTEXITCODE
}
finally {
    $env:PYTHONPATH = $robotPreviousPath
}
exit $robotExitCode
