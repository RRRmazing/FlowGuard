$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$dependencyRoot = Join-Path $projectRoot 'third_party'
$archive = Join-Path $dependencyRoot 'npcap-sdk-1.17.zip'
$sdkRoot = Join-Path $dependencyRoot 'npcap-sdk'
New-Item -ItemType Directory -Path $dependencyRoot -Force | Out-Null
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-sdk-1.17.zip' -OutFile $archive -TimeoutSec 60
}
$expectedHash = 'AB7E1A6CB8D07427E0071EC11BE380BD9D2BB19AE6AB3F5EDE0698C301638258'
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'SDK archive differs from the stage 0 download. Check the official source before proceeding.'
}
Expand-Archive -LiteralPath $archive -DestinationPath $sdkRoot -Force
Write-Host "Npcap SDK ready: $sdkRoot"
