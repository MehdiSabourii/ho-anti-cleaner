# Packaging Script for WordPress Plugin

$PluginDir = "G:\ho-anti\ho-anti-cleaner"
$ZipFile = "G:\ho-anti\ho-anti-cleaner.zip"

Write-Host "Packaging ho-anti-cleaner..."

if (Test-Path $ZipFile) {
    Remove-Item -Force $ZipFile
}

Compress-Archive -Path $PluginDir -DestinationPath $ZipFile -Force

$item = Get-Item $ZipFile
Write-Host "Success! Created package: $($item.FullName) ($([math]::Round($item.Length/1KB, 1)) KB)"
