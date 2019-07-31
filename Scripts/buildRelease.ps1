$scriptDir = Split-Path $myinvocation.mycommand.path -Parent
$root = Split-Path $scriptDir -Parent
$target = Join-Path $root "fido2-net-lib.sln"
Write-Host "Building $target"
dotnet build -c Release $target $args