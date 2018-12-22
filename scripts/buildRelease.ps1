$scriptDir = Split-Path $myinvocation.mycommand.path -Parent
$root = Split-Path $scriptDir -Parent
$target = Join-Path $root "fido2-net-lib" | Join-Path -ChildPath "Fido2NetLib.csproj"
Write-Host "Building $target"
dotnet build -c Release $target