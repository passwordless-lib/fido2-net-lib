$scriptDir = Split-Path $myinvocation.mycommand.path -Parent
$root = Split-Path $scriptDir -Parent
$target = Join-Path $root "Src" | Join-Path -ChildPath "Fido2NetLib.csproj"
Write-Host "Packing $target"
dotnet pack -c Release $target