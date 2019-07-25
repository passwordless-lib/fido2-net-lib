$scriptDir = Split-Path $myinvocation.mycommand.path -Parent
$root = Split-Path $scriptDir -Parent

$target = Join-Path $root "Models" | Join-Path -ChildPath "Fido2NetLib.Models.csproj"

Write-Host "Packing $target"

dotnet pack -c Release $target