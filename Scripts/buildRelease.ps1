$scriptDir = Split-Path $myinvocation.mycommand.path -Parent
$root = Split-Path $scriptDir -Parent
$target1 = Join-Path $root "Src" | Join-Path -ChildPath "Fido2NetLib.csproj"
$target2 = Join-Path $root "Models" | Join-Path -ChildPath "Fido2NetLib.Models.csproj"
Write-Host "Building $target1"
dotnet build -c Release $target1 $args
dotnet build -c Release $target2 $args