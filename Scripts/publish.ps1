param([String]$nupkgPath="") #Must be the first statement in your script

$scriptDir = Split-Path $myinvocation.mycommand.path -Parent
$root = Split-Path $scriptDir -Parent
$target = Join-Path $root "Src" | Join-Path -ChildPath "bin" | Join-Path -ChildPath "release"

if ($nupkgPath -eq "") {
    Write-Error "No nupkg path supplied"
    Write-Host "nupkgs found in release folder $target\:"
    $files = Get-ChildItem $target -Filter *.nupkg
    Write-Host $files
    exit 1
}

Write-Host "Publishing $nupkgPath..."
Start-Sleep 2
nuget push $nupkgPath -Source https://api.nuget.org/v3/index.json