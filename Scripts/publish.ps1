param(
    [Parameter(Mandatory=$true)]
    [System.IO.FileInfo]
    [String] $path) #Must be the first statement in your script

# if ($nupkgPath -eq "") {
#     $scriptDir = Split-Path $myinvocation.mycommand.path -Parent
#     $root = Split-Path $scriptDir -Parent
#     $target = Join-Path $root "Src" | Join-Path -ChildPath "bin" | Join-Path -ChildPath "release"
    
#     Write-Error "No nupkg path supplied"
#     Write-Host "nupkgs found in release folder $target\:"
#     $files = Get-ChildItem $target -Filter *.nupkg
#     Write-Host $files
#     exit 1
# }

$path2 = $path;

$path = Resolve-Path $path
if($path2 -ne $path) {
Write-Host "Resolved $path2 -> $path"
}
Write-Host "Publishing $path..."
Start-Sleep 2
dotnet nuget push $path --source https://api.nuget.org/v3/index.json

Write-Host "Done $path..."