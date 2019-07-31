param([String]$VersionPrefix="1.0.0", [String]$VersionSuffix="") #Must be the first statement in your script

$scriptDir = Split-Path $myinvocation.mycommand.path -Parent
$root = Split-Path $scriptDir -Parent

## Prefix the suffix with a dash if set.
if($VersionSuffix) {
    $VersionSuffixPath = "-" + $VersionSuffix
}

# Check for confirmation
Write-Host "This will call setVersion, pack and publish both projects to nuget."
Write-Host -background yellow -foreground black "Version: $VersionPrefix$VersionSuffixPath"
$confirmation = Read-Host "Are you Sure You Want To Proceed [y]"
if ($confirmation -ne 'y') {exit}

# proceed
& (join-path $scriptDir "setVersion.ps1") -VersionPrefix $VersionPrefix -VersionSuffix $VersionSuffix
& (join-path $scriptDir "buildRelease.ps1")
#& (join-path $scriptDir "packRelease.ps1")

if ($? -eq $false) {
    write-host -background DarkBlue -foreground Red "<Error Exit>"
    exit 1 
}

$target1 = Join-Path $root "Src\Fido2\bin\Release\Fido2.$VersionPrefix$VersionSuffixPath.nupkg"
$target2 = Join-Path $root "Src\Fido2.Models\bin\Release\Fido2.Models.$VersionPrefix$VersionSuffixPath.nupkg"

if (
    ((Test-Path $target1) -eq $false) -Or ((Test-Path $target2) -eq $false)) {
    write-host -background DarkBlue -foreground Red "Could not locate nupkg"
    Write-Host "Path1 $target1"
    Write-Host "Path2 $target2"

    exit 1 
}

Write-Host "Ready to publish $target1"
Write-Host "Ready to publish $target2"
Write-Host -background yellow -foreground black "Version: $VersionPrefix$VersionSuffixPath"

$confirmation = Read-Host "Are you Sure You Want To Proceed (y)"
if ($confirmation -ne 'y') {exit}
& (join-path $scriptDir "publish.ps1") -path $target2
& (join-path $scriptDir "publish.ps1") -path $target1


Write-Host "Done. Update to $VersionPrefix $VersionSuffix and published to nuget."