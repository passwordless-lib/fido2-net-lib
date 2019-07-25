param([String]$VersionPrefix="1.0.0", [String]$VersionSuffix="") #Must be the first statement in your script

$scriptDir = Split-Path $myinvocation.mycommand.path -Parent
$root = Split-Path $scriptDir -Parent

## Prefix the suffix with a dash if set.
if($VersionSuffix) {
    $VersionSuffixPath = "-" + $VersionSuffix
}

$target1 = Join-Path $root "Src\bin\Release\Fido2.$VersionPrefix$VersionSuffixPath.nupkg"
$target2 = Join-Path $root "Models\bin\Release\Fido2.Models.$VersionPrefix$VersionSuffixPath.nupkg"

#Write-Host $target1

# Check for confirmation
$confirmation = Read-Host "This will call setVersion, pack and publish both projects to nuget.  Are you Sure You Want To Proceed [y]"
if ($confirmation -ne 'y') {exit}

# proceed
& (join-path $scriptDir "setVersion.ps1") -VersionPrefix $VersionPrefix -VersionSuffix $VersionSuffix
& (join-path $scriptDir "packRelease.ps1")
& (join-path $scriptDir "packReleaseModels.ps1")

if ($? -eq $false) {
    write-host -background DarkBlue -foreground Red "<Error Exit>"
    exit 1 
}

Write-Host "Ready to publish $target1"
Write-Host "Ready to publish $target2"
$confirmation = Read-Host "Are you Sure You Want To Proceed (y)"
if ($confirmation -ne 'y') {exit}
& (join-path $scriptDir "publishModels.ps1") $target2
& (join-path $scriptDir "publish.ps1") $target1


Write-Host "Done. Update to $VersionPrefix $VersionSuffix and published to nuget."