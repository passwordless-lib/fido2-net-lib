param([String]$VersionPrefix="1.0.0", [String]$VersionSuffix="") #Must be the first statement in your script

$scriptDir = Split-Path $myinvocation.mycommand.path -Parent
$root = Split-Path $scriptDir -Parent

$target1 = Join-Path $root "Directory.Build.props"

Write-Host "Changing $target1"
$filePathToTask = $target1
$xml = New-Object XML
$xml.Load($filePathToTask)
$element =  $xml.SelectSingleNode("//VersionPrefix")
$element.InnerText = $VersionPrefix
$element =  $xml.SelectSingleNode("//VersionSuffix")
$element.InnerText = $VersionSuffix
$xml.Save($filePathToTask)

Write-Host "Updated to version $VersionPrefix $VersionSuffix"