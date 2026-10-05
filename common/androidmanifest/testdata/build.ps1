# Rebuilds the fixture APKs in this directory with aapt2 (build-tools 35) and
# android.jar (API 35). The tools come from experimental/first_connection_probe/tools.
# The APKs are unsigned: only their manifest and resources.arsc are read.
param([string]$Tools = (Join-Path $PSScriptRoot '..\..\..\experimental\first_connection_probe\tools'))
$ErrorActionPreference = 'Stop'
$aapt = (Get-ChildItem (Join-Path $Tools 'build-tools-35.0.0') -Recurse -Filter aapt2.exe | Select-Object -First 1).FullName
$jar = (Get-ChildItem (Join-Path $Tools 'platforms-android-35') -Recurse -Filter android.jar | Select-Object -First 1).FullName
$src = Join-Path $PSScriptRoot 'src'
$work = Join-Path ([IO.Path]::GetTempPath()) 'androidmanifest-fixtures'
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory $work | Out-Null

function Link([string]$manifest, [string]$out, [string[]]$extra) {
    $flat = Join-Path $work 'res.zip'
    & $aapt compile --dir (Join-Path $src 'res') -o $flat
    if ($LASTEXITCODE -ne 0) { throw 'aapt2 compile failed' }
    & $aapt link -I $jar --manifest (Join-Path $src $manifest) -o (Join-Path $PSScriptRoot $out) $flat @extra
    if ($LASTEXITCODE -ne 0) { throw "aapt2 link $out failed" }
}

Link 'plain.xml' 'plain.apk' @()
Link 'reference.xml' 'reference.apk' @()
Link 'reference.xml' 'reference-sparse.apk' @('--enable-sparse-encoding')
Link 'reference.xml' 'reference-compact.apk' @('--enable-compact-entries')
New-Item -ItemType Directory -Force (Join-Path $PSScriptRoot 'split') | Out-Null
Link 'split-base.xml' 'split\base.apk' @()
Link 'split-feature.xml' 'split\split_feature.apk' @()
Link 'other.xml' 'split\other.apk' @()
# Like Chrome's split_on_demand.apk: a split with no resources of its own
# whose android:process references a string in the base APK.
& $aapt link -I $jar -I (Join-Path $PSScriptRoot 'split\base.apk') --manifest (Join-Path $src 'split-ondemand.xml') -o (Join-Path $PSScriptRoot 'split\split_ondemand.apk')
if ($LASTEXITCODE -ne 0) { throw 'aapt2 link split_ondemand failed' }
