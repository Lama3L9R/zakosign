

$targetDirectory = ".\src"
$sourceFiles = Get-ChildItem -Path $targetDirectory -Recurse -Filter "*.c"
$binaryFiles = Get-ChildItem -Path $targetDirectory -Recurse -Filter "*.bin"
$objectFiles = @()

$libraries = @(
    "vcruntime.lib"
    "ucrt.lib"
    "msvcrt.lib"
    "Shlwapi.lib"
    "Kernel32.lib"
    "boringssl/build-host/Release/ssl.lib"
    "boringssl/build-host/Release/crypto.lib"
)

if (!(Test-Path Env:\VCINSTALLDIR)) {
    Write-Error "Visual Studio environment variables not found. Try run this script in Developer PowerShell for VS"
    exit 1
}

if ($Env:VSCMD_ARG_TGT_ARCH -ne "x64") {
    Write-Error "Unsupported arch (Current: $Env:VSCMD_ARG_TGT_ARCH)! Please run 'Enter-VsDevShell amd64 <\Path\To\VS>'"
    exit 1
}

if (!(Test-Path -Path "obj")) {
    mkdir obj | Out-Null 
}

if (!(Test-Path -Path "bin")) {
    mkdir bin | Out-Null 
}

foreach ($file in $sourceFiles) {
    $objName = $file.Name -replace "\.c$", ".o"

    Write-Host "  CC      $file $objName"
    clang.exe -Iboringssl/include -Isrc -m64 -O0 -c -o "obj/$objName" $file.FullName
    
    $objectFiles += "obj/$objName"
}

foreach ($file in $binaryFiles) {
    $objName = $file.Name -replace "\.bin$", ".o"

    Write-Host "  BIN2OBJ $file $objName"
    tools/bin2obj.ps1 $file.FullName "obj/$objName"
    
    $objectFiles += "obj/$objName"
}

Write-Host "  LINK    zakosign.exe"
link.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 /OUT:"bin/zakosign.exe" @libraries @objectFiles | Out-Null
