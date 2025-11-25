param (
    [Parameter(Mandatory=$true)]
    [string]$InputFile,

    [Parameter(Mandatory=$true)]
    [string]$OutputFile,

    [string]$ExtraArgs
)

$IntermediateDir = "generated-intermediates"

if (-not (Test-Path $InputFile)) {
    Write-Error "error: input file missing"
    exit 1
}

if (-not (Test-Path $IntermediateDir)) {
    New-Item -ItemType Directory -Path $IntermediateDir -Force | Out-Null
}

$fileItem = Get-Item $InputFile
$size = $fileItem.Length
$name = $fileItem.BaseName
$absPath = $fileItem.FullName

$asmContent = @"
section .rdata
global const_${name}
global const_${name}_end
global const_${name}_sz

const_${name}:
    incbin "${absPath}"
const_${name}_end:

const_${name}_sz:
    dd ${size}
"@

$asmFile = Join-Path $IntermediateDir "$name.asm"
Set-Content -Path $asmFile -Value $asmContent -Encoding Ascii

nasm -f win64 $asmFile -o $OutputFile $ExtraArgs