param()

if (-not (Test-Path -LiteralPath "binaries" -PathType Container)) { Write-Host "Error: No folder named binaries exists in CWD."; exit 1 }
if (-not (Test-Path -LiteralPath "example_inputs" -PathType Container)) { Write-Host "Error: No folder named example_inputs exists in CWD."; exit 1 }

if (-not (Test-Path -LiteralPath "fuzzer_output" -PathType Container)) { Write-Host "Creating fuzzer_output folder"; New-Item -ItemType Directory -Path "fuzzer_output" | Out-Null }

Write-Host "Deleting old fuzzer output files."
Remove-Item -Path "fuzzer_output\*" -Recurse -Force -ErrorAction SilentlyContinue

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Host "Error: docker not found in PATH."; exit 1 }

Write-Host "Docker container building..."
& docker build -t fuzzer-image . 
if ($LASTEXITCODE -ne 0) { Write-Host "Error: Failed to build docker container"; exit 1 }
Write-Host "Docker container built successfully"

$binaries = (Resolve-Path -LiteralPath 'binaries').Path
$inputs   = (Resolve-Path -LiteralPath 'example_inputs').Path
$output   = (Resolve-Path -LiteralPath 'fuzzer_output').Path

Write-Host "Running Fuzzer"
& docker run --rm -it --shm-size=256m --cap-add=SYS_PTRACE `
--mount type=bind,source="${binaries}",target=/binaries,readonly `
--mount type=bind,source="${inputs}",target=/example_inputs,readonly `
--mount type=bind,source="${output}",target=/fuzzer_output `
fuzzer-image
