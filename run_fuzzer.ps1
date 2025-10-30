# Clean up old fuzzer output files
Write-Host "Deleting old fuzzer output files."
if (Test-Path "fuzzer_outputs") {
    Remove-Item "fuzzer_outputs\*" -Recurse -Force -ErrorAction SilentlyContinue
}

# Build the Docker container
Write-Host "Docker container building..."
docker build -t fuzzer-image .
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to build docker container"
    exit 1
}
Write-Host "Docker container built successfully"

# Run the Docker container, mounting volumes
Write-Host "Running Fuzzer"
$pwdPath = (Get-Location).Path
docker run `
    -v "${pwdPath}\binaries:/binaries:ro" `
    -v "${pwdPath}\example_inputs:/example_inputs:ro" `
    -v "${pwdPath}\fuzzer_outputs:/fuzzer_outputs" `
    fuzzer-image
