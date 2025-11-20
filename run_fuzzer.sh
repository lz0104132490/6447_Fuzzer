#!/bin/bash

# Ensure the binaries folder exists.
if [ ! -d "binaries" ]; then
    echo "Error: No folder named binaries exists in CWD."
    exit 1
fi

# Ensure the example_inputs folder exists.
if [ ! -d "example_inputs" ]; then
    echo "Error: No folder named example_inputs exists in CWD."
    exit 1
fi

# Make a folder for fuzzer_output
if [ ! -d "fuzzer_output" ]; then
    echo "Creating fuzzer_output folder"
    mkdir fuzzer_output
fi

echo "Deleting old fuzzer output files."
rm -f fuzzer_output/* 2>/dev/null

# Ensure docker is available
if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker not found in PATH."
    exit 1
fi

echo "Docker container building..."
docker build -t fuzzer-image .
if [ $? -ne 0 ]; then
    echo "Error: Failed to build docker container"
    exit 1
fi
echo "Docker container built successfully"

# Resolve absolute paths for bind mounts (to mirror run_fuzzer.ps1 behavior)
BINARIES_DIR="$(pwd)/binaries"
INPUTS_DIR="$(pwd)/example_inputs"
OUTPUT_DIR="$(pwd)/fuzzer_output"

# Run the image, mounting /binaries and /example_inputs as read-only and /fuzzer_output as read-write
echo "Running Fuzzer"
docker run --rm -it --shm-size=256m --cap-add=SYS_PTRACE \
    -v "${BINARIES_DIR}:/binaries:ro" \
    -v "${INPUTS_DIR}:/example_inputs:ro" \
    -v "${OUTPUT_DIR}:/fuzzer_output" \
    fuzzer-image
