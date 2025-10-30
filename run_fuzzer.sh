#!/bin/bash

echo "Deleting old fuzzer output files."
rm -rf 'fuzzer_outputs/*' 2>/dev/null

echo "Docker container building..."
docker build -t fuzzer-image .
if [ $? -ne 0 ]; then
    echo "Error: Failed to build docker container"
    exit 1
fi
echo "Docker container built successfully"

# Run the image, mounting /binaries as read-only and /fuzzer_outputs
echo "Running Fuzzer"
docker run --rm -v "$(pwd)/binaries":/binaries:ro -v "$(pwd)/example_inputs":/example_inputs:ro -v "$(pwd)/fuzzer_outputs":/fuzzer_outputs fuzzer-image
