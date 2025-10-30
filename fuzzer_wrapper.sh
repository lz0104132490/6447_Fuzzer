#!/bin/bash

# Fuzzer wrapper script that runs against all binaries in /binaries
# and writes crash outputs to /fuzzer_outputs

set -euo pipefail

BINARIES_DIR="/binaries"
EXAMPLE_INPUTS_DIR="/example_inputs"
OUTPUT_DIR="/fuzzer_outputs"
FUZZER="/fuzzer"
SHARED_LIB="/shared.so"

# Check if directories exist
if [ ! -d "$BINARIES_DIR" ]; then
    echo "Error: $BINARIES_DIR does not exist"
    exit 1
fi

if [ ! -d "$EXAMPLE_INPUTS_DIR" ]; then
    echo "Error: $EXAMPLE_INPUTS_DIR does not exist"
    exit 1
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Creating $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
fi

# Change to output directory so fuzzer writes there
cd "$OUTPUT_DIR"

echo "========================================="
echo "Starting Fuzzer"
echo "========================================="

# Iterate over all binaries
for binary in "$BINARIES_DIR"/*; do
    if [ ! -f "$binary" ]; then
        continue
    fi
    
    # Get binary name without path
    binary_name=$(basename "$binary")
    
    echo ""
    echo "========================================="
    echo "Fuzzing: $binary_name"
    echo "========================================="
    
    # Find corresponding example input
    example_input=""
    for ext in txt json xml csv pdf; do
        candidate="$EXAMPLE_INPUTS_DIR/${binary_name}.${ext}"
        if [ -f "$candidate" ]; then
            example_input="$candidate"
            break
        fi
    done
    
    if [ -z "$example_input" ]; then
        echo "Warning: No example input found for $binary_name, skipping..."
        continue
    fi
    
    echo "Using example input: $example_input"
    
    # Run fuzzer with reasonable iteration count
    # Adjust -n parameter based on time constraints
    "$FUZZER" -b "$binary" -i "$example_input" -n 1000 -t 60 || true
    
    echo "Completed fuzzing $binary_name"
done

echo ""
echo "========================================="
echo "Fuzzing Complete"
echo "========================================="
echo "Output files in $OUTPUT_DIR:"
ls -lh "$OUTPUT_DIR" || true
