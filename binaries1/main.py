# main.py
import os
import sys
from fuzzer import Fuzzer
from typechecker import detect_type
from strategies import get_mutator_class

def main():
    # Get input directory from arguments (or default path)
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <input_dir>")
        sys.exit(1)
    input_dir = sys.argv[1]
    os.makedirs("/fuzzer_output", exist_ok=True)  # Ensure output directory exists

    # Iterate over files in the input directory (expecting pairs of binary and seed file)
    for filename in os.listdir(input_dir):
        file_path = os.path.join(input_dir, filename)
        # Identify binaries vs input files; for simplicity, assume seed input files have a known extension
        if filename.endswith(".bin"):  # Suppose binary files are marked with .bin (just for illustration)
            binary_path = file_path
            # Assume corresponding input file has same base name with .txt or known extension
            seed_input_path = binary_path.replace(".bin", ".txt")
            if not os.path.exists(seed_input_path):
                print(f"No seed input for {binary_path}, skipping.")
                continue

            # Read the seed input content
            with open(seed_input_path, "rb") as f:
                seed_data = f.read()
            # Detect input type (e.g., JSON, CSV, etc.)
            input_type = detect_type(seed_data)
            # Get the appropriate mutator class for this input type
            MutatorClass = get_mutator_class(input_type)

            # Create Fuzzer instance and run it
            fuzzer = Fuzzer(binary_path, seed_data, MutatorClass)
            print(f"[*] Fuzzing {binary_path} with input type {input_type}...")
            fuzzer.run()
