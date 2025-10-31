# fuzzer.py
import time
from harness import run_process

class Fuzzer:
    def __init__(self, binary_path, seed_input_data, MutatorClass):
        self.binary_path = binary_path
        self.seed_input = seed_input_data
        # Instantiate the mutator with the initial seed data
        self.mutator = MutatorClass(self.seed_input)
        # Derive program name for logging
        self.prog_name = binary_path.split('/')[-1]

    def run(self, duration=60):
        """Run the fuzzing loop for the given duration (in seconds)."""
        start_time = time.time()
        crashes = 0
        # Loop until time budget is exhausted
        while time.time() - start_time < duration:
            # Generate a mutated input
            test_input = self.mutator.mutate()
            # Run the target program with this input
            crashed = run_process(self.binary_path, test_input)
            if crashed:
                crashes += 1
                # Save the crashing input to a file
                output_path = f"/fuzzer_output/bad_{self.prog_name}.txt"
                with open(output_path, "ab") as out:  # append in binary mode
                    out.write(b"==== Crash Input ====\n")
                    out.write(test_input + b"\n")
                print(f"[!] Crash detected in {self.prog_name}! Saved to {output_path}")
                # (Optionally, break out after first crash or continue to find more)
                # For thoroughness, we continue to see if other crashes occur within time
            # (Else, no crash, continue loop)
        print(f"Finished fuzzing {self.prog_name}. Crashes found: {crashes}")
