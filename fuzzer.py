import os
import json
import csv
import random
import string
import subprocess
import signal
import time
import hashlib
from pathlib import Path
from threading import Thread

MAX_RUN_TIME = 60
OUTPUT_DIR = "/fuzzer_output"
EXAMPLE_INPUTS_DIR = "/example_inputs"
BINARIES_DIR = "/binaries"

os.makedirs(OUTPUT_DIR, exist_ok=True)

def detect_format(seed_path):
    with open(seed_path, 'r', errors='ignore') as f:
        try:
            json.load(f)
            return "json"
        except:
            pass
        try:
            csv.Sniffer().sniff(f.read(1024))
            return "csv"
        except:
            return "text"

def mutate_json(seed_data):
    def deep_nest(d, depth):
        for _ in range(depth):
            d = {str(random.randint(0, 100)): d}
        return d

    mutations = []
    for _ in range(100):
        data = seed_data.copy()
        choice = random.choice(["add", "modify", "nest", "overflow"])
        if choice == "add":
            data[str(random.randint(1000, 2000))] = random.choice(["val", 123, True, None])
        elif choice == "modify" and data:
            key = random.choice(list(data.keys()))
            data[key] = random.choice(["", 10**random.randint(5, 20), None])
        elif choice == "nest":
            data = deep_nest(data, random.randint(2, 10))
        elif choice == "overflow":
            data[str(random.randint(2001, 3000))] = int("9" * random.randint(20, 1000))
        mutations.append(json.dumps(data))
    return mutations

def mutate_csv(seed_lines):
    header = seed_lines[0]
    rows = seed_lines[1:]
    mutations = []
    for _ in range(100):
        mutated = [header]
        for row in rows:
            fields = row.split(',')
            new_fields = []
            for f in fields:
                choice = random.choice(["repeat", "long", "quote", "empty", "numeric"])
                if choice == "repeat":
                    new_fields.append(f * random.randint(2, 10))
                elif choice == "long":
                    new_fields.append(f + ''.join(random.choices(string.ascii_letters, k=random.randint(50, 500))))
                elif choice == "quote":
                    new_fields.append(f'"{f},{f}"')
                elif choice == "empty":
                    new_fields.append('')
                elif choice == "numeric":
                    new_fields.append(str(random.randint(-999999, 999999999)))
            mutated.append(','.join(new_fields))
        # sometimes add extra rows
        if random.random() < 0.3:
            for _ in range(random.randint(1, 10)):
                mutated.append(','.join(['EXTRA'] * len(mutated[0].split(','))))
        mutations.append('\n'.join(mutated))
    return mutations

def mutate_generic(data):
    mutations = []
    for _ in range(100):
        raw = bytearray(data.encode('utf-8'))
        for _ in range(random.randint(1, 10)):
            if raw:
                idx = random.randint(0, len(raw) - 1)
                raw[idx] = random.randint(0, 255)
        mutations.append(raw.decode('utf-8', errors='ignore'))
    return mutations

def run_binary(binary_path, mutated_input):
    try:
        proc = subprocess.run([binary_path], input=mutated_input.encode(), stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=1)
        return proc.returncode, None
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except subprocess.CalledProcessError as e:
        return e.returncode, None

def crash_detected(returncode):
    if returncode is None:
        return False
    return returncode < 0

def fuzz_target(binary_name):
    seed_file = os.path.join(EXAMPLE_INPUTS_DIR, binary_name + ".txt")
    binary_file = os.path.join(BINARIES_DIR, binary_name)
    format_type = detect_format(seed_file)
    print(f"[*] Fuzzing {binary_name} (format: {format_type.upper()}) for {MAX_RUN_TIME} seconds.")
    with open(seed_file, 'r', errors='ignore') as f:
        content = f.read()

    if format_type == "json":
        try:
            seed_data = json.loads(content)
            mutated_inputs = mutate_json(seed_data)
        except:
            mutated_inputs = mutate_generic(content)
    elif format_type == "csv":
        lines = content.splitlines()
        mutated_inputs = mutate_csv(lines)
    else:
        mutated_inputs = mutate_generic(content)

    crash_path = os.path.join(OUTPUT_DIR, f"bad_{binary_name}.txt")
    crashes = 0
    seen = set()
    start = time.time()
    i = 0
    while time.time() - start < MAX_RUN_TIME:
        inp = mutated_inputs[i % len(mutated_inputs)]
        ret, err = run_binary(binary_file, inp)
        if crash_detected(ret):
            sig = -ret 
            digest = hashlib.blake2b(inp.encode('utf-8', errors='ignore'), digest_size=16).hexdigest()
            key = (sig, digest)
            if key in seen:
                i += 1
                continue
            seen.add(key)

            crashes += 1
            with open(crash_path, 'a', encoding='utf-8', errors='ignore') as outf:
                outf.write(f"---- crash #{crashes}  signal={sig}  hash={digest} ----\n")
                outf.write(inp)
                if not inp.endswith('\n'):
                    outf.write('\n')
                outf.write('\n')

            print(f"[!] Crash detected in {binary_name} (signal {sig}), saved to {crash_path}")

        i += 1

    print(f"[*] Finished fuzzing {binary_name}. Total crashes: {crashes}\n")

def main():
    for binary in os.listdir(BINARIES_DIR):
        fuzz_target(binary)

if __name__ == "__main__":
    main()

