import os
import json
import csv
import random
import subprocess
import signal
import time
import hashlib
import xml.etree.ElementTree as ET
from multiprocessing import shared_memory
from pathlib import Path
from threading import Thread

from mutators.base import BaseMutator
from mutators.json_mutator import JSONMutator
from mutators.csv_mutator import CSVMutator
from mutators.xml_mutator import XMLMutator
from mutators.jpeg_mutator import JPEGMutator
from mutators.elf_mutator import ELFMutator
from mutators.pdf_mutator import PDFMutator
from forkserver import ForkserverRunner

MAX_RUN_TIME = 60
EXEC_TIMEOUT = 1.0
OUTPUT_DIR = "/fuzzer_output"
EXAMPLE_INPUTS_DIR = "/example_inputs"
BINARIES_DIR = "/binaries"

os.makedirs(OUTPUT_DIR, exist_ok=True)

def detect_format(seed_path):
    # Try binary magic numbers first
    try:
        with open(seed_path, 'rb') as fb:
            head = fb.read(8192)
    except Exception:
        head = b""

    if head.startswith(b"\xFF\xD8\xFF"):
        return "jpeg"
    if head.startswith(b"\x7FELF"):
        return "elf"
    if head.startswith(b"%PDF-"):
        return "pdf"

    # Fallback to text-based format checks
    try:
        with open(seed_path, 'r', errors='ignore') as f:
            text_probe = f.read(4096)
    except Exception:
        text_probe = ""

    # JSON
    try:
        json.loads(text_probe)
        return "json"
    except Exception:
        pass

    # XML
    try:
        ET.fromstring(text_probe.strip())
        return "xml"
    except Exception:
        pass

    # CSV
    try:
        csv.Sniffer().sniff(text_probe)
        return "csv"
    except Exception:
        return "text"

def signal_name(sig: int) -> str:
    try:
        return signal.Signals(sig).name
    except Exception:
        return f"SIG{sig}"


def run_binary_bytes(binary_path: str, data: bytes, timeout: float = 1.0):
    try:
        proc = subprocess.run([binary_path], input=data, capture_output=True, timeout=timeout, check=False)
        rc = proc.returncode
        sig = -rc if rc is not None and rc < 0 else None
        crashed = bool(sig in (signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS, signal.SIGILL, signal.SIGFPE))
        return rc, sig, crashed, False, proc.stdout[:4096], proc.stderr[:4096]
    except subprocess.TimeoutExpired as e:
        out = e.output if hasattr(e, 'output') and e.output is not None else b''
        err = e.stderr if hasattr(e, 'stderr') and e.stderr is not None else b''
        return None, None, False, True, out[:4096], err[:4096]

def handle_crash(runner, out, err, sig, crash_keys, crash_path, mb, binary_name):
    if runner and runner.cov_shm is not None:
        cov_bytes = bytes(runner.cov_shm.buf)
        triage = hashlib.blake2b(cov_bytes, digest_size=16).hexdigest()
    else:
        triage = hashlib.blake2b(
            (out[:256] if out else b"") + b"|" + (err[:256] if err else b""), 
            digest_size=16
        ).hexdigest()
    
    key = (sig, triage)
    new_unique = key not in crash_keys
    
    if new_unique:
        crash_keys.add(key)
        sig_name = signal_name(sig) if sig is not None else "UNKNOWN"
        with open(crash_path, 'a', encoding='utf-8', errors='ignore') as outf:
            outf.write(f"---- crash signal={sig} ({sig_name}) triage={triage} ----\n")
            try:
                outf.write(mb.decode('utf-8'))
            except UnicodeDecodeError:
                outf.write(mb.decode('latin-1', errors='ignore'))
            if not str(mb).endswith('\n'):
                outf.write('\n')
            outf.write('\n')
        print(f"[!] Crash detected in {binary_name} ({sig_name}), triage={triage}, saved to {crash_path}", flush=True)
        
    return new_unique, triage


def run_target(runner, binary_file, input_data, exec_timeout):
    if runner:
        runner.clear_coverage()
        return runner.run_one(input_data, exec_timeout)
    else:
        return run_binary_bytes(binary_file, input_data, timeout=exec_timeout)

def update_coverage(runner, rc, out, err, seen_cov_bits, seen_cov_beh, corpus, crashed, hung):
    if runner:
        if not crashed and not hung:
            cov = runner.read_coverage_indices()
            new = cov - seen_cov_bits
            if new:
                seen_cov_bits |= cov
                if len(corpus) < 1024:
                    return True
    else:
        beh_key = (rc, len(out), len(err))
        if beh_key not in seen_cov_beh and not crashed and not hung:
            seen_cov_beh.add(beh_key)
            if len(corpus) < 1024:
                return True
    return False

def fuzz_target(binary_name):
    seed_file = os.path.join(EXAMPLE_INPUTS_DIR, binary_name + ".txt")
    binary_file = os.path.join(BINARIES_DIR, binary_name)
    format_type = detect_format(seed_file)
    print(f"[*] Fuzzing {binary_name} (format: {format_type.upper()}) for {MAX_RUN_TIME} seconds.", flush=True)
    
    try:
        if format_type in ("jpeg", "elf", "pdf"):
            with open(seed_file, 'rb') as fb:
                seed_bytes = fb.read()
            seed_text = None
        else:
            with open(seed_file, 'r', errors='ignore') as f:
                seed_text = f.read()
            seed_bytes = seed_text.encode('utf-8', errors='ignore')
    except Exception:
        seed_text = ""
        seed_bytes = b""

    crash_path = os.path.join(OUTPUT_DIR, f"bad_{binary_name}.txt")
    start = time.time()
    seen_cov_bits = set()
    seen_cov_beh = set()
    crashes = 0
    hangs = 0
    execs = 0
    last_report = start

    corpus: list[bytes] = [seed_bytes]
    if format_type == "json":
        mutator = JSONMutator(seed_text, seed_bytes)
    elif format_type == "csv":
        mutator = CSVMutator(seed_text, seed_bytes)
    elif format_type == "xml":
        mutator = XMLMutator(seed_text, seed_bytes)
    elif format_type == "jpeg":
        mutator = JPEGMutator(seed_text, seed_bytes)
    elif format_type == "elf":
        mutator = ELFMutator(seed_text, seed_bytes)
    elif format_type == "pdf":
        mutator = PDFMutator(seed_text, seed_bytes)
    else:
        mutator = BaseMutator(seed_text, seed_bytes)
    runner = None
    try:
        runner = ForkserverRunner(binary_file)
        runner.start()
        print(f"[*] {binary_name}: forkserver enabled", flush=True)
    except Exception as e:
        runner = None
        print(f"[*] {binary_name}: forkserver unavailable, falling back to subprocess ({e})", flush=True)
    crash_keys = set()
    distinct_crashes = 0

    for mb in mutator.deterministic_inputs():
        rc, sig, crashed, hung, out, err = run_target(runner, binary_file, mb, EXEC_TIMEOUT)
        execs += 1

        if update_coverage(runner, rc, out, err, seen_cov_bits, seen_cov_beh, corpus, crashed, hung):
            corpus.append(mb)

        if crashed:
            new_unique, _ = handle_crash(runner, out, err, sig, crash_keys, crash_path, mb, binary_name)
            if new_unique:
                distinct_crashes += 1
            crashes += 1
        elif hung:
            hangs += 1

    while time.time() - start < MAX_RUN_TIME:
        base = random.choice(corpus)

        mb = mutator.mutate(base)
        if random.random() < 0.2:
            mb = mutator.mutate_bytes(mb)

        rc, sig, crashed, hung, out, err = run_target(runner, binary_file, mb, EXEC_TIMEOUT)
        execs += 1

        if update_coverage(runner, rc, out, err, seen_cov_bits, seen_cov_beh, corpus, crashed, hung):
            corpus.append(mb)

        if crashed:
            new_unique, _ = handle_crash(runner, out, err, sig, crash_keys, crash_path, mb, binary_name)
            if new_unique:
                distinct_crashes += 1
            crashes += 1
        elif hung:
            hangs += 1

        now = time.time()
        if now - last_report >= 4.0:
            elapsed = now - start
            rate = execs / elapsed if elapsed > 0 else 0.0
            cov_count = len(seen_cov_bits) if runner else len(seen_cov_beh)
            print(f"[*] {binary_name}: execs={execs} ({rate:.0f}/s) coverage={cov_count} crashes={crashes} unique_crashes={distinct_crashes} hangs={hangs} queue={len(corpus)} elapsed={elapsed:.1f}s", flush=True)
            last_report = now


    cov_count = len(seen_cov_bits) if runner else len(seen_cov_beh)
    print(f"[*] Finished fuzzing {binary_name}. execs={execs} coverage={cov_count} crashes={crashes} unique_crashes={distinct_crashes} hangs={hangs}", flush=True)
    print("================================================", flush=True)
    print("================================================", flush=True)
def main():
    for binary in os.listdir(BINARIES_DIR):
        fuzz_target(binary)

if __name__ == "__main__":
    main()
