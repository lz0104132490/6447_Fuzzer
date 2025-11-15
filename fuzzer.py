import os
import random
import subprocess
import signal
import time
import hashlib


from mutators.base import BaseMutator
from mutators.json_mutator import JSONMutator
from mutators.csv_mutator import CSVMutator
from mutators.xml_mutator import XMLMutator
from mutators.jpeg_mutator import JPEGMutator
from mutators.elf_mutator import ELFMutator
from mutators.pdf_mutator import PDFMutator
from forkserver import ForkserverRunner
from utils import detect_format, signal_name

MAX_RUN_TIME = 60
EXEC_TIMEOUT = 1.0
OUTPUT_DIR = "/fuzzer_output"
EXAMPLE_INPUTS_DIR = "/example_inputs"
BINARIES_DIR = "/binaries"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# fallback to subprocess if forkserver is not available
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

# --- Mutator factory ---
def get_mutator_by_type(format_type, seed_text, seed_bytes):
    mapping = {
        "json": JSONMutator,
        "csv": CSVMutator,
        "xml": XMLMutator,
        "jpeg": JPEGMutator,
        "elf": ELFMutator,
        "pdf": PDFMutator,
        "text": BaseMutator,
    }
    return mapping.get(format_type, BaseMutator)(seed_text, seed_bytes)

# --- Fuzzer class using strategy ---
class Fuzzer:
    def __init__(self, mutator: BaseMutator, runner, binary_file, crash_path, max_run_time=60, exec_timeout=1.0):
        self.mutator = mutator
        self.runner = runner
        self.binary_file = binary_file
        self.crash_path = crash_path
        self.max_run_time = max_run_time
        self.exec_timeout = exec_timeout

    def run(self, seed_bytes, record_deterministic=False, det_dir=None):
        start = time.time()
        seen_cov_bits = set()
        seen_cov_beh = set()
        crashes = 0
        hangs = 0
        execs = 0
        last_report = start
        distinct_crashes = 0
        crash_keys = set()
        corpus: list[bytes] = [seed_bytes]

        if det_dir:
            os.makedirs(det_dir, exist_ok=True)

        # Deterministic phase
        for idx, mb in enumerate(self.mutator.deterministic_inputs()):
            if det_dir:
                with open(os.path.join(det_dir, f"{idx:04d}.bin"), "wb") as df:
                    df.write(mb)
            rc, sig, crashed, hung, out, err = run_target(self.runner, self.binary_file, mb, self.exec_timeout)
            execs += 1
            if update_coverage(self.runner, rc, out, err, seen_cov_bits, seen_cov_beh, corpus, crashed, hung):
                corpus.append(mb)
            if crashed:
                new_unique, _ = handle_crash(self.runner, out, err, sig, crash_keys, self.crash_path, mb, os.path.basename(self.binary_file))
                if new_unique:
                    distinct_crashes += 1
                crashes += 1
            elif hung:
                hangs += 1

        # Random mutation phase
        while time.time() - start < self.max_run_time:
            base = random.choice(corpus)
            mb = self.mutator.mutate(base)
            if random.random() < 0.2:
                mb = self.mutator.mutate_bytes(mb)
            rc, sig, crashed, hung, out, err = run_target(self.runner, self.binary_file, mb, self.exec_timeout)
            execs += 1
            if update_coverage(self.runner, rc, out, err, seen_cov_bits, seen_cov_beh, corpus, crashed, hung):
                corpus.append(mb)
            if crashed:
                new_unique, _ = handle_crash(self.runner, out, err, sig, crash_keys, self.crash_path, mb, os.path.basename(self.binary_file))
                if new_unique:
                    distinct_crashes += 1
                crashes += 1
            elif hung:
                hangs += 1
            now = time.time()
            if now - last_report >= 4.0:
                elapsed = now - start
                rate = execs / elapsed if elapsed > 0 else 0.0
                cov_count = len(seen_cov_bits) if self.runner else len(seen_cov_beh)
                print(f"[*] {os.path.basename(self.binary_file)}: execs={execs} ({rate:.0f}/s) coverage={cov_count} crashes={crashes} unique_crashes={distinct_crashes} hangs={hangs} queue={len(corpus)} elapsed={elapsed:.1f}s", flush=True)
                last_report = now

        cov_count = len(seen_cov_bits) if self.runner else len(seen_cov_beh)
        print(f"[*] Finished fuzzing {os.path.basename(self.binary_file)}. execs={execs} coverage={cov_count} crashes={crashes} unique_crashes={distinct_crashes} hangs={hangs}", flush=True)
        print("================================================", flush=True)
        print(f"==============={os.path.basename(self.binary_file)} finished===========", flush=True)
        print("================================================", flush=True)

def fuzz_target(binary_name, record_deterministic=False):
    seed_file = os.path.join(EXAMPLE_INPUTS_DIR, binary_name + ".txt")
    binary_file = os.path.join(BINARIES_DIR, binary_name)
    format_type = detect_format(seed_file)
    print(f"[*] Fuzzing {binary_name} (format: {format_type.upper()}) for {MAX_RUN_TIME} seconds.", flush=True)

    try:
        # reading in bytes to avoid encoding issues
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
    runner = None
    try:
        runner = ForkserverRunner(binary_file)
        runner.start()
        print(f"[*] {binary_name}: forkserver enabled", flush=True)
    except Exception as e:
        runner = None
        print(f"[*] {binary_name}: forkserver unavailable, falling back to subprocess ({e})", flush=True)

    mutator = get_mutator_by_type(format_type, seed_text, seed_bytes)
    det_dir = os.path.join(OUTPUT_DIR, f"deterministic_{binary_name}") if record_deterministic else None
    fuzzer = Fuzzer(mutator, runner, binary_file, crash_path, max_run_time=MAX_RUN_TIME, exec_timeout=EXEC_TIMEOUT)
    fuzzer.run(seed_bytes, record_deterministic=record_deterministic, det_dir=det_dir)

def main():
    TEST_BINARY = ['csv', 'json', 'xml', 'jpeg', 'elf', 'pdf'] # development
    for binary in os.listdir(BINARIES_DIR):
        for test_binary in TEST_BINARY:
            if binary.find(test_binary) != -1:
                fuzz_target(binary)
                break

    # for binary in os.listdir(BINARIES_DIR):
    #     fuzz_target(binary)

if __name__ == "__main__":
    main()
