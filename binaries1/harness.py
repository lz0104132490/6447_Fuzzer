# harness.py
import subprocess
import signal

def run_process(binary_path, input_data):
    """
    Runs the binary at binary_path with input_data fed to its stdin.
    Returns True if a crash (SIGSEGV, SIGABRT, SIGBUS) was detected, False otherwise.
    """
    try:
        # Run the process, provide input_data to stdin, limit runtime in case of hang
        result = subprocess.run([binary_path], input=input_data, capture_output=True, timeout=5)
        # `timeout=5` limits each execution to 5 seconds to avoid hangs (adjustable)
    except subprocess.TimeoutExpired:
        # If the program hangs or doesn't terminate, we kill it and consider it a crash (hang as a failure)
        return True

    rc = result.returncode
    if rc < 0:
        # On Unix, a negative return code means killed by signal -rc:contentReference[oaicite:1]{index=1}
        signum = -rc
        # Check for common crash signals
        if signum in (signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS):
            return True
    # Also consider non-zero exit code as a potential crash (if the program indicates error by non-zero).
    # This is optional; some programs use non-zero exits for expected error cases.
    return False
