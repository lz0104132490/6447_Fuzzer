import os
import time
import fcntl
import signal
import struct
import select
import subprocess
from multiprocessing import shared_memory

class ForkserverRunner:
    def __init__(self, binary_path: str, shm_size: int = 1 << 20, cov_size: int = 1 << 16):
        self.binary_path = binary_path
        self.shm_size = shm_size
        self.cov_size = cov_size
        self.shm = None
        self.cov_shm = None
        self.ctl_r = self.ctl_w = None
        self.st_r = self.st_w = None
        self.proc = None

    def start(self):
        self.shm = shared_memory.SharedMemory(create=True, size=self.shm_size)
        self.cov_shm = shared_memory.SharedMemory(create=True, size=self.cov_size)
        self.ctl_r, self.ctl_w = os.pipe()
        self.st_r, self.st_w = os.pipe()

        def _preexec():
            os.dup2(self.ctl_r, 198)
            os.dup2(self.st_w, 199)
            # Clear FD_CLOEXEC flag so the dynamic linker doesn't close these FDs
            fcntl.fcntl(198, fcntl.F_SETFD, 0)
            fcntl.fcntl(199, fcntl.F_SETFD, 0)
            try:
                os.close(self.ctl_r)
                os.close(self.st_w)
            except Exception:
                pass

        env = os.environ.copy()
        env["LD_PRELOAD"] = "/forkserver_lib.so"
        env["FUZZER_SHM_NAME"] = self.shm.name
        env["FUZZER_SHM_SIZE"] = str(self.shm_size)
        env["FUZZER_COV_NAME"] = self.cov_shm.name
        env["FUZZER_COV_SIZE"] = str(self.cov_size)

        self.proc = subprocess.Popen(
            [self.binary_path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=_preexec,
            close_fds=False,
            env=env,
        )

        os.close(self.ctl_r)
        os.close(self.st_w)

        hb = self._read_exact(self.st_r, 4, 1.0)
        if len(hb) < 4:
            raise RuntimeError("forkserver handshake failed")

    def _read_exact(self, fd: int, n: int, timeout: float) -> bytes:
        buf = bytearray()
        end = time.time() + timeout
        while len(buf) < n:
            remain = end - time.time()
            if remain <= 0:
                break
            rlist, _, _ = select.select([fd], [], [], remain)
            if not rlist:
                break
            chunk = os.read(fd, n - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def run_one(self, data: bytes, timeout: float):
        if self.shm is None:
            raise RuntimeError("forkserver not started")
        if len(data) + 4 > self.shm_size:
            data = data[: self.shm_size - 4]
        mv = self.shm.buf
        mv[0:4] = struct.pack('<I', len(data))
        mv[4:4+len(data)] = data

        try:
            os.write(self.ctl_w, b"\x00\x00\x00\x00")
        except Exception:
            # Control pipe write failed; drain status to resync and report hang
            self._drain_status()
            return None, None, False, True, b"", b""

        pid_bytes = self._read_exact(self.st_r, 4, timeout)
        if len(pid_bytes) < 4:
            # Timeout or protocol desync; drain any pending status to realign
            self._drain_status()
            return None, None, False, True, b"", b""
        pid = struct.unpack('<I', pid_bytes)[0]

        status_bytes = self._read_exact(self.st_r, 4, timeout)
        if len(status_bytes) < 4:
            try:
                if pid:
                    os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
            # After killing hung child, drain pending bytes to avoid desync next iter
            self._drain_status()
            return None, None, False, True, b"", b""
        status = struct.unpack('<I', status_bytes)[0]

        crashed = False
        sig = None
        rc = 0
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            rc = -sig
            crashed = sig in (signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS, signal.SIGILL, signal.SIGFPE)
        elif os.WIFEXITED(status):
            rc = os.WEXITSTATUS(status)
        else:
            pass
        return rc, sig, crashed, False, b"", b""

    def _drain_status(self):
        # Non-blocking drain of status pipe to recover from protocol desyncs
        try:
            while True:
                rlist, _, _ = select.select([self.st_r], [], [], 0)
                if not rlist:
                    break
                chunk = os.read(self.st_r, 4096)
                if not chunk:
                    break
        except Exception:
            pass

    def clear_coverage(self):
        if self.cov_shm is not None:
            mv = self.cov_shm.buf
            mv[:] = b"\x00" * len(mv)

    def read_coverage_indices(self):
        if self.cov_shm is None:
            return set()
        mv = self.cov_shm.buf
        return {i for i, v in enumerate(mv) if v}
