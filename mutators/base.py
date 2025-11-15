import random
import math
from typing import Optional, List


class BaseMutator:
    def __init__(self, seed_text: Optional[str], seed_bytes: bytes):
        self.seed_text = seed_text
        self.seed_bytes = seed_bytes or b""

    def mutate(self, base: bytes) -> bytes:
        if self.seed_text is not None and random.random() < 0.7:
            mg = self._mutate_generic_text_once(self.seed_text)
            return mg.encode('utf-8', errors='ignore')
        return self.mutate_bytes(base)

    def deterministic_inputs(self) -> list[bytes]:
        outs: list[bytes] = []
        outs.extend(self._det_empty_file())
        outs.extend(self._det_overflow_bytes(self.seed_bytes))
        return outs

    def mutate_bytes(self, data_bytes: bytes) -> bytes:
        b = bytearray(data_bytes)
        if not b:
            b.append(random.randrange(256))
            return bytes(b)
        op = random.choice(["bitflip", "set", "arith", "insert", "delete", "dup"])
        if op == "bitflip":
            i = random.randrange(len(b))
            b[i] ^= 1 << random.randrange(8)
        elif op == "set":
            i = random.randrange(len(b))
            b[i] = random.randrange(256)
        elif op == "arith":
            i = random.randrange(len(b))
            b[i] = (b[i] + random.choice([-128, -16, -1, 1, 16, 127])) & 0xFF
        elif op == "insert" and len(b) < 65535:
            i = random.randrange(len(b) + 1)
            for _ in range(random.randint(1, 8)):
                b.insert(i, random.randrange(256))
        elif op == "delete" and len(b) > 1:
            i = random.randrange(len(b))
            del b[i]
        elif op == "dup" and len(b) < 65535:
            start = random.randrange(len(b))
            end = min(len(b), start + random.randint(1, 16))
            chunk = b[start:end]
            ins = random.randrange(len(b) + 1)
            b[ins:ins] = chunk
        return bytes(b)

    def _mutate_generic_text_once(self, data: str) -> str:
        raw = bytearray(data.encode('utf-8'))
        for _ in range(random.randint(1, 10)):
            if raw:
                idx = random.randint(0, len(raw) - 1)
                if random.random() < 0.6:
                    raw[idx] = random.randint(0, 255)
                else:
                    raw[idx] = (raw[idx] + random.choice([-128, -16, -1, 1, 16, 127])) & 0xFF
        return raw.decode('utf-8', errors='ignore')

    # Generic helpers available to all mutators
    def _get_numeric_mutations(self, value: str) -> List[str]:
        try:
            num = float(value)
            is_int = num.is_integer()
            mutations = [
                "0", "-0", "1", "-1", "100", "-100",
                str(2**31-1), str(-(2**31)), str(2**63-1), str(-(2**63)),
                str(10**9), str(10**18),
                "inf", "-inf", "NaN",
                "1e9", "1e-9", "1e308", "-1e308",
            ]
            if is_int:
                iv = int(num)
                mutations.extend([str(iv + 1), str(iv - 1), str(iv * 10), str(iv // 10) if iv != 0 else "0"])
            else:
                mutations.extend([
                    str(float(num) * 1.1),
                    str(float(num) * 0.9),
                    str(math.floor(float(num))),
                    str(math.ceil(float(num)))
                ])
            return mutations
        except (ValueError, OverflowError):
            return []

    def _get_string_mutations(self, value: str) -> List[str]:
        return [
            "",
            '"',
            '""',
            "'",
            "A" * 1000,
            "A" * 10000,
            "\x00",
            "\t\n\r",
            "🚨",
            "\u202E",
            "'" + value + "'",
            '"' + value + '"',
            value + ",",
            value + "\n",
            value + "\\",
        ]
    
    def _det_overflow_bytes(self, value: bytes) -> List[bytes]:
        return [
            value + b"A" * 1000,
            value + b"A" * 10000,
            value + b"\x00",
            value + b"\t\n\r",
            value + b"\u202E",
        ]

    def _det_empty_file(self) -> List[bytes]:
        return [b""]
    