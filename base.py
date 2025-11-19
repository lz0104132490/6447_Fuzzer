import random
import math
import sys
import string
from typing import Optional, List

NUM_BOUNDARIES = [
    0,
    1,
    -1,
    2**7,
    2**15,
    2**31 - 1,
    -(2**31),
    2**32,
    -(2**32),
    0xFF,
    0xFFFFFFFF,
    sys.maxsize,
    -sys.maxsize - 1,
]


def _looks_int(tok: str) -> bool:
    try:
        int(tok)
        return True
    except ValueError:
        return False


class BaseMutator:
    def __init__(self, seed_text: Optional[str], seed_bytes: bytes):
        self.seed_text = seed_text
        self.seed_bytes = seed_bytes or b""


    def mutate(self, base: bytes) -> bytes:
        if self.seed_text is not None and random.random() < 0.7:
            mg = self._mutate_generic_text_once(self.seed_text)
            return mg.encode("utf-8", errors="ignore")
        return self.mutate_bytes(base)


    def deterministic_inputs(self) -> list[bytes]:
        outs: list[bytes] = []
        outs.extend(self._det_empty_file())
        outs.extend(self._det_overflow_bytes(self.seed_bytes))
        if self.seed_text:
            big1 = ("A" * 4096) + "\n"
            big2 = ("A" * 8192) + "\n"
            outs.append(big1.encode("utf-8", errors="ignore"))
            outs.append(big2.encode("utf-8", errors="ignore"))

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
        lines = data.splitlines()
        if not lines:
            lines = [data]

        max_line_len = max(len(l) for l in lines) if lines else 0
        total_len = sum(len(l) for l in lines)

        max_allowed_line = max(64, max_line_len * 4)       
        max_allowed_total = max(1024, total_len * 8, 16384) 

        choice = random.randrange(8)

        # Repeat each row multiple times.
        if choice == 0:
            factor = random.randint(2, 6)
            out_lines = []
            for line in lines:
                s = line * factor
                if len(s) > max_allowed_line:
                    s = s[:max_allowed_line]
                out_lines.append(s)
            out = "\n".join(out_lines) + "\n"
            return out[:max_allowed_total]

        # Random ASCII string
        if choice == 1:
            alphabet = string.ascii_letters
            line_count = max(1, len(lines))
            line_len = min(max_allowed_line, max(8, 8 + random.randint(0, 64)))
            base = "".join(random.choice(alphabet) for _ in range(line_len))
            out = "\n".join(base for _ in range(line_count)) + "\n"
            return out[:max_allowed_total]

        # Replace with boundary number
        if choice == 2:
            val = random.choice(NUM_BOUNDARIES)
            out_lines = []
            for line in lines:
                if _looks_int(line.strip()):
                    out_lines.append(str(val))
                else:
                    out_lines.append(line)
            out = "\n".join(out_lines) + "\n"
            return out[:max_allowed_total]

        # Replace with a medium-length long string
        if choice == 3:
            length = min(max_allowed_line, 16 + random.randint(0, 256))
            filler = "A" * length
            out_lines = []
            for line in lines:
                if _looks_int(line.strip()):
                    out_lines.append(filler)
                else:
                    out_lines.append(line)
            out = "\n".join(out_lines) + "\n"
            return out[:max_allowed_total]

        # Enlarge an integer to a very large positive number
        if choice == 4:
            exponent = 2 + random.randint(0, 4)  # 2..6
            out_lines = []
            for line in lines:
                s = line.strip()
                if _looks_int(s):
                    try:
                        n = int(s) ** exponent
                    except OverflowError:
                        n = sys.maxsize
                    out_lines.append(str(n))
                else:
                    out_lines.append(line)
            out = "\n".join(out_lines) + "\n"
            return out[:max_allowed_total]

        # Enlarge an integer to a very large negative number
        if choice == 5:
            exponent = 2 + random.randint(0, 4)
            out_lines = []
            for line in lines:
                s = line.strip()
                if _looks_int(s):
                    try:
                        n = -(int(s) ** exponent)
                    except OverflowError:
                        n = -sys.maxsize - 1
                    out_lines.append(str(n))
                else:
                    out_lines.append(line)
            out = "\n".join(out_lines) + "\n"
            return out[:max_allowed_total]

        # 6) XOR bitflip
        if choice == 6:
            mask = random.randrange(1, 256)
            mutated = []
            for line in lines:
                mutated_line = "".join(chr(ord(c) ^ mask) for c in line)
                mutated.append(mutated_line)
            out = "\n".join(mutated) + "\n"
            return out[:max_allowed_total]

        # 7) Append a formatting placeholder 
        if choice == 7:
            tokens = ["%x", "%p", "%d", "%s"]
            fmt = "".join(tokens) * random.randint(1, 3)
            out_lines = [line + fmt for line in lines]
            out = "\n".join(out_lines) + "\n"
            if len(out) > max_allowed_total:
                out = out[:max_allowed_total]
            return out

    def _get_numeric_mutations(self, value: str) -> List[str]:
        mutations = [str(b) for b in NUM_BOUNDARIES]
        mutations.extend(
            [
                "inf",
                "-inf",
                "NaN",
                "1e9",
                "1e-9",
                "1e308",
                "-1e308",
            ]
        )

        try:
            num = float(value)
        
            is_int = num.is_integer()
            if is_int:
                iv = int(num)
                mutations.extend(
                    [
                        str(iv + 1),
                        str(iv - 1),
                        str(iv * 10),
                        str(iv // 10) if iv != 0 else "0",
                    ]
                )
            else:
                f = float(num)
                mutations.extend(
                    [
                        str(f * 1.1),
                        str(f * 0.9),
                        str(math.floor(f)),
                        str(math.ceil(f)),
                    ]
                )

            return mutations
        except (ValueError, OverflowError):
            return mutations
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

