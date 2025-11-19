import random
from typing import List, Optional

from mutators.base import BaseMutator


class OctetMutator(BaseMutator):

    def __init__(self, seed_text: Optional[str], seed_bytes: bytes):
        super().__init__(seed_text, seed_bytes)

        raw = self.seed_bytes or b""
        stripped = raw.strip()

        self._ascii_part: bytes = b""
        self._binary_part: bytes = b""

        if stripped:
            ascii_bytes = bytearray()
            binary_bytes = bytearray()
            for b in stripped:
                ch = chr(b)
                if ch.isprintable():
                    ascii_bytes.append(b)
                else:
                    binary_bytes.append(b)

            if binary_bytes:
                self._ascii_part = bytes(ascii_bytes)
                self._binary_part = bytes(binary_bytes)
            else:
                self._ascii_part = b""
                self._binary_part = stripped
        else:
            if raw:
                self._ascii_part = b""
                self._binary_part = raw


    def deterministic_inputs(self) -> List[bytes]:
        outs: List[bytes] = []

        outs.extend(BaseMutator.deterministic_inputs(self))

        if not self._binary_part:
            return outs

        for mask in range(0x100):
            flipped = bytes((b ^ mask for b in self._binary_part))
            mutated = self._ascii_part + flipped
            outs.append(mutated)

        return outs


    def mutate(self, base: bytes) -> bytes:
        data = base or self.seed_bytes or b""
        if not data:
            return b""

        buf = bytearray(data)

        binary_indices = [i for i, b in enumerate(buf) if not chr(b).isprintable()]

        if binary_indices:
            flips = random.randint(1, min(8, len(binary_indices)))
            for idx in random.sample(binary_indices, flips):
                # XOR 一个随机 8bit mask
                buf[idx] ^= random.getrandbits(8)

        mutated = bytes(buf)

        if random.random() < 0.7:
            mutated = self.mutate_bytes(mutated)

        return mutated