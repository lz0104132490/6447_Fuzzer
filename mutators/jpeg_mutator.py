import os
import random
from mutators.base import BaseMutator


class JPEGMutator(BaseMutator):
    def mutate(self, base: bytes) -> bytes:
        b = bytearray(base)
        if not b.startswith(b"\xFF\xD8\xFF"):
            return self.mutate_bytes(base)
        for _ in range(random.randint(1, 4)):
            i = b.find(0xFF, random.randrange(2, len(b)))
            if i == -1 or i + 3 >= len(b):
                break
            if b[i + 1] not in (0x00, 0xD8, 0xD9):
                b[i + 2] = random.randrange(256)
                b[i + 3] = random.randrange(256)
        if random.random() < 0.2 and len(b) > 4:
            del b[-random.randint(1, min(1024, len(b) - 2)) :]
        if random.random() < 0.2 and len(b) < 65500:
            b.extend(os.urandom(random.randint(1, 512)))
        return bytes(b)
