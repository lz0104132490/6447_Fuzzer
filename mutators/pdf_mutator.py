import os
import random
from mutators.base import BaseMutator


class PDFMutator(BaseMutator):
    def mutate(self, base: bytes) -> bytes:
        if not base.startswith(b"%PDF-"):
            return self.mutate_bytes(base)
        b = bytearray(base)
        insertion = f"\n{random.randint(10,999)} 0 obj\n<< /Length 0 /Filter /FlateDecode >>\nstream\n".encode()
        insertion += os.urandom(random.randint(8, 64)) + b"\nendstream\nendobj\n"
        pos = random.randrange(len(b) + 1)
        b[pos:pos] = insertion
        if random.random() < 0.3:
            x = b.find(b"xref")
            if x != -1 and x + 10 < len(b):
                b[x:x+10] = b"xref\n0 1\n0000000000 00000 n\n"
        return bytes(b)
