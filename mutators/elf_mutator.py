import random
from mutators.base import BaseMutator


class ELFMutator(BaseMutator):
    def mutate(self, base: bytes) -> bytes:
        if not base.startswith(b"\x7FELF"):
            return self.mutate_bytes(base)
        b = bytearray(base)
        for off in [16, 18, 48, 44]:
            if off + 1 < len(b):
                val = int.from_bytes(b[off:off+2], 'little', signed=False)
                delta = random.choice([-1, 1, 0x100, -0x100, 0x7FFF])
                val = (val + delta) & 0xFFFF
                b[off:off+2] = val.to_bytes(2, 'little')
        return bytes(b)
