import random
from mutators.base import BaseMutator
from typing import List


class ELFMutator(BaseMutator):
    def deterministic_inputs(self) -> List[bytes]:
        outs = []
        outs.extend(self._det_corrupt_ident())
        outs.extend(self._det_truncate_header())
        outs.extend(self._det_entrypoint_zero())
        outs.extend(self._det_empty_file())
        outs.extend(self._det_overflow_bytes(self.seed_bytes))
        return outs

    # --- Deterministic mutations ---

    def _det_corrupt_ident(self) -> List[bytes]:
        # Corrupt the ELF identification bytes
        outs = []
        b = bytearray(self.seed_bytes)
        if b.startswith(b"\x7FELF"):
            for val in [0x00, 0xFF]:
                mutated = bytearray(b)
                mutated[1] = val  # Corrupt class field
                outs.append(bytes(mutated))
        return outs

    def _det_truncate_header(self) -> List[bytes]:
        # Truncate after ELF header (64 bytes)
        outs = []
        b = bytearray(self.seed_bytes)
        if len(b) > 64:
            outs.append(bytes(b[:64]))
        return outs

    def _det_entrypoint_zero(self) -> List[bytes]:
        # Set entry point address to zero
        outs = []
        b = bytearray(self.seed_bytes)
        if b.startswith(b"\x7FELF") and len(b) > 0x18+8:
            mutated = bytearray(b)
            for i in range(8):
                mutated[0x18+i] = 0
            outs.append(bytes(mutated))
        return outs

    # --- Random mutation ---
    def mutate(self, base: bytes) -> bytes:
        if not base.startswith(b"\x7FELF"):
            return self.mutate_bytes(base)
        b = bytearray(base)
        # Randomly corrupt ELF header fields
        for off in [16, 18, 48, 44]:
            if off + 1 < len(b):
                val = int.from_bytes(b[off:off+2], 'little', signed=False)
                delta = random.choice([-1, 1, 0x100, -0x100, 0x7FFF])
                val = (val + delta) & 0xFFFF
                b[off:off+2] = val.to_bytes(2, 'little')
        # Apply generic byte-level mutations as well
        for _ in range(random.randint(1, 3)):
            b = bytearray(self.mutate_bytes(bytes(b)))
        return bytes(b)
