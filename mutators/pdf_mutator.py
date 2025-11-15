import os
import random
from mutators.base import BaseMutator
from typing import List


class PDFMutator(BaseMutator):
    def deterministic_inputs(self) -> List[bytes]:
        outs = []
        outs.extend(self._det_version_change())
        outs.extend(self._det_remove_eof())
        outs.extend(self._det_truncations())
        outs.extend(self._det_insert_bad_object())
        outs.extend(self._det_corrupt_xref())
        outs.extend(self._det_trailer_mutations())
        outs.extend(self._det_append_junk())
        outs.extend(self._det_empty_file())
        outs.extend(self._det_overflow_bytes(self.seed_bytes))
        return outs

    # --- Deterministic Mutation Functions ---
    def _det_version_change(self) -> List[bytes]:
        # Change PDF version string
        outs = []
        b = bytearray(self.seed_bytes)
        if b.startswith(b"%PDF-"):
            for ver in [b"1.0", b"1.1", b"1.2", b"1.3", b"1.4", b"1.5", b"1.6", b"1.7"]:
                nv = bytearray(b)
                nv[5:8] = ver  # e.g., %PDF-1.4
                outs.append(bytes(nv))
        return outs

    def _det_remove_eof(self) -> List[bytes]:
        # Remove EOF marker
        b = bytearray(self.seed_bytes)
        outs = []
        eof_found = b.find(b'%%EOF')
        if eof_found != -1:
            nv = b[:eof_found] + b[eof_found+6:]
            outs.append(bytes(nv))
        return outs

    def _det_truncations(self) -> List[bytes]:
        # Truncate PDF at different fractions
        b = bytearray(self.seed_bytes)
        outs = []
        for frac in [0.9, 0.5, 0.1]:
            n = int(len(b) * frac)
            outs.append(bytes(b[:n]))
        return outs

    def _det_insert_bad_object(self) -> List[bytes]:
        # Insert a known-bad PDF object at start
        b = bytearray(self.seed_bytes)
        bad_obj = b"1 0 obj\n<< /Type /BadType >>\nendobj\n"
        return [bad_obj + bytes(b)]

    def _det_corrupt_xref(self) -> List[bytes]:
        # Overwrite or corrupt the xref section
        b = bytearray(self.seed_bytes)
        outs = []
        xref_pos = b.find(b'xref')
        if xref_pos != -1:
            nv = bytearray(b)
            nv[xref_pos:xref_pos+10] = b"xref\n0 1\n"
            outs.append(bytes(nv))
        return outs

    def _det_trailer_mutations(self) -> List[bytes]:
        # Remove or duplicate the trailer section
        b = bytearray(self.seed_bytes)
        outs = []
        trailer_pos = b.find(b'trailer')
        if trailer_pos != -1:
            # Remove trailer
            nv = b[:trailer_pos]
            outs.append(bytes(nv))
            # Duplicate trailer
            nv2 = b + b"\ntrailer\n<< /Root 1 0 R >>"
            outs.append(bytes(nv2))
        return outs

    def _det_append_junk(self) -> List[bytes]:
        # Add arbitrary junk at end
        b = bytearray(self.seed_bytes)
        return [bytes(b) + b"\nJUNKJUNKJUNK\n"]

    # --- Random Mutation ---
    def mutate(self, base: bytes) -> bytes:
        b = bytearray(base)
        # Insert a random new PDF object
        insertion = f"\n{random.randint(10,999)} 0 obj\n<< /Length 0 /Filter /FlateDecode >>\nstream\n".encode()
        insertion += os.urandom(random.randint(8, 64)) + b"\nendstream\nendobj\n"
        pos = random.randrange(len(b) + 1)
        b[pos:pos] = insertion
        # Corrupt xref sometimes
        if random.random() < 0.3:
            x = b.find(b"xref")
            if x != -1 and x + 10 < len(b):
                b[x:x+10] = b"xref\n0 1\n0000000000 00000 n\n"
        # Corrupt trailer sometimes
        if random.random() < 0.2:
            t = b.find(b'trailer')
            if t != -1 and t + 7 < len(b):
                for i in range(7):
                    b[t+i] = random.randint(0,255)
        # Call generic byte-level mutation(s) as well
        for _ in range(random.randint(1,3)):
            b = bytearray(self.mutate_bytes(bytes(b)))
        return bytes(b)
