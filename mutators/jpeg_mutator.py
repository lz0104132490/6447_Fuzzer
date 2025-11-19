import io
import os
import random
from mutators.base import BaseMutator

class JPEGMutator(BaseMutator):

    def __init__(self, seed_text: str | None, seed_bytes: bytes):
        # Keep the same constructor interface expected by fuzz_target/get_mutator_by_type.
        super().__init__(seed_text, seed_bytes)

    def deterministic_inputs(self) -> list[bytes]:
        """
        Deterministic seeds for JPEG:
        - Base class deterministic inputs (empty + overflow).
        - The original seed bytes (if any) unchanged.
        - A handful of structural variants of the original JPEG that target
          SOF/DQT/DHT/SOS, tail truncation/padding, and the upsampling bugs.
        """
        outs = []
        if not self.seed_bytes:
            return outs

        outs.append(self.seed_bytes)

        # Try to parse the seed as JPEG and generate a few structured variants
        # to quickly explore interesting decoder paths before random fuzzing.
        if self.seed_bytes.startswith(b"\xFF\xD8\xFF"):
            def add_variant(mutator):
                variant = bytearray(self.seed_bytes)
                try:
                    success = mutator(variant)
                except Exception:
                    success = False
                if success:
                    outs.append(bytes(variant))

            add_variant(self._deterministic_extreme_dimensions)
            add_variant(self._deterministic_gray_scan_repeat)
            add_variant(lambda b: self._deterministic_segment_length(b, small=True))
            add_variant(lambda b: self._deterministic_segment_length(b, small=False))
            add_variant(self._deterministic_dqt_corrupt)
            add_variant(self._deterministic_dht_corrupt)
            add_variant(self._deterministic_sos_corrupt)
            add_variant(self._deterministic_truncate)
            add_variant(self._deterministic_pad)
            add_variant(self._deterministic_upsample_overflow)
            add_variant(self._deterministic_upsample_tiny)

        return outs

    def mutate(self, base: bytes) -> bytes:
        # Fallback to generic byte mutator if this doesn't look like a JPEG.
        if not base.startswith(b"\xFF\xD8\xFF"):
            return self.mutate_bytes(base)

        b = bytearray(base)

        # With some probability, just do a generic mutation on top to keep diversity.
        if random.random() < 0.2:
            return self.mutate_bytes(base)

        # Parse markers in a very loose way: enough to find interesting places
        # to smash (length fields, SOF, DQT, DHT, SOS).
        try:
            segments = self._scan_segments(b)
        except Exception:
            # If parsing fails badly, don't get stuck; just generic-mutate.
            return self.mutate_bytes(base)

        # Choose one or more structural mutations.
        for _ in range(random.randint(1, 4)):
            if not segments:
                break
            kind = random.choice(
                [
                    "length",
                    "dimensions",
                    "dimensions_overflow",
                    "dimensions_tiny",
                    "dqt_payload",
                    "dht_payload",
                    "sos_header",
                    "sampling",
                    "truncate_or_pad",
                ]
            )
            if kind == "length":
                self._mutate_segment_length(b, segments)
            elif kind == "dimensions":
                self._mutate_dimensions(b, segments)
            elif kind == "dimensions_overflow":
                self._mutate_dimensions_overflow(b, segments)
            elif kind == "dimensions_tiny":
                self._mutate_dimensions_tiny(b, segments)
            elif kind == "dqt_payload":
                self._mutate_dqt_payload(b, segments)
            elif kind == "dht_payload":
                self._mutate_dht_payload(b, segments)
            elif kind == "sos_header":
                self._mutate_sos_header(b, segments)
            elif kind == "sampling":
                self._mutate_sampling(b, segments)
            elif kind == "truncate_or_pad":
                self._truncate_or_pad(b)

        return bytes(b)

    # --- simple JPEG parsing helpers ---

    def _scan_segments(self, b: bytearray):
        """
        Return a list of segments:
        { "marker": int, "start": int, "len_off": int, "length": int|None }

        len_off is the index of the first length byte (big-endian 16-bit),
        or -1 for markers without a length (SOI, EOI, RSTx, standalone 0xFF00).
        """
        segments = []
        i = 0
        n = len(b)

        # Expect SOI at start.
        if n < 4 or not (b[0] == 0xFF and b[1] == 0xD8):
            return segments

        i = 2
        while i + 1 < n:
            if b[i] != 0xFF:
                i += 1
                continue
            # Skip fill bytes 0xFF FF FF...
            j = i
            while j < n and b[j] == 0xFF:
                j += 1
            if j >= n:
                break
            marker = b[j]
            start = i
            i = j + 1

            # Standalone markers: no length field.
            if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7) or marker == 0x01:
                segments.append(
                    {
                        "marker": marker,
                        "start": start,
                        "len_off": -1,
                        "length": None,
                    }
                )
                continue
            if i + 1 >= n:
                break
            l = (b[i] << 8) | b[i + 1]
            seg = {
                "marker": marker,
                "start": start,
                "len_off": i,
                "length": l,
            }
            segments.append(seg)

            # Move i to the end of this segment, but clamp.
            seg_end = i + l
            if seg_end <= i:
                # Clearly bogus length; stop parsing to avoid loops.
                break
            i = min(seg_end, n)

            # Stop at SOS (start of scan); rest is entropy-coded data.
            if marker == 0xDA:
                break
        return segments

    # --- structural mutation helpers ---

    def _mutate_segment_length(self, b: bytearray, segments):
        """Smash the 16-bit length field of a random segment (not SOI/EOI)."""
        candidates = [s for s in segments if s["len_off"] >= 0 and s["length"] is not None]
        if not candidates:
            return
        s = random.choice(candidates)
        off = s["len_off"]

        old = s["length"]
        # Try very small, very large, or off-by-one style lengths.
        choices = [
            0,
            1,
            2,
            old ^ 0xFFFF,
            (old + random.choice([-2, -1, 1, 2, 0x10, 0x100, 0x7FFF])) & 0xFFFF,
            0xFFFF,
        ]
        new = random.choice(choices)
        b[off] = (new >> 8) & 0xFF
        b[off + 1] = new & 0xFF

    def _mutate_dimensions(self, b: bytearray, segments):
        """Mutate SOF width/height to extreme or inconsistent values."""
        sof_markers = {0xC0, 0xC1, 0xC2, 0xC3}
        sofs = [s for s in segments if s["marker"] in sof_markers and s["len_off"] >= 0]
        if not sofs:
            return
        s = random.choice(sofs)
        # SOF layout: length(2), precision(1), height(2), width(2), ...
        base = s["len_off"] + 3
        if base + 3 >= len(b):
            return
        height = ((b[base] << 8) | b[base + 1]) or 1
        width = ((b[base + 2] << 8) | b[base + 3]) or 1

        # Create nasty but still plausible dims (trigger int overflows/huge allocs).
        choices = [
            (1, width),
            (height, 1),
            (0xFFFF, width),
            (height, 0xFFFF),
            (0x7FFF, 0x7FFF),
            (0xFFFF, 0xFFFF),
        ]
        nh, nw = random.choice(choices)
        b[base] = (nh >> 8) & 0xFF
        b[base + 1] = nh & 0xFF
        b[base + 2] = (nw >> 8) & 0xFF
        b[base + 3] = nw & 0xFF

    def _mutate_dimensions_overflow(self, b: bytearray, segments):
        """Force dimensions large enough to overflow 32-bit size calculations."""
        width = random.randint(50000, 65534)
        height = random.randint(50000, 65534)
        if self._set_dimensions_values(b, segments, height, width):
            self._force_subsampling_pattern(b, segments, h_target=2, v_target=2)

    def _mutate_dimensions_tiny(self, b: bytearray, segments):
        """Force dimensions tiny so that subsampled planes are only a few pixels."""
        width = random.randint(1, 8)
        height = random.randint(1, 8)
        if self._set_dimensions_values(b, segments, height, width):
            self._force_subsampling_pattern(b, segments, h_target=2, v_target=2)

    def _mutate_dqt_payload(self, b: bytearray, segments):
        """Corrupt DQT tables: change count/precision or smash inside payload."""
        dqts = [s for s in segments if s["marker"] == 0xDB and s["len_off"] >= 0]
        if not dqts:
            return
        s = random.choice(dqts)
        start = s["len_off"] + 2
        if start >= len(b):
            return
        # Randomly smash some bytes in this DQT payload.
        end = min(len(b), start + max(0, s["length"] - 2))
        if end <= start:
            return
        for _ in range(random.randint(1, 8)):
            pos = random.randrange(start, end)
            b[pos] = random.randrange(256)

    def _mutate_dht_payload(self, b: bytearray, segments):
        """Corrupt DHT tables: change code counts or table contents."""
        dhts = [s for s in segments if s["marker"] == 0xC4 and s["len_off"] >= 0]
        if not dhts:
            return
        s = random.choice(dhts)
        start = s["len_off"] + 2
        if start >= len(b):
            return
        end = min(len(b), start + max(0, s["length"] - 2))
        if end <= start:
            return
        # Either smash the 16 count bytes or some of the value bytes.
        if end - start >= 16 and random.random() < 0.5:
            for i in range(16):
                # Inflate or deflate symbol counts to confuse Huffman builder.
                if random.random() < 0.7:
                    b[start + i] = random.randrange(0, 0xFF)
        else:
            for _ in range(random.randint(1, 8)):
                pos = random.randrange(start, end)
                b[pos] = random.randrange(256)

    def _mutate_sos_header(self, b: bytearray, segments):
        """Mutate SOS (Start of Scan) header to reference bad tables/components."""
        soss = [s for s in segments if s["marker"] == 0xDA and s["len_off"] >= 0]
        if not soss:
            return
        s = random.choice(soss)
        base = s["len_off"] + 2
        if base + 1 >= len(b):
            return
        ncomp = b[base]
        # Each component: id (1), table selector (1)
        hdr_end = base + 1 + 2 * ncomp + 3  # includes Ss, Se, Ah/Al
        hdr_end = min(hdr_end, len(b))
        # Randomly flip table selectors and component ids.
        for i in range(base + 1, min(base + 1 + 2 * ncomp, hdr_end), 2):
            if i + 1 >= len(b):
                break
            if random.random() < 0.7:
                b[i] = random.randrange(0, 0xFF)  # bogus component id
            if random.random() < 0.9:
                b[i + 1] ^= random.choice([0x0F, 0xF0, 0x33, 0xCC])

    def _mutate_sampling(self, b: bytearray, segments):
        """Adjust sampling factors to ensure upsampling helpers are exercised."""
        # Increase the primary component sampling and shrink others to force upsampling.
        self._force_subsampling_pattern(
            b,
            segments,
            h_target=random.choice([2, 3]),
            v_target=random.choice([1, 2]),
        )
        info = self._get_sof_info(b, segments)
        if not info:
            return
        for comp in info["components"][1:]:
            if random.random() < 0.4:
                h = random.randint(1, 2)
                v = random.randint(1, 2)
                b[comp["sample_off"]] = ((h & 0xF) << 4) | (v & 0xF)

    def _get_sof_info(self, b: bytearray, segments):
        sof_markers = {0xC0, 0xC1, 0xC2, 0xC3}
        for s in segments:
            if s["marker"] not in sof_markers or s["len_off"] < 0:
                continue
            if s["length"] is None or s["length"] < 8:
                continue
            base = s["len_off"] + 3
            if base + 4 >= len(b):
                continue
            ncomp_off = base + 4
            if ncomp_off >= len(b):
                continue
            ncomp = b[ncomp_off]
            comp_start = ncomp_off + 1
            seg_end = min(len(b), s["start"] + 2 + s["length"])
            total_bytes = ncomp * 3
            if comp_start + total_bytes > seg_end or comp_start + total_bytes > len(b):
                continue
            components = []
            for idx in range(ncomp):
                off = comp_start + idx * 3
                if off + 2 >= len(b):
                    components = []
                    break
                components.append(
                    {
                        "index": idx,
                        "id": b[off],
                        "id_off": off,
                        "sample_off": off + 1,
                        "qt_off": off + 2,
                        "sampling": b[off + 1],
                    }
                )
            if not components:
                continue
            return {
                "segment": s,
                "base": base,
                "ncomp_off": ncomp_off,
                "components": components,
            }
        return None

    def _set_dimensions_values(self, b: bytearray, segments, height: int, width: int):
        info = self._get_sof_info(b, segments)
        if not info:
            return False
        if not (0 < height <= 0xFFFF and 0 < width <= 0xFFFF):
            return False
        base = info["base"]
        if base + 3 >= len(b):
            return False
        b[base] = (height >> 8) & 0xFF
        b[base + 1] = height & 0xFF
        b[base + 2] = (width >> 8) & 0xFF
        b[base + 3] = width & 0xFF
        return True

    def _force_subsampling_pattern(
        self,
        b: bytearray,
        segments,
        h_target: int = 2,
        v_target: int = 2,
    ):
        info = self._get_sof_info(b, segments)
        if not info or len(info["components"]) < 2:
            return False
        changed = False
        h = max(1, min(4, h_target))
        v = max(1, min(4, v_target))
        primary = info["components"][0]
        primary_value = ((h & 0xF) << 4) | (v & 0xF)
        if b[primary["sample_off"]] != primary_value:
            b[primary["sample_off"]] = primary_value
            changed = True
        for comp in info["components"][1:]:
            target = 0x11
            if b[comp["sample_off"]] != target:
                b[comp["sample_off"]] = target
                changed = True
        return changed

    def _truncate_or_pad(self, b: bytearray):
        """Occasionally truncate or pad the tail to stress length handling."""
        if random.random() < 0.5 and len(b) > 16:
            # Chop off part of the entropy-coded data.
            cut = random.randint(1, min(len(b) - 2, 2048))
            del b[-cut:]
        elif len(b) < 65500:
            b.extend(os.urandom(random.randint(1, 512)))

    # --- deterministic structural variants used in deterministic_inputs() ---

    def _deterministic_extreme_dimensions(self, b: bytearray):
        segments = self._scan_segments(b)
        sof_markers = {0xC0, 0xC1, 0xC2, 0xC3}
        sofs = [s for s in segments if s["marker"] in sof_markers and s["len_off"] >= 0]
        if not sofs:
            return False
        s = sofs[0]  # pick first SOF deterministically
        base = s["len_off"] + 3
        if base + 3 >= len(b):
            return False
        nh, nw = 0xFFFF, 0xFFFF
        b[base] = (nh >> 8) & 0xFF
        b[base + 1] = nh & 0xFF
        b[base + 2] = (nw >> 8) & 0xFF
        b[base + 3] = nw & 0xFF
        return True

    def _deterministic_segment_length(self, b: bytearray, small: bool):
        segments = self._scan_segments(b)
        candidates = [s for s in segments if s["len_off"] >= 0 and s["length"] is not None]
        if not candidates:
            return False
        s = candidates[0] if small else candidates[-1]
        off = s["len_off"]
        new = 1 if small else 0xFFFE
        if off + 1 >= len(b):
            return False
        b[off] = (new >> 8) & 0xFF
        b[off + 1] = new & 0xFF
        return True

    def _deterministic_dqt_corrupt(self, b: bytearray):
        segments = self._scan_segments(b)
        dqts = [s for s in segments if s["marker"] == 0xDB and s["len_off"] >= 0]
        if not dqts:
            return False
        s = dqts[0]
        start = s["len_off"] + 2
        end = min(len(b), start + max(0, s["length"] - 2))
        if end - start < 8:
            return False
        # Overwrite first 8 bytes of the first DQT payload with extreme values.
        for i in range(8):
            if start + i < end:
                b[start + i] = 0xFF if i % 2 == 0 else 0x00
        return True

    def _deterministic_dht_corrupt(self, b: bytearray):
        segments = self._scan_segments(b)
        dhts = [s for s in segments if s["marker"] == 0xC4 and s["len_off"] >= 0]
        if not dhts:
            return False
        s = dhts[0]
        start = s["len_off"] + 2
        end = min(len(b), start + max(0, s["length"] - 2))
        if end - start < 16:
            return False
        # Set all 16 count bytes to large values to stress Huffman table builder.
        for i in range(16):
            if start + i < end:
                b[start + i] = 0x10
        return True

    def _deterministic_sos_corrupt(self, b: bytearray):
        segments = self._scan_segments(b)
        soss = [s for s in segments if s["marker"] == 0xDA and s["len_off"] >= 0]
        if not soss:
            return False
        s = soss[0]
        base = s["len_off"] + 2
        if base + 1 >= len(b):
            return False
        ncomp = b[base]
        hdr_end = base + 1 + 2 * ncomp + 3
        hdr_end = min(hdr_end, len(b))
        # Force all component ids and table selectors to odd patterns.
        for i in range(base + 1, min(base + 1 + 2 * ncomp, hdr_end), 2):
            if i + 1 >= len(b):
                break
            b[i] = 0xFF
            b[i + 1] = 0xF0
        return True

    def _deterministic_truncate(self, b: bytearray):
        if len(b) > 64:
            # Remove last 1/4 of the file deterministically.
            cut = len(b) // 4
            del b[-cut:]
            return True
        return False

    def _deterministic_pad(self, b: bytearray):
        if len(b) < 65000:
            b.extend(b"\xFF" * 256)
            return True
        return False

    def _deterministic_gray_scan_repeat(self, b: bytearray):
        # Try to convert to grayscale; ignore failures so we still mutate.
        self._convert_to_grayscale_inplace(b)
        return self._repeat_scan_segment(
            b,
            repeats=8000,
            height=0xFFFF,
            width=0xFFFF,
        )

    def _deterministic_upsample_overflow(self, b: bytearray):
        segments = self._scan_segments(b)
        if not segments:
            return False
        changed = False
        changed |= self._set_dimensions_values(b, segments, 65000, 65000)
        changed |= self._force_subsampling_pattern(b, segments, h_target=2, v_target=2)
        return changed

    def _deterministic_upsample_tiny(self, b: bytearray):
        segments = self._scan_segments(b)
        if not segments:
            return False
        changed = False
        changed |= self._set_dimensions_values(b, segments, 4, 4)
        changed |= self._force_subsampling_pattern(b, segments, h_target=2, v_target=2)
        return changed

    # --- helpers for grayscale + scan repeat deterministic variant ---

    def _repeat_scan_segment(
        self,
        b: bytearray,
        *,
        repeats: int,
        height: int,
        width: int,
    ) -> bool:
        if repeats <= 0 or len(b) < 4:
            return False

        try:
            sof = self._find_marker(b, b"\xFF\xC0")
        except RuntimeError:
            return False
        if sof + 9 >= len(b):
            return False

        height_off = sof + 5
        width_off = sof + 7
        b[height_off : height_off + 2] = int(height).to_bytes(2, "big")
        b[width_off : width_off + 2] = int(width).to_bytes(2, "big")

        try:
            sos = self._find_marker(b, b"\xFF\xDA")
        except RuntimeError:
            return False
        if sos + 4 >= len(b):
            return False
        length = int.from_bytes(b[sos + 2 : sos + 4], "big")
        scan_start = sos + 2 + length
        eoi = bytes(b).rfind(b"\xFF\xD9")
        if eoi == -1 or scan_start >= eoi:
            return False

        prefix = bytes(b[:scan_start])
        scan = bytes(b[scan_start:eoi])
        if not scan:
            return False

        suffix = bytes(b[eoi:])
        out = bytearray(prefix)
        # Repeating via extend(scan * repeats) would require large allocations;
        # looped extend uses less temporary memory.
        for _ in range(repeats):
            out.extend(scan)
        out.extend(suffix)
        b[:] = out
        return True

    def _convert_to_grayscale_inplace(self, b: bytearray) -> bool:
        try:
            from PIL import Image  # type: ignore
        except ImportError:
            return False

        data = bytes(b)
        try:
            with Image.open(io.BytesIO(data)) as img:
                gray = img.convert("L")
                buf = io.BytesIO()
                gray.save(buf, format="JPEG")
                new_bytes = buf.getvalue()
        except Exception:
            return False

        b[:] = new_bytes
        return True

    def _find_marker(
        self,
        data: bytearray | bytes,
        marker: bytes,
        start: int = 0,
    ) -> int:
        idx = bytes(data).find(marker, start)
        if idx == -1:
            raise RuntimeError(f"Marker {marker!r} not found")
        return idx
