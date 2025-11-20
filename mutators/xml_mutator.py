import os
import random
import re
from typing import Callable, Optional

from mutators.base import BaseMutator


VERBOSE_DET = os.getenv("FUZZER_VERBOSE_DET", "").lower() in ("1", "true", "yes")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


class XMLMutator(BaseMutator):
    LARGE_ATTR_LEN = 200_000
    PAD_CHUNK_SIZE = 1 * 1024 * 1024
    PAD_TARGET_BYTES = _env_int("XML_PAD_BYTES", 2 * 1024 * 1024 * 1024)
    PAD_LIMIT_BYTES = _env_int("XML_PAD_LIMIT_BYTES", 64 * 1024 * 1024)
    MUTATION_PAD_BYTES = _env_int("XML_MUT_PAD_BYTES", 1 * 1024 * 1024)
    CHILD_OVERFLOW_COUNT = _env_int("XML_CHILD_COUNT", 2048)
    XML_TOKENS = [
        b"<?xml",
        b"version=",
        b"encoding=",
        b"?>",
        b"<",
        b">",
        b"</",
        b"/>",
        b"<!DOCTYPE",
        b"<!ENTITY",
        b"CDATA",
        b"&",
        b";",
        b"xmlns",
        b"xsi:",
        b"schemaLocation",
        b"<html",
        b"<head",
        b"<body",
        b"<div",
        b"<a",
        b"<script",
        b"href=",
        b"src=",
        b"id=",
        b"class=",
        b"style=",
        b"</html>",
        b"</head>",
        b"</body>",
        b"</div>",
    ]
    BAD_VALUES = [
        b"&" * 10000,
        b"<" * 1000,
        b">" * 1000,
        b"<tag>" * 10000,
        b"\x00" * 100,
        b"\xff" * 100,
        b"A" * 100000,
        b"../../../etc/passwd",
        b"file:///etc/passwd",
        b"<script>alert(1)</script>",
        b"javascript:alert(1)",
        b"onerror=alert(1)",
        b'\'" onclick=alert(1)//',
        b"http://" + b"A" * 10000,
        b'href="' + b"x" * 100000 + b'"',
        b'id="' + b"#" * 10000 + b'"',
        b'class="' + b" " * 10000 + b'"',
        b"<div>" * 10000,
        b'<a href="x">' * 1000,
    ]

    def deterministic_inputs(self) -> list[bytes]:
        outs = list(super().deterministic_inputs())

        def add_variant(label: str, builder: Callable[[], Optional[str | bytes]]):
            try:
                candidate = builder()
            except Exception as exc:
                self._log_det_error(label, exc)
                return
            if not candidate:
                return
            # Normalise to bytes so callers always see byte inputs.
            if isinstance(candidate, str):
                outs.append(candidate.encode("utf-8", errors="ignore"))
            elif isinstance(candidate, (bytes, bytearray)):
                outs.append(bytes(candidate))

        if self.seed_text:
            add_variant(
                "seed_with_many_children",
                lambda: self._inject_many_children(self.seed_text),
            )
            add_variant(
                "deeply_nested_nodes",
                lambda: self._deeply_nested_nodes(self.seed_text),
            )

        return outs

    def mutate(self, base: bytes) -> bytes:
        if self.seed_text is None:
            return self.mutate_bytes(base)

        text = self.seed_text

        # Give the href/format-string style mutation a higher chance.
        if random.random() < 0.4:
            mutated = self._overflow_link_href(text)
            return mutated.encode("utf-8", errors="ignore")

        transforms: list[Callable[[str], str]] = [
            lambda s: s.replace("</", "<\\/", 1),
            lambda s: s.replace("=\"", '="\'', 1),
            lambda s: f"<!--{s[:1000]}-->\n{s}",
            lambda s: f"<root id='{random.randint(1,999)}'>\n{s}\n</root>",
            lambda s: f"{s}\n<a{'x'*random.randint(10,200)}/> ",
            self._append_unclosed_attr,
            self._deeply_nested_nodes,
            self._prepend_massive_padding,
            self._insert_xml_bombs,
            self._malform_html_structure,
            self._corrupt_html_tags,
            self._aggressive_tag_corruption,
            self._partial_tag_deletion,
            self._random_tag_mutations,
            self._insert_bad_values,
            self._extract_and_insert_xml_keywords,
        ]

        mutated = random.choice(transforms)(text)
        return mutated.encode("utf-8", errors="ignore")

    # --- deterministic builders -------------------------------------------------

    def _det_wrap_seed(self) -> Optional[str]:
        if not self.seed_text:
            return None
        return f"<root>\n{self.seed_text}\n</root>"

    def _det_comment_seed(self) -> Optional[str]:
        if not self.seed_text:
            return None
        snippet = self.seed_text[:2000]
        return f"<!--{snippet}-->"

    # --- mutation helpers -------------------------------------------------------

    def _append_unclosed_attr(self, text: str) -> str:
        snippet = self._build_unclosed_attr_text(random.randint(5_000, 50_000))
        return f"{text}\n{snippet}"

    def _combine_with_seed(self, malicious_snippet: str) -> str:
        base = self.seed_text or "<root/>"
        return f"{base}\n{malicious_snippet}"

    def _build_unclosed_attr_text(self, length: int) -> str:
        payload = "A" * max(1, length)
        return f'<tag foo="{payload} />'

    def _build_padded_attr_document(self, pad_bytes: int) -> bytes:
        pad = self._build_padding_bytes(pad_bytes)
        doc = (
            b'<?xml version="1.0"?>\n'
            b"<root>\n"
            b"<pad>"
            + pad
            + b"</pad>\n"
            b'<trigger attr="AAA"/>\n'
            b"</root>"
        )
        return doc

    def _prepend_massive_padding(self, text: str) -> str:
        pad_bytes = self._padding_mutation_bytes()
        padding = "P" * pad_bytes
        return f"<root>\n<pad>{padding}</pad>\n<trigger attr=\"AAA\"/>\n{text}\n</root>"

    def _inject_many_children(self, text: str) -> str:
        count = random.randint(65, max(66, self.CHILD_OVERFLOW_COUNT))
        children = self._build_many_children_text(count)
        return f"<root>\n{children}\n{text}\n</root>"

    def _deeply_nested_nodes(self, text: str) -> str:
        depth = random.randint(1400, max(1401, self.CHILD_OVERFLOW_COUNT))
        open_tags = "<a>" * depth
        close_tags = "</a>" * depth
        return open_tags + close_tags

    def _overflow_link_href(self, text: str) -> str:
        data = text.encode("utf-8", errors="ignore")
        if b"<link" not in data and b"href=" not in data:
            return text
        payloads = [
            b"%s",
            b"%s%s%s",
            b"%s%s%s%s%s",
            b"%s" * 10,
            b"%s" * 20,
            b"%n",
            b"%n%n%n",
            b"%s%n",
            b"%p" * 10,
            b"%x" * 10,
            b"%s%s%p%p%n",
            b"%10000s",
            b"%99999s",
            b"%1$s",
            b"%10$s",
            b"%100$s",
            b"%1$n",
            b"AAAA%s%s%s",
        ]
        payload = random.choice(payloads)
        result = re.sub(rb'href="[^"]*"', b'href="' + payload + b'"', data)
        return result.decode("utf-8", errors="ignore")

    def _padding_target_bytes(self) -> int:
        return max(1, min(self.PAD_TARGET_BYTES, self.PAD_LIMIT_BYTES))

    def _padding_mutation_bytes(self) -> int:
        return max(1, min(self.MUTATION_PAD_BYTES, self._padding_target_bytes()))

    def _build_padding_bytes(self, pad_bytes: int) -> bytes:
        pad_bytes = max(1, pad_bytes)
        chunk = b"P" * min(self.PAD_CHUNK_SIZE, pad_bytes)
        buf = bytearray()
        remaining = pad_bytes
        while remaining > 0:
            take = chunk if remaining >= len(chunk) else chunk[:remaining]
            buf.extend(take)
            remaining -= len(take)
        return bytes(buf)

    def _insert_xml_bombs(self, text: str) -> str:
        data = text.encode("utf-8", errors="ignore")
        bomb_patterns = [
            b'<!DOCTYPE lol [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;">]>',
            b'<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            b"&" + b"x" * 1000 + b";",
            b"<tag>" * 1000 + b"</tag>" * 1000,
            b"<script>while(1){}</script>",
            b'<iframe src="javascript:alert(1)">',
            b'<a href="' + b"x" * 100000 + b'">link</a>',
            b'<div id="' + b"#" * 10000 + b'">',
            b"<div>" * 1000 + b"content" + b"</div>" * 1000,
            b'<a href="x">' * 500 + b"link" + b"</a>" * 500,
            b'<a href="' + b"\x00" * 100 + b'">',
            b'<link href="' + b"A" * 100000 + b'" />',
            b"<body " + b'x="1" ' * 10000 + b">",
            b'<div style="' + b"color:red;" * 1000 + b'">',
        ]
        pattern = random.choice(bomb_patterns)
        insert_pos = random.randint(0, len(data))
        result = data[:insert_pos] + pattern + data[insert_pos:]
        return result.decode("utf-8", errors="ignore")

    def _malform_html_structure(self, text: str) -> str:
        data = text.encode("utf-8", errors="ignore")
        result = bytearray(data)
        mutations = [
            lambda d: d.replace(b"<html", b"<html" * 100),
            lambda d: d.replace(b"</html>", b""),
            lambda d: d.replace(b"<head", b"<head><head><head"),
            lambda d: d.replace(b"</body>", b"</body></body></body>"),
            lambda d: d.replace(b"<div", b"<div" * 50),
            lambda d: d.replace(b'href="', b'href=""href="'),
            lambda d: d.replace(b'id="', b'id="' + b"#" * 1000),
            lambda d: d.replace(b'">', b'"' * 100 + b">"),
            lambda d: d.replace(b"http://", b"http://" * 100),
            lambda d: d.replace(b'"', b""),
            lambda d: d.replace(b'"', b"'"),
            lambda d: d.replace(b'="', b"="),
            lambda d: d.replace(b"</", b"<"),
            lambda d: d.replace(b"/>", b">"),
            lambda d: d.replace(b">", b">>"),
            lambda d: d.replace(b"<", b"<<"),
            lambda d: d + b"<unclosed>",
            lambda d: d.replace(b"</div>", b""),
            lambda d: d.replace(b"</a>", b""),
        ]
        mutation = random.choice(mutations)
        return mutation(bytes(result)).decode("utf-8", errors="ignore")

    def _corrupt_html_tags(self, text: str) -> str:
        data = text.encode("utf-8", errors="ignore")
        result = bytearray(data)
        html_corruptions = [
            (b"<html>", b"<html" * 100 + b">"),
            (b"<head>", b"<head><head><head>"),
            (b"<body>", b"<body " + b"x" * 1000 + b">"),
            (b"<div", b"<div" * 50),
            (b"<a href=", b"<a href=" * 10),
            (b"</html>", b""),
            (b"</head>", b"<head>"),
            (b"</body>", b"<body>"),
            (b'href="http://', b'href="' + b"x" * 10000),
            (b'id="#', b'id="' + b"#" * 10000),
            (b'.com"', b".com" + b"x" * 1000 + b'"'),
        ]
        old, new = random.choice(html_corruptions)
        if old in result:
            result = result.replace(old, new, 1)
        return bytes(result).decode("utf-8", errors="ignore")

    def _aggressive_tag_corruption(self, text: str) -> str:
        data = text.encode("utf-8", errors="ignore")
        tags = re.findall(rb"<([a-zA-Z][a-zA-Z0-9]*)", data)
        if not tags:
            return text
        target_tag = random.choice(tags)
        corruptions = [
            lambda t, d: d.replace(
                b"<" + t,
                b"<" + t[: random.randint(1, max(1, len(t) - 1))],
                1,
            ),
            lambda t, d: d.replace(b"<" + t + b">", b"<" + t, 1),
            lambda t, d: d.replace(b"<" + t + b">", b"<" + t + b"xxx>", 1),
            lambda t, d: d.replace(b"<" + t + b">", b"<" + t + b"</a>", 1),
            lambda t, d: d.replace(b"<" + t, b"<" + t + t, 1),
            lambda t, d: d.replace(b"<" + t + b">", b"<" + t + b"\x00>", 1),
            lambda t, d: d.replace(b"</" + t + b">", b"", 1),
            lambda t, d: d.replace(b"<" + t + b">", b"</" + t + b">", 1),
            lambda t, d: d.replace(
                b"</" + t + b">",
                b"</" + t[: random.randint(1, max(1, len(t) - 1))],
                1,
            ),
        ]
        corruption = random.choice(corruptions)
        try:
            result = corruption(target_tag, data)
        except Exception:
            return text
        return result.decode("utf-8", errors="ignore")

    def _partial_tag_deletion(self, text: str) -> str:
        data = text.encode("utf-8", errors="ignore")
        result = bytearray(data)
        if b"<" in result:
            positions = [i for i, bch in enumerate(result) if bch == ord(b"<")]
            if positions:
                pos = random.choice(positions)
                delete_len = random.randint(1, min(5, len(result) - pos - 1))
                result = result[: pos + 1] + result[pos + 1 + delete_len :]
        return bytes(result).decode("utf-8", errors="ignore")

    def _random_tag_mutations(self, text: str) -> str:
        data = text.encode("utf-8", errors="ignore")
        result = bytearray(data)
        tag_positions = [i for i, bch in enumerate(result) if bch == ord(b"<")]
        if not tag_positions:
            return text
        pos = random.choice(tag_positions)
        for i in range(random.randint(1, 3)):
            if pos + 1 + i < len(result):
                result[pos + 1 + i] = random.randint(ord("a"), ord("z"))
        return bytes(result).decode("utf-8", errors="ignore")

    def _insert_bad_values(self, text: str) -> str:
        data = text.encode("utf-8", errors="ignore")
        result = bytearray(data)
        bad_value = random.choice(self.BAD_VALUES)
        insert_pos = random.randint(0, len(result))
        result = result[:insert_pos] + bad_value + result[insert_pos:]
        return bytes(result).decode("utf-8", errors="ignore")

    def _extract_and_insert_xml_keywords(self, text: str) -> str:
        data = text.encode("utf-8", errors="ignore")
        result = bytearray(data)
        found_tokens = [token for token in self.XML_TOKENS if token in data]
        if found_tokens and len(result) > 0:
            token = random.choice(found_tokens)
            insert_pos = random.randint(0, len(result))
            repetitions = random.randint(1, 50)
            result = result[:insert_pos] + token * repetitions + result[insert_pos:]
        return bytes(result).decode("utf-8", errors="ignore")

    def _build_many_children_document(self, count: int) -> bytes:
        snippet = self._build_many_children_text(count)
        doc = f'<?xml version="1.0"?>\n<root>\n{snippet}\n</root>'
        return doc.encode("utf-8", errors="ignore")

    def _build_many_children_text(self, count: int) -> str:
        count = max(65, min(count, 512))
        nodes = []
        for i in range(count):
            nodes.append(f'<node idx="{i}"/>')
        return "\n".join(nodes)

    def _log_det_error(self, label: str, exc: Exception) -> None:
        if VERBOSE_DET:
            print(f"[XML deterministic] {label} failed: {exc}")
