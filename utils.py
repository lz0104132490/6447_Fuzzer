import os
import json
import csv
import signal
import xml.etree.ElementTree as ET
import magic
from collections import Counter

def is_numeric(s: str) -> bool:
    try:
        float(s)
        return True
    except (ValueError, TypeError):
        return False


def is_csv_text(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return False

    comma_counts = [ln.count(",") for ln in lines]
    if max(comma_counts) == 0:
        return False

    counter = Counter(comma_counts)
    most_commas, freq = counter.most_common(1)[0]

    if most_commas == 0:
        return False

    if freq < max(2, int(len(lines) * 0.8)):
        return False

    return True


def detect_format(seed_path: str) -> str:
    try:
        m = magic.Magic(mime=True)
        mime_type = (m.from_file(seed_path) or "").lower()
    except Exception:
        mime_type = ""

    if any(key in mime_type for key in ["x-executable", "x-elf", "x-pie-executable"]):
        return "elf"

    if "jpeg" in mime_type or "jpg" in mime_type:
        return "jpeg"

    if "pdf" in mime_type:
        return "pdf"

    if "json" in mime_type:
        return "json"

    if "xml" in mime_type:
        return "xml"

    if "csv" in mime_type:
        return "csv"

    if "octet-stream" in mime_type:
        return "octet"

    if mime_type in ["application/x-unknown", "application/x-generic"]:
        return "octet"

    try:
        with open(seed_path, "r", errors="ignore") as f:
            text_probe = f.read(4096)
    except UnicodeDecodeError:
        return "octet"
    except Exception:
        return "octet"

    stripped = text_probe.strip()

    # JSON
    try:
        json.loads(stripped)
        return "json"
    except Exception:
        pass

    # XML
    try:
        ET.fromstring(stripped)
        return "xml"
    except Exception:
        pass

    # CSV
    if is_csv_text(text_probe):
        return "csv"

    return "text"



def signal_name(sig: int) -> str:
    try:
        return signal.Signals(sig).name
    except Exception:
        return f"SIG{sig}"