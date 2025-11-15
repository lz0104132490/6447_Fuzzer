import os
import json
import csv
import signal
import xml.etree.ElementTree as ET

def is_numeric(s: str) -> bool:
    try:
        float(s)
        return True
    except (ValueError, TypeError):
        return False

def detect_format(seed_path):
    # Try binary magic numbers first
    try:
        with open(seed_path, 'rb') as fb:
            head = fb.read(8192)
    except Exception:
        head = b""

    if head.startswith(b"\xFF\xD8\xFF"):
        return "jpeg"
    if head.startswith(b"\x7FELF"):
        return "elf"
    if head.startswith(b"%PDF-"):
        return "pdf"

    # Fallback to text-based format checks
    try:
        with open(seed_path, 'r', errors='ignore') as f:
            text_probe = f.read(4096)
    except Exception:
        text_probe = ""

    # JSON
    try:
        json.loads(text_probe)
        return "json"
    except Exception:
        pass

    # XML
    try:
        ET.fromstring(text_probe.strip())
        return "xml"
    except Exception:
        pass

    # CSV
    try:
        csv.Sniffer().sniff(text_probe)
        return "csv"
    except Exception:
        return "text"

def signal_name(sig: int) -> str:
    try:
        return signal.Signals(sig).name
    except Exception:
        return f"SIG{sig}"