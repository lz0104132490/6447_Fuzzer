# typechecker.py
import json

def detect_type(data: bytes) -> str:
    # Check for binary file signatures first
    if data.startswith(b"%PDF"):
        return "PDF"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"\xff\xd8"):
        return "JPEG"
    # Check for textual format indicators
    stripped = data.lstrip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        # Likely JSON (try parse to confirm)
        try:
            json.loads(stripped.decode('utf-8'))
            return "JSON"
        except Exception:
            return "JSON"  # treat it as JSON even if malformed JSON text
    if stripped.startswith(b"<"):
        return "XML"
    # Heuristic for CSV: has commas and multiple lines
    text = data.decode('utf-8', errors='ignore')
    if text.count(",") > 0 and "\n" in text:
        return "CSV"
    # Fallback to generic text
    return "text"
