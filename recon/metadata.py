"""
recon.metadata — pure-Python document/image metadata extraction.

The metascan module prefers `exiftool` when the binary is present (richest
output); this module is the dependency-free fallback so metadata analysis works
without it. Given raw file bytes, it extracts author / creator / software /
company / GPS-style metadata that frequently leaks internal usernames, software
versions and internal paths from published documents and images.

Formats:
  * OOXML  (.docx/.xlsx/.pptx) — docProps/core.xml + app.xml  (zip + XML)
  * PDF    (.pdf)              — /Info dictionary + XMP packet   (regex on bytes)
  * JPEG   (.jpg/.jpeg)        — EXIF IFD0 ASCII tags + GPS lat/lon + XMP
  * PNG    (.png)              — tEXt / iTXt chunks

Pure and deterministic: no network, never raises on malformed input (returns {}).
Values are treated as untrusted target output by the caller (sanitized at event
construction). Nothing here asserts anything about a live host.
"""

from __future__ import annotations

import io
import re
import struct
import zipfile

# Extensions worth analyzing (checked on the URL path / filename).
DOC_EXTS = {".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"}
IMG_EXTS = {".jpg", ".jpeg", ".png", ".tif", ".tiff"}
META_EXTS = DOC_EXTS | IMG_EXTS

# Metadata keys that most often leak sensitive information.
_SENSITIVE_KEYS = {
    "author", "creator", "last_modified_by", "lastmodifiedby", "company",
    "manager", "producer", "software", "application", "artist", "make", "model",
    "creatortool", "gps", "gps_latitude", "gps_longitude",
}


# ── format dispatch ────────────────────────────────────────────────────────────

def extract(data: bytes, filename: str = "") -> dict[str, str]:
    """Return a flat {key: value} metadata dict for a file's bytes. Never raises."""
    if not data:
        return {}
    try:
        if data[:4] == b"PK\x03\x04":
            return _ooxml(data)
        if data[:5] == b"%PDF-":
            return _pdf(data)
        if data[:2] == b"\xff\xd8":
            return _jpeg(data)
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return _png(data)
    except Exception:
        return {}
    return {}


def sensitive(meta: dict[str, str]) -> dict[str, str]:
    """Subset of a metadata dict whose keys are of security interest."""
    return {k: v for k, v in meta.items()
            if v and (k.lower() in _SENSITIVE_KEYS or "gps" in k.lower())}


# ── OOXML (docx/xlsx/pptx) ─────────────────────────────────────────────────────

_OOXML_CORE = {
    "creator": "author",
    "lastModifiedBy": "last_modified_by",
    "title": "title",
    "subject": "subject",
    "keywords": "keywords",
    "revision": "revision",
    "created": "created",
    "modified": "modified",
}
_OOXML_APP = {
    "Application": "application",
    "Company": "company",
    "Manager": "manager",
    "AppVersion": "app_version",
}


def _ooxml(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = set(z.namelist())
        if "[Content_Types].xml" not in names:
            return {}
        if "docProps/core.xml" in names:
            _harvest_xml(z.read("docProps/core.xml").decode("utf-8", "replace"), _OOXML_CORE, out)
        if "docProps/app.xml" in names:
            _harvest_xml(z.read("docProps/app.xml").decode("utf-8", "replace"), _OOXML_APP, out)
    return out


def _harvest_xml(xml: str, mapping: dict[str, str], out: dict[str, str]) -> None:
    for tag, key in mapping.items():
        # namespace-agnostic: match <...:tag> or <tag>
        m = re.search(rf"<(?:\w+:)?{re.escape(tag)}\b[^>]*>(.*?)</(?:\w+:)?{re.escape(tag)}>",
                      xml, re.S | re.I)
        if m:
            val = m.group(1).strip()
            if val:
                out[key] = val


# ── PDF ─────────────────────────────────────────────────────────────────────────

_PDF_INFO = {
    "Author": "author",
    "Creator": "creator",
    "Producer": "producer",
    "Title": "title",
    "CreationDate": "created",
    "ModDate": "modified",
}
_XMP_TAGS = {
    "xmp:CreatorTool": "creatortool",
    "dc:creator": "author",
    "xmp:CreateDate": "created",
    "pdf:Producer": "producer",
}


def _pdf(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    text = data.decode("latin-1", "replace")
    for key, norm in _PDF_INFO.items():
        # /Author (value) or /Author <hex>
        m = re.search(rf"/{key}\s*\(([^)]{{0,300}})\)", text)
        if m:
            v = _pdf_unescape(m.group(1)).strip()
            if v:
                out[norm] = v
    _harvest_xmp(text, out)
    return out


def _harvest_xmp(text: str, out: dict[str, str]) -> None:
    for tag, norm in _XMP_TAGS.items():
        m = re.search(rf"<{re.escape(tag)}\b[^>]*>(.*?)</{re.escape(tag)}>", text, re.S)
        if not m:
            continue
        val = m.group(1)
        inner = re.search(r"<rdf:li\b[^>]*>(.*?)</rdf:li>", val, re.S)
        val = (inner.group(1) if inner else val).strip()
        if val and norm not in out:
            out[norm] = val


def _pdf_unescape(s: str) -> str:
    return s.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")


# ── JPEG (EXIF) ──────────────────────────────────────────────────────────────────

_EXIF_TAGS = {0x010F: "make", 0x0110: "model", 0x0131: "software",
              0x013B: "artist", 0x0132: "datetime", 0x8298: "copyright"}


def _jpeg(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    seg = _find_app1_exif(data)
    if seg:
        try:
            _parse_exif(seg, out)
        except Exception:
            pass
    # XMP (Adobe) packet, if present
    text = data.decode("latin-1", "replace")
    _harvest_xmp(text, out)
    m = re.search(r"<xmp:CreatorTool\b[^>]*>(.*?)</xmp:CreatorTool>", text, re.S)
    if m and "creatortool" not in out:
        out["creatortool"] = m.group(1).strip()
    return out


def _find_app1_exif(data: bytes) -> bytes | None:
    i = 2
    n = len(data)
    while i + 4 < n:
        if data[i] != 0xFF:
            break
        marker = data[i + 1]
        size = struct.unpack(">H", data[i + 2:i + 4])[0]
        if marker == 0xE1 and data[i + 4:i + 10] == b"Exif\x00\x00":
            return data[i + 10:i + 2 + size]
        if marker in (0xD8, 0xD9) or size < 2:
            break
        i += 2 + size
    return None


def _parse_exif(tiff: bytes, out: dict[str, str]) -> None:
    if len(tiff) < 8:
        return
    endian = "<" if tiff[:2] == b"II" else ">"
    ifd0 = struct.unpack(endian + "I", tiff[4:8])[0]
    gps_off = _read_ifd(tiff, ifd0, endian, out, _EXIF_TAGS, gps_tag=0x8825)
    if gps_off:
        _read_gps(tiff, gps_off, endian, out)


def _read_ifd(tiff, offset, endian, out, tagmap, gps_tag=None) -> int | None:
    if offset + 2 > len(tiff):
        return None
    count = struct.unpack(endian + "H", tiff[offset:offset + 2])[0]
    gps_off = None
    for k in range(count):
        e = offset + 2 + k * 12
        if e + 12 > len(tiff):
            break
        tag, typ, cnt = struct.unpack(endian + "HHI", tiff[e:e + 8])
        valoff = tiff[e + 8:e + 12]
        if gps_tag and tag == gps_tag:
            gps_off = struct.unpack(endian + "I", valoff)[0]
            continue
        if tag in tagmap and typ == 2:  # ASCII
            length = cnt
            if length <= 4:
                raw = valoff[:length]
            else:
                p = struct.unpack(endian + "I", valoff)[0]
                raw = tiff[p:p + length]
            val = raw.split(b"\x00", 1)[0].decode("latin-1", "replace").strip()
            if val:
                out[tagmap[tag]] = val
    return gps_off


def _read_gps(tiff, offset, endian, out) -> None:
    if offset + 2 > len(tiff):
        return
    count = struct.unpack(endian + "H", tiff[offset:offset + 2])[0]
    gps: dict[int, object] = {}
    for k in range(count):
        e = offset + 2 + k * 12
        if e + 12 > len(tiff):
            break
        tag, typ, cnt = struct.unpack(endian + "HHI", tiff[e:e + 8])
        valoff = tiff[e + 8:e + 12]
        if tag in (1, 3):      # N/S, E/W ref
            gps[tag] = valoff[:1].decode("latin-1", "replace")
        elif tag in (2, 4) and typ == 5:   # lat/lon rationals (3x)
            p = struct.unpack(endian + "I", valoff)[0]
            gps[tag] = _rationals(tiff, p, 3, endian)
    lat = _dms(gps.get(2), gps.get(1))
    lon = _dms(gps.get(4), gps.get(3))
    if lat is not None:
        out["gps_latitude"] = f"{lat:.6f}"
    if lon is not None:
        out["gps_longitude"] = f"{lon:.6f}"


def _rationals(tiff, p, n, endian):
    vals = []
    for i in range(n):
        num, den = struct.unpack(endian + "II", tiff[p + i * 8:p + i * 8 + 8])
        vals.append(num / den if den else 0.0)
    return vals


def _dms(vals, ref):
    if not vals or len(vals) < 3:
        return None
    deg = vals[0] + vals[1] / 60 + vals[2] / 3600
    if ref in ("S", "W"):
        deg = -deg
    return deg


# ── PNG (text chunks) ─────────────────────────────────────────────────────────

def _png(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    i = 8
    n = len(data)
    while i + 8 <= n:
        length = struct.unpack(">I", data[i:i + 4])[0]
        ctype = data[i + 4:i + 8]
        chunk = data[i + 8:i + 8 + length]
        if ctype in (b"tEXt", b"iTXt"):
            kw, _, rest = chunk.partition(b"\x00")
            key = kw.decode("latin-1", "replace").strip().lower()
            val = rest.split(b"\x00")[-1].decode("utf-8", "replace").strip()
            if key and val:
                out[key] = val
                if "xmp" in key:
                    _harvest_xmp(val, out)
        if ctype == b"IEND":
            break
        i += 12 + length  # length + type + data + CRC
    return out
