"""
Tests for the pure-Python metadata engine (recon.metadata) using real generated
fixtures (a genuine OOXML zip, a PNG with text chunks, a PDF with an Info dict).
No external binary required.
"""

from __future__ import annotations

import io
import struct
import zipfile

from recon import metadata


# ── fixture builders (produce byte-accurate real files) ──────────────────────

def make_docx(creator="jsmith", last_mod="admin", company="Acme Corp", app="Microsoft Word"):
    core = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="ns" xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:creator>{creator}</dc:creator>
<cp:lastModifiedBy>{last_mod}</cp:lastModifiedBy>
<dc:title>Quarterly Report</dc:title>
</cp:coreProperties>"""
    app_xml = f"""<?xml version="1.0"?>
<Properties><Application>{app}</Application><Company>{company}</Company></Properties>"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app_xml)
    return buf.getvalue()


def make_png_with_text(software="Adobe Photoshop", author="jdoe"):
    def chunk(ctype, data):
        return struct.pack(">I", len(data)) + ctype + data + b"\x00\x00\x00\x00"
    out = b"\x89PNG\r\n\x1a\n"
    out += chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    out += chunk(b"tEXt", b"Software\x00" + software.encode())
    out += chunk(b"tEXt", b"Author\x00" + author.encode())
    out += chunk(b"IEND", b"")
    return out


def make_pdf(author="mjones", producer="LibreOffice 7.2"):
    body = (f"%PDF-1.5\n1 0 obj\n<< /Author ({author}) /Producer ({producer}) "
            f"/Creator (Writer) >>\nendobj\n%%EOF").encode()
    return body


# ── OOXML ─────────────────────────────────────────────────────────────────────

def test_docx_metadata():
    meta = metadata.extract(make_docx(), "report.docx")
    assert meta["author"] == "jsmith"
    assert meta["last_modified_by"] == "admin"
    assert meta["company"] == "Acme Corp"
    assert meta["application"] == "Microsoft Word"
    assert meta["title"] == "Quarterly Report"


def test_docx_sensitive_subset():
    sens = metadata.sensitive(metadata.extract(make_docx(), "x.docx"))
    assert "author" in sens and "company" in sens
    assert "title" not in sens                    # title isn't a sensitive key


# ── PNG ──────────────────────────────────────────────────────────────────────

def test_png_text_chunks():
    meta = metadata.extract(make_png_with_text(), "image.png")
    assert meta.get("software") == "Adobe Photoshop"
    assert meta.get("author") == "jdoe"


# ── PDF ──────────────────────────────────────────────────────────────────────

def test_pdf_info_dict():
    meta = metadata.extract(make_pdf(), "doc.pdf")
    assert meta["author"] == "mjones"
    assert meta["producer"] == "LibreOffice 7.2"
    assert meta["creator"] == "Writer"


# ── JPEG (EXIF) ────────────────────────────────────────────────────────────────

def test_jpeg_exif_software_tag():
    # Minimal JPEG with an APP1/Exif IFD0 containing a Software (0x0131) ASCII tag.
    sw = b"TestCam 1.0\x00"
    endian = b"II"
    # TIFF header @ offset 0 within exif payload: II, 42, IFD0 offset=8
    tiff = endian + struct.pack("<HI", 42, 8)
    # IFD0: 1 entry, Software tag, ASCII(2), count=len, value offset (points after IFD)
    count = 1
    ifd = struct.pack("<H", count)
    val_offset = 8 + 2 + 12 + 4   # header+count+one entry+next-ifd ptr
    ifd += struct.pack("<HHI", 0x0131, 2, len(sw)) + struct.pack("<I", val_offset)
    ifd += struct.pack("<I", 0)   # next IFD = 0
    tiff += ifd + sw
    app1 = b"\xff\xe1" + struct.pack(">H", len(b"Exif\x00\x00" + tiff) + 2) + b"Exif\x00\x00" + tiff
    jpeg = b"\xff\xd8" + app1 + b"\xff\xd9"
    meta = metadata.extract(jpeg, "photo.jpg")
    assert meta.get("software") == "TestCam 1.0"


# ── dispatch / robustness ─────────────────────────────────────────────────────

def test_unknown_and_empty_bytes_safe():
    assert metadata.extract(b"", "x") == {}
    assert metadata.extract(b"not a real file", "x.bin") == {}
    assert metadata.extract(b"\x89PNG\r\n\x1a\n\x00\x00", "trunc.png") == {} or isinstance(
        metadata.extract(b"\x89PNG\r\n\x1a\n\x00\x00", "trunc.png"), dict)


def test_meta_exts_cover_common_formats():
    for e in (".pdf", ".docx", ".xlsx", ".pptx", ".jpg", ".jpeg", ".png"):
        assert e in metadata.META_EXTS
