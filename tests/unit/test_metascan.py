"""Tests for the metascan module's authoring-software → TECHNOLOGY logic.

`_authoring_tech` was folded in from the former exifmeta module. It operates on
metascan's already-normalized (lowercase-key) metadata dict, so it works
identically for the exiftool and pure-Python extraction paths.
"""
from modules.web.metascan import _authoring_tech


def test_authoring_tech_splits_dotted_version():
    assert _authoring_tech({"software": "Adobe Acrobat 15.7"}) == ("Adobe Acrobat", "15.7")
    # A non-dotted year is not a version — the whole string is the name.
    assert _authoring_tech({"producer": "Microsoft Word 2016"}) == ("Microsoft Word 2016", None)


def test_authoring_tech_no_version():
    assert _authoring_tech({"creatortool": "Skia/PDF"}) == ("Skia/PDF", None)


def test_authoring_tech_field_priority():
    # producer wins over software/application when several are present.
    meta = {"application": "Foo", "software": "Bar 2.0", "producer": "Ghostscript 9.5"}
    assert _authoring_tech(meta) == ("Ghostscript", "9.5")


def test_authoring_tech_creator_requires_software_hint():
    # A bare human name in `creator` must NOT be emitted as a technology.
    assert _authoring_tech({"creator": "Jane Doe"}) is None
    # ...but a software-looking `creator` value is accepted.
    assert _authoring_tech({"creator": "LibreOffice 7.4"}) == ("LibreOffice", "7.4")


def test_authoring_tech_empty_and_non_string():
    assert _authoring_tech({}) is None
    assert _authoring_tech({"producer": ""}) is None
    assert _authoring_tech({"producer": 123}) is None
