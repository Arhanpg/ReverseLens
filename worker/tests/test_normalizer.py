from pathlib import Path
import json

from reverselens_worker.normalizer import normalize_engine


def test_androguard_normalizer_emits_hashed_permission_evidence(tmp_path):
    summary = tmp_path / "raw/analysis/androguard-summary.json"
    summary.parent.mkdir(parents=True)
    summary.write_text(json.dumps({
        "package": "org.example.lab",
        "permissions": ["android.permission.INTERNET"],
        "activities": ["org.example.lab.MainActivity"],
        "services": [],
        "receivers": [],
        "providers": [],
        "dex_entries": [{"name": "classes.dex", "size_bytes": 1000}]
    }))
    rows = normalize_engine("androguard", tmp_path)
    keys = {row["canonical_key"] for row in rows}
    assert "package_metadata:org.example.lab" in keys
    assert "permission:android.permission.internet" in keys
    assert all(len(row["evidence_sha256"]) == 64 for row in rows)


def test_apktool_normalizer_extracts_permissions_and_components(tmp_path):
    manifest = tmp_path / "raw/decoded/AndroidManifest.xml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("""<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-permission android:name="android.permission.INTERNET" />
      <application><activity android:name="org.example.MainActivity" /></application>
    </manifest>""")
    rows = normalize_engine("apktool", tmp_path)
    keys = {row["canonical_key"] for row in rows}
    assert "permission:android.permission.internet" in keys
    assert "manifest_component:activity:org.example.mainactivity" in keys


def test_jadx_url_strings_strip_userinfo_query_and_fragment(tmp_path):
    source = tmp_path / "raw/decompiled/demo/Api.java"
    source.parent.mkdir(parents=True)
    source.write_text('''
      class Api {
        String endpoint = "https://user:pass@EXAMPLE.com/v1/items?token=secret#frag";
        String password = "not-for-export";
        String label = "visible client label";
      }
    ''')
    rows = normalize_engine("jadx", tmp_path)
    endpoints = [row["observed_value"] for row in rows if row["item_type"] == "endpoint"]
    strings = [row["observed_value"] for row in rows if row["item_type"] == "string_literal"]
    assert "https://example.com/v1/items" in endpoints
    assert all("secret" not in value and "user:pass" not in value for value in endpoints)
    assert "visible client label" in strings
    assert "not-for-export" not in strings


def test_bundletool_normalizer_emits_split_inventory_and_manifest(tmp_path):
    manifest = tmp_path / "raw/manifest.xml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-permission android:name="android.permission.INTERNET" />
    </manifest>''')
    split_file = tmp_path / "raw/split-inventory.json"
    split_file.write_text(json.dumps({"splits":[{"name":"base-master.apk","size_bytes":4096}]}))
    rows = normalize_engine("bundletool", tmp_path)
    keys = {row["canonical_key"] for row in rows}
    assert "permission:android.permission.internet" in keys
    assert "apk_split:base-master.apk" in keys
