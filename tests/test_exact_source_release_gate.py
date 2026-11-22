"""Independent Radar exact-source provenance and tamper rejection gate (M4)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import finco_radar
import finco_protocol.verification.envelope as env_mod
import radar_service


def test_provenance_manifest_is_valid_and_matches_installed_core_blobs() -> None:
    root = Path(__file__).resolve().parents[1]
    prov_path = root / "PROVENANCE_FROM_FINCOPROTOCOL.json"
    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    assert prov["schema"] == "FINCO_RADAR_PROVENANCE_V1"
    assert prov["source_commit"] == "707e68b290694c57b470f4a112c190abb3d02ac9"
    assert prov["source_tree"] == "0d4e8961c33e7bab7aa94077ee4fe9b561061ba2"
    assert prov["file_count"] == len(prov["files"]) and prov["file_count"] >= 200

    # Verify installed finco_radar files in site-packages match exact source SHA-256
    installed_radar_root = Path(finco_radar.__file__).resolve().parent
    checked = 0
    for entry in prov["files"]:
        if entry["category"] == "RADAR_CORE":
            rel_inside = Path(entry["target_path"]).relative_to("finco_radar")
            installed_file = installed_radar_root / rel_inside
            assert installed_file.is_file(), f"Missing installed wheel file: {rel_inside}"
            actual_sha256 = hashlib.sha256(installed_file.read_bytes()).hexdigest()
            assert actual_sha256 == entry["sha256"], f"Tampered/mismatched wheel file: {rel_inside}"
            checked += 1
    assert checked == 112

    # Verify installed shared envelope matches exact provenance SHA-256
    env_entry = next(e for e in prov["files"] if e["source_path"] == "finco_protocol/verification/envelope.py")
    assert hashlib.sha256(Path(env_mod.__file__).resolve().read_bytes()).hexdigest() == env_entry["sha256"]

    # Verify staged docs and deploy files match exact provenance SHA-256
    checked_docs_deploy = 0
    for entry in prov["files"]:
        if entry["target_path"].startswith(("docs/radar/", "deploy/")):
            staged_file = root / entry["target_path"]
            assert staged_file.is_file(), f"Missing staged provenance file: {entry['target_path']}"
            actual_sha256 = hashlib.sha256(staged_file.read_bytes()).hexdigest()
            assert actual_sha256 == entry["sha256"], f"Tampered/mismatched staged file: {entry['target_path']}"
            checked_docs_deploy += 1
    assert checked_docs_deploy >= 28

    # Verify radar_service itself is loaded from site-packages (not monorepo)
    assert "FincoProtocol" not in Path(radar_service.__file__).resolve().parts

