"""Independent Radar exact-source provenance, adaptation custody, and tamper rejection gate (M4/B5)."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import finco_protocol.verification.envelope as env_mod
import finco_radar
import finco_yield
import radar_service


def test_provenance_and_adaptations_match_installed_wheels_with_zero_model_imports() -> None:
    root = Path(__file__).resolve().parents[1]

    # 1. Verify all 4 packages are loaded from installed site-packages (no source-tree leak)
    for mod in (finco_radar, finco_yield, radar_service, env_mod):
        p = Path(mod.__file__).resolve()
        assert "site-packages" in p.parts, f"{mod.__name__} not imported from site-packages: {p}"
        assert "FincoProtocol" not in p.parts, f"Monorepo path leak in {mod.__name__}: {p}"

    # 2. Verify immutable historical provenance manifest (112 finco_radar files + shared envelope + docs)
    prov = json.loads((root / "PROVENANCE_FROM_FINCOPROTOCOL.json").read_text(encoding="utf-8"))
    assert prov["schema"] == "FINCO_RADAR_PROVENANCE_V1"
    assert prov["source_commit"] == "707e68b290694c57b470f4a112c190abb3d02ac9"
    assert prov["source_tree"] == "0d4e8961c33e7bab7aa94077ee4fe9b561061ba2"
    assert prov["file_count"] == len(prov["files"]) and prov["file_count"] >= 200

    installed_radar_root = Path(finco_radar.__file__).resolve().parent
    checked_core = 0
    for entry in prov["files"]:
        if entry["category"] == "RADAR_CORE":
            rel_inside = Path(entry["target_path"]).relative_to("finco_radar")
            installed_file = installed_radar_root / rel_inside
            assert installed_file.is_file(), f"Missing installed wheel file: {rel_inside}"
            assert not installed_file.is_symlink(), f"Forbidden symlink: {rel_inside}"
            actual_sha256 = hashlib.sha256(installed_file.read_bytes()).hexdigest()
            assert actual_sha256 == entry["sha256"], f"Tampered/mismatched wheel file: {rel_inside}"
            checked_core += 1
    assert checked_core == 112

    env_entry = next(e for e in prov["files"] if e["source_path"] == "finco_protocol/verification/envelope.py")
    assert hashlib.sha256(Path(env_mod.__file__).resolve().read_bytes()).hexdigest() == env_entry["sha256"]

    checked_docs = 0
    for entry in prov["files"]:
        if entry["target_path"].startswith("docs/radar/"):
            staged_file = root / entry["target_path"]
            assert staged_file.is_file(), f"Missing staged doc: {entry['target_path']}"
            actual_sha256 = hashlib.sha256(staged_file.read_bytes()).hexdigest()
            assert actual_sha256 == entry["sha256"], f"Tampered/mismatched staged doc: {entry['target_path']}"
            checked_docs += 1
    assert checked_docs >= 28

    # 3. Verify versioned adaptation manifest anchored to predecessor Radar@5034eadc & FincoProtocol@707e68b2
    adapt = json.loads((root / "PROVENANCE_ADAPTATIONS_V2.json").read_text(encoding="utf-8"))
    assert adapt["schema"] == "FINCO_RADAR_PROVENANCE_ADAPTATIONS_V2"
    assert adapt["predecessor_commit"] == "5034eadcae0792506d0e37b44b27e2ba78190fb1"
    assert adapt["source_commit"] == "707e68b290694c57b470f4a112c190abb3d02ac9"
    assert adapt["entry_count"] == len(adapt["entries"]) and adapt["entry_count"] >= 70

    pkg_roots = {
        "finco_yield": Path(finco_yield.__file__).resolve().parent,
        "radar_service": Path(radar_service.__file__).resolve().parent,
    }
    checked_adapted = 0
    for entry in adapt["entries"]:
        tp = entry["target_path"]
        top = tp.split("/", 1)[0]
        if top in pkg_roots:
            rel_inside = Path(tp).relative_to(top)
            inst = pkg_roots[top] / rel_inside
            assert inst.is_file(), f"Missing adapted installed wheel file: {tp}"
            assert not inst.is_symlink(), f"Forbidden symlink: {tp}"
            actual = hashlib.sha256(inst.read_bytes()).hexdigest()
            assert actual == entry["target_sha256"], f"Tampered/mismatched adapted file: {tp}"
            checked_adapted += 1
    assert checked_adapted >= 70

    # 4. Full-tree AST import isolation check across ALL installed packages (zero app.* or Model imports)
    forbidden = ("app", "main_web", "main_api", "financial_engine", "finco_core", "domain", "tax_reference_registry")
    for mod in (finco_radar, finco_yield, radar_service):
        pkg_dir = Path(mod.__file__).resolve().parent
        for pyf in pkg_dir.rglob("*.py"):
            tree = ast.parse(pyf.read_text(encoding="utf-8"), filename=str(pyf))
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods = [node.module]
                for m in mods:
                    root_mod = m.split(".", 1)[0]
                    assert root_mod not in forbidden, f"Forbidden import {m!r} in installed {pyf}"
