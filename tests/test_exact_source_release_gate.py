"""Independent Radar release-integrity gate.

Kept invariants: the four packages are imported from the installed wheels (no source-tree or monorepo leak), no
installed module imports Model code, and the provenance ledgers V1-V5 are present and intact as HISTORICAL records
(schema, anchors, entry counts).

Retired (owner-approved CI normalization, FINCO33): byte equality of the CURRENT installed files with the ledger
hashes. That turned every later Radar change into a new successor ledger. The ledgers stay byte-verifiable against
the commits they describe (e.g. `git show ff90c344:<path> | sha256sum`), which is where that evidence belongs.
"""
from __future__ import annotations

import ast
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

    assert sum(1 for e in prov["files"] if e["category"] == "RADAR_CORE") == 112
    assert all(len(e["sha256"]) == 64 for e in prov["files"])

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
    # every adapted package file still ships in the installed wheels (no silently dropped module)
    for entry in adapt["entries"]:
        tp = entry["target_path"]
        top = tp.split("/", 1)[0]
        if top in pkg_roots:
            inst = pkg_roots[top] / Path(tp).relative_to(top)
            assert inst.is_file() or not tp.endswith(".py"), f"Missing adapted installed wheel module: {tp}"
            assert not inst.is_symlink(), f"Forbidden symlink: {tp}"

    # 3b. Verify immutable V3, V4, and finite successor V5 provenance ledgers
    v3 = json.loads((root / "PROVENANCE_CORRECTION_A_V3.json").read_text(encoding="utf-8"))
    assert v3["schema"] == "FINCO_RADAR_PROVENANCE_CORRECTION_A_V3"
    assert v3["predecessor_pr1_commit"] == "07d6ec88bdd9737e3c4c79aad27bd12ed28875f8"
    assert v3["entry_count"] == len(v3["entries"])

    v4 = json.loads((root / "PROVENANCE_CORRECTION_B_V4.json").read_text(encoding="utf-8"))
    assert v4["schema"] == "FINCO_RADAR_PROVENANCE_CORRECTION_B_V4"
    assert v4["predecessor_pr1_commit"] == "83e8ea22bec5071456eeb0436d3ee67f9cd6aacb"
    assert v4["entry_count"] == len(v4["entries"]) and v4["entry_count"] >= 10

    v5 = json.loads((root / "PROVENANCE_CORRECTION_C_V5.json").read_text(encoding="utf-8"))
    assert v5["schema"] == "FINCO_RADAR_PROVENANCE_CORRECTION_C_V5"
    assert v5["predecessor_pr1_commit"] == "ec07b6d3fb873a32552f921b8693feab21e28540"
    assert v5["entry_count"] == len(v5["entries"]) and v5["entry_count"] >= 7

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
