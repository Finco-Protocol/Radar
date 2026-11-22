"""Standalone FincoRadar wheel provenance, AST boundary, and authentic terminal boot checks."""

from __future__ import annotations

import ast
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

import finco_radar
from finco_radar.terminal.presenter import reconstruct_terminal_digest
from finco_radar.terminal.web import ROOT as TERMINAL_ROOT, create_radar_app
from tests.test_radar_r6_terminal import terminal as build_r6_terminal


FORBIDDEN_MONOREPO_ROOTS = frozenset(
    {
        "financial_engine",
        "finco_core",
        "domain",
        "tax_reference_registry",
        "app",
        "finco_yield",
        "main_web",
        "main_api",
    }
)


def scan_forbidden_imports(
    package_root: Path,
    forbidden_roots: frozenset[str] = FORBIDDEN_MONOREPO_ROOTS,
) -> tuple[int, list[str]]:
    """Fail-closed static AST scan for forbidden Model/host imports.

    Checks ``import``, ``from ... import``, and literal constant-string calls to
    ``importlib.import_module(...)`` / ``__import__(...)``. Arbitrary runtime-computed
    dynamic import strings are an explicit limitation of static AST analysis.
    """
    if not package_root.is_dir():
        return 0, [f"{package_root}: missing package directory"]
    py_files = sorted(package_root.rglob("*.py"))
    if not py_files:
        return 0, [f"{package_root}: no Python files found"]

    violations: list[str] = []
    for path in py_files:
        rel = path.relative_to(package_root).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            violations.append(f"{rel}: {type(exc).__name__}: {exc}")
            continue

        importlib_aliases = {"importlib"}
        import_module_aliases: set[str] = set()
        builtins_aliases = {"builtins"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if alias.name == "importlib":
                        importlib_aliases.add(alias.asname or "importlib")
                    elif alias.name == "builtins":
                        builtins_aliases.add(alias.asname or "builtins")
                    if root in forbidden_roots:
                        violations.append(f"{rel}:{node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                root = node.module.split(".", 1)[0]
                if node.module == "importlib":
                    for alias in node.names:
                        if alias.name == "import_module":
                            import_module_aliases.add(alias.asname or "import_module")
                if root in forbidden_roots:
                    violations.append(f"{rel}:{node.lineno}: from {node.module} import ...")

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                is_dyn = (
                    (isinstance(func, ast.Name) and (func.id == "__import__" or func.id in import_module_aliases))
                    or (
                        isinstance(func, ast.Attribute)
                        and isinstance(func.value, ast.Name)
                        and (
                            (func.attr == "import_module" and func.value.id in importlib_aliases)
                            or (func.attr == "__import__" and func.value.id in builtins_aliases)
                        )
                    )
                )
                if not is_dyn:
                    continue
                target_node = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "name"), None)
                if isinstance(target_node, ast.Constant) and isinstance(target_node.value, str):
                    target = target_node.value
                    if target and not target.startswith(".") and target.split(".", 1)[0] in forbidden_roots:
                        violations.append(f"{rel}:{node.lineno}: dynamic import {target!r}")

    return len(py_files), violations


def test_installed_wheel_origin_has_no_monorepo_leakage() -> None:
    pkg_file = Path(finco_radar.__file__).resolve()
    assert "FincoProtocol" not in pkg_file.parts, f"Leaked monorepo import: {pkg_file}"
    assert "site-packages" in pkg_file.parts, f"Expected wheel install in site-packages, got: {pkg_file}"
    assert (TERMINAL_ROOT / "templates" / "radar_terminal.html").is_file()
    assert (TERMINAL_ROOT / "static" / "radar_terminal.css").is_file()
    assert (TERMINAL_ROOT / "static" / "radar_terminal.js").is_file()
    assert (pkg_file.parent / "venues" / "data" / "venue_registry_seed.json").is_file()


def test_installed_finco_radar_ast_boundary_has_zero_model_or_app_imports() -> None:
    pkg_root = Path(finco_radar.__file__).resolve().parent
    scanned, violations = scan_forbidden_imports(pkg_root)
    assert scanned == 108, f"Expected 108 Python files in installed wheel, got {scanned}"
    assert violations == [], f"Forbidden imports detected: {violations}"


@pytest.mark.parametrize(
    ("snippet", "expected"),
    [
        ("import financial_engine.foo\n", "financial_engine.foo"),
        ("from finco_core.bar import X\n", "finco_core.bar"),
        ("from domain import x\n", "domain"),
        ("from tax_reference_registry.x import y\n", "tax_reference_registry.x"),
        ("import app.auth\n", "app.auth"),
        ("import importlib\nimportlib.import_module('financial_engine.x')\n", "financial_engine.x"),
        ("__import__('app.radar_ui')\n", "app.radar_ui"),
    ],
)
def test_ast_boundary_rejects_negative_mutants(tmp_path: Path, snippet: str, expected: str) -> None:
    pkg = tmp_path / "synthetic_radar"
    pkg.mkdir()
    (pkg / "mutant.py").write_text(snippet, encoding="utf-8")
    scanned, violations = scan_forbidden_imports(pkg)
    assert scanned == 1 and len(violations) == 1 and expected in violations[0]


def test_authentic_terminal_boot_routes_and_digest_from_installed_wheel() -> None:
    snapshot, _ = build_r6_terminal(buy=("-75", "-80"), sell=("0", "0"))
    assert reconstruct_terminal_digest(snapshot) == snapshot.terminal_snapshot_digest

    app = create_radar_app(lambda: snapshot)
    client = TestClient(app, raise_server_exceptions=True)

    html_resp = client.get("/radar")
    assert html_resp.status_code == 200
    assert snapshot.asset.asset_uid in html_resp.text

    snap_resp = client.get("/radar/api/snapshot")
    assert snap_resp.status_code == 200
    payload = snap_resp.json()
    assert payload["terminalSnapshotDigest"] == snapshot.terminal_snapshot_digest
    assert payload["status"] == "TERMINAL_OK"

    css_resp = client.get("/radar/static/radar_terminal.css")
    assert css_resp.status_code == 200 and len(css_resp.text) > 100

    js_resp = client.get("/radar/static/radar_terminal.js")
    assert js_resp.status_code == 200 and len(js_resp.text) > 100
