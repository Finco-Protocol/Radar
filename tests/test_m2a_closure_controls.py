"""M2-A closure controls: R2 negative doc guards, EvidenceEnvelope v1 contract verification,
permitted shared namespace check, and R3 Decimal precision pollution probe."""

from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal, getcontext
import hashlib
from pathlib import Path
import re

import pytest

import finco_protocol
import finco_protocol.verification.envelope as env_mod
import finco_radar
from tests.test_radar_r2_gap import _repo_doc


EXPECTED_ENVELOPE_BLOB_SHA1 = "4d9560f9d874271860757dde7a9f04aa4837d475"
EXPECTED_R2_DOC_BLOB_SHA1 = "0ba3711ac8459376ce8ac76c492d9e8d09cb1a91"


def _git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def test_r2_doc_exact_provenance_and_negative_missing_or_wrong_doc(tmp_path: Path) -> None:
    doc_path = Path(__file__).resolve().parents[1] / "docs" / "radar" / "r2_finco_gap.md"
    assert doc_path.is_file()
    assert _git_blob_sha1(doc_path.read_bytes()) == EXPECTED_R2_DOC_BLOB_SHA1

    # Negative 1: missing doc fails closed with FileNotFoundError
    with pytest.raises(FileNotFoundError):
        _repo_doc(doc_root=tmp_path / "missing_root")

    # Negative 2: wrong/obsolete doc fails the E4 alignment predicate
    wrong_root = tmp_path / "wrong_root"
    (wrong_root / "docs" / "radar").mkdir(parents=True)
    (wrong_root / "docs" / "radar" / "r2_finco_gap.md").write_text(
        "R2 emits no R0 size-impact field.\n", encoding="utf-8"
    )
    wrong_doc = _repo_doc(doc_root=wrong_root)
    assert re.search(r"emits\s+\**no\**\s+R0 size-impact field", wrong_doc, re.IGNORECASE) is not None


def test_shared_envelope_wheel_provenance_and_canonical_contract() -> None:
    env_file = Path(env_mod.__file__).resolve()
    assert "site-packages" in env_file.parts
    assert "FincoProtocol" not in env_file.parts
    assert _git_blob_sha1(env_file.read_bytes()) == EXPECTED_ENVELOPE_BLOB_SHA1

    # Only the verification envelope namespace is installed — no Model modules from finco_protocol
    with pytest.raises(ModuleNotFoundError):
        __import__("finco_protocol.verification.public_corpus")
    with pytest.raises(ModuleNotFoundError):
        __import__("finco_protocol.verification.model")

    # Canonical serialization: Decimal, date, datetime, Unicode, payload-only digest
    payload = {
        "amount": Decimal("123.4500"),
        "as_of_date": date(2026, 11, 22),
        "ts": datetime(2026, 11, 22, 13, 0, 0, tzinfo=timezone.utc),
        "label": "FINCO — café €",
    }
    envelope = env_mod.build_evidence_envelope(
        surface="finco_radar.r11.verification",
        evidence_type="m2a-contract-probe",
        payload=payload,
        authority_refs=("finco_radar.r11",),
    )
    assert envelope.schema == "finco.evidence-envelope.v1"
    assert envelope.canonicalization == "FINCO_SORTED_JSON_V1"
    assert len(envelope.payload_sha256) == 64
    assert envelope.content_address == f"sha256:{envelope.payload_sha256}"

    # Payload-only digest: altering metadata (surface) does not change payload_sha256,
    # while altering payload changes both payload_sha256 and content_address
    envelope_meta_diff = env_mod.build_evidence_envelope(
        surface="finco_radar.r11.other_surface",
        evidence_type="m2a-contract-probe",
        payload=payload,
        authority_refs=("finco_radar.r11",),
    )
    assert envelope_meta_diff.payload_sha256 == envelope.payload_sha256

    tampered = dict(payload)
    tampered["amount"] = Decimal("123.4501")
    envelope_tampered = env_mod.build_evidence_envelope(
        surface="finco_radar.r11.verification",
        evidence_type="m2a-contract-probe",
        payload=tampered,
        authority_refs=("finco_radar.r11",),
    )
    assert envelope_tampered.payload_sha256 != envelope.payload_sha256
    assert envelope_tampered.content_address != envelope.content_address


def test_r3_decimal_context_precision_invariance_probe() -> None:
    """Probe R3 liquidity engine precision invariance (no weakening of Decimal precision)."""
    before_prec = getcontext().prec
    from tests.test_radar_r3_liquidity import test_50_r0_r1_r2_source_behavior_unchanged

    test_50_r0_r1_r2_source_behavior_unchanged()
    assert getcontext().prec == before_prec
    assert Path(finco_radar.__file__).resolve().parts
    assert Path(finco_protocol.__file__).resolve().parts
