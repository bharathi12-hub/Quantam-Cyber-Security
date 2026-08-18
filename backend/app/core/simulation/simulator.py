"""
Migration impact simulation.

Estimates the operational impact of migrating each finding to its PQC target,
grounded in the *real* key/signature/ciphertext sizes of the NIST algorithms
(FIPS 203/204/205) versus classical baselines. These are modeled estimates —
sizes are exact; bandwidth/latency use representative, documented figures.
"""
from __future__ import annotations

from typing import Iterable

from ..detection.rules import RULES_BY_ID

# --- Sizes in bytes (public references) ---------------------------------------
# Classical
RSA2048_PUB, RSA2048_SIG = 270, 256
ECDSA_P256_PUB, ECDSA_P256_SIG = 91, 72
ECDH_X25519_PUB = 32
# Post-quantum (FIPS 203/204/205)
MLKEM768_PUB, MLKEM768_CT = 1184, 1088
MLDSA65_PUB, MLDSA65_SIG = 1952, 3309

# Representative single-TLS-handshake wire cost (key share + leaf cert sig+pub).
_CLASSICAL_HANDSHAKE = ECDH_X25519_PUB * 2 + ECDSA_P256_SIG + ECDSA_P256_PUB       # ~227 B
_PQC_HANDSHAKE = (MLKEM768_PUB + MLKEM768_CT) + MLDSA65_SIG + MLDSA65_PUB           # ~7533 B

_HANDSHAKES_PER_DAY = 1_000_000  # stated assumption for the daily projection


def _pct(before: float, after: float) -> int:
    if before <= 0:
        return 0
    return round((after - before) / before * 100)


def compute(findings: Iterable[dict]) -> dict:
    items = list(findings)
    cats = []
    for f in items:
        rule = RULES_BY_ID.get(f.get("rule_id", ""))
        cats.append(rule.pqc_category if rule else None)

    n_pk = sum(1 for c in cats if c in ("pk-encryption", "key-exchange"))
    n_sig = sum(1 for c in cats if c == "signature")
    n_shor = sum(1 for f in items if f.get("quantum_threat") == "shor")
    total = len(items)

    # --- Aggregate size deltas across affected asymmetric findings ---
    pub_before = n_pk * RSA2048_PUB + n_sig * ECDSA_P256_PUB
    pub_after = n_pk * MLKEM768_PUB + n_sig * MLDSA65_PUB
    sig_before = n_sig * ECDSA_P256_SIG
    sig_after = n_sig * MLDSA65_SIG

    key_before = pub_before + sig_before
    key_after = pub_after + sig_after

    daily_increase_mb = round((_PQC_HANDSHAKE - _CLASSICAL_HANDSHAKE) * _HANDSHAKES_PER_DAY / 1e6)

    metrics = [
        {
            "name": "Public key material",
            "before": pub_before, "after": pub_after, "unit": "B",
            "delta_pct": _pct(pub_before, pub_after),
            "note": "RSA/ECDSA public keys → ML-KEM/ML-DSA keys.",
        },
        {
            "name": "Signature size",
            "before": sig_before, "after": sig_after, "unit": "B",
            "delta_pct": _pct(sig_before, sig_after),
            "note": "ECDSA ~72 B → ML-DSA-65 ~3.3 KB per signature.",
        },
        {
            "name": "Key/cert storage",
            "before": key_before, "after": key_after, "unit": "B",
            "delta_pct": _pct(key_before, key_after),
            "note": "Aggregate at-rest growth for affected keys and certificates.",
        },
    ]

    compatibility_risk = min(90, 20 + round(60 * (n_shor / total))) if total else 0

    if n_sig or n_pk:
        downtime = "Short maintenance window per service"
        downtime_detail = ("Certificate reissuance and key rotation require a brief, scheduled "
                           "window per service. Hybrid deployment avoids a hard cutover.")
    else:
        downtime = "None (rolling config change)"
        downtime_detail = "All remediations are in-place primitive swaps or configuration changes."

    latency_notes = [
        "ML-KEM keygen/encaps/decaps are faster than RSA-2048 in CPU time — the cost is bandwidth, not compute.",
        "ML-DSA verification is fast; signing is moderate. SLH-DSA signing is slow (use for rare, long-lived signatures).",
        "Expect a small added handshake latency from ~1 extra MTU of data per direction.",
    ]

    return {
        "assumptions": {"handshakes_per_day": _HANDSHAKES_PER_DAY},
        "metrics": metrics,
        "bandwidth": {
            "per_handshake_before_b": _CLASSICAL_HANDSHAKE,
            "per_handshake_after_b": _PQC_HANDSHAKE,
            "per_handshake_delta_b": _PQC_HANDSHAKE - _CLASSICAL_HANDSHAKE,
            "delta_pct": _pct(_CLASSICAL_HANDSHAKE, _PQC_HANDSHAKE),
            "projected_daily_increase_mb": daily_increase_mb,
            "note": f"Per-handshake wire growth (hybrid ML-KEM + ML-DSA cert); daily figure assumes "
                    f"{_HANDSHAKES_PER_DAY:,} handshakes/day.",
        },
        "latency": {"rating": "Low to Moderate", "notes": latency_notes},
        "compatibility_risk": compatibility_risk,
        "downtime": {"estimate": downtime, "detail": downtime_detail},
        "api_sites_to_update": n_pk + n_sig,
        "affected": {"key_establishment": n_pk, "signatures": n_sig, "quantum_vulnerable": n_shor},
        "summary": (f"Migrating {n_shor} quantum-vulnerable asset(s) grows asymmetric key/signature "
                    f"material substantially but adds little CPU cost. Primary operational impact is "
                    f"bandwidth (~{_PQC_HANDSHAKE - _CLASSICAL_HANDSHAKE} B/handshake) and certificate "
                    f"size; deploy in hybrid mode to avoid downtime."),
    }
