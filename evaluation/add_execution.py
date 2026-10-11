#!/usr/bin/env python3
"""Add execution field: simulated (mock assertion) vs live (server really performed it).

Rule: simulated = response ASSERTS an event that never happened (fake command output,
fake metadata, fake dumps/secrets, error-text without backend). Default: live.
Usage: python evaluation/add_execution.py [--apply]
"""
import json, os, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_PATH = os.path.join(BASE, "ground-truth.json")
APPLY = "--apply" in sys.argv

# Body-text mocks: no backend, no real action — pattern-match simülasyon.
SIMULATED = {
    "INJ-SQLI-01", "INJ-AUTH-BYPASS-01", "INJ-NOSQLI-01", "INJ-CMDI-01", "INJ-SSTI-01",
    "INJ-LDAP-01", "INJ-XPATH-01", "INJ-XXE-01", "CH-UNION-01", "CH-STACK-01",
    "CH-2ND-02", "CH-SSTI-JINJA", "CH-SSTI-TWIG", "CH-SSTI-FMT", "CH-SSTI-ERB",
    "AC-TRAV-01", "FILE-LFI-01", "FILE-RFI-01", "FILE-WRAP-01", "FILE-UNI-01",
    "FILE-ZIP-01", "FILE-SVG-01", "SSRF-01", "APP-AVATAR-01",
    "EDGE-SSRF-DEC", "EDGE-SSRF-ZERO", "EDGE-SSRF-AT", "EDGE-SSRF-FRAG", "EDGE-SSRF-REDIR",
    "DESER-01", "RT-LOG4J-01", "CRYPTO-PAN-01", "CRYPTO-DEBUG-01", "CRYPTO-GIT-01",
    "CRYPTO-HASH-01", "EXP-ENV-01", "EXP-BAK-01", "EXP-DS-01", "EXP-MAP-01",
    "EXP-SWAG-01", "EXP-ACT-01", "EXP-ROBOTS-01", "API-BOLA-01", "API-EXCESS-01",
    "API-INVITE-01", "GQL-INTROS-01", "GQL-IDOR-01", "GQL2-FED-01", "GQL-BATCH-01",
    "RT-PHPINFO-01", "RT-PKG-01", "RT-COMPOSER-01", "EDGE-CFG-01", "EDGE-XDOM-01",
    "MIS-DIR-01", "MIS-DEFAULT-01", "RT-MAILHDR-01", "CH-LEGACY-01", "XSS-MXSS-01",
    "RT-LOGPOISON-01", "RT-BLINDXSS-02", "XSS2-BLIND-ROLE-02",
}


def main():
    gt = json.load(open(GT_PATH, encoding="utf-8"))
    n_sim = 0
    for g in gt:
        if g["expectation"] != "vulnerable":
            g["execution"] = "n/a"
            continue
        g["execution"] = "simulated" if g["id"] in SIMULATED else "live"
        n_sim += g["execution"] == "simulated"
    from collections import Counter
    print("execution:", dict(Counter(g["execution"] for g in gt if g["expectation"] == "vulnerable")))
    unknown = sorted(SIMULATED - {g["id"] for g in gt})
    if unknown:
        print("STALE SIM IDS:", unknown)
    if APPLY:
        json.dump(gt, open(GT_PATH, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"applied: {len(gt)} rows")
    else:
        print("dry-run (use --apply to write)")


if __name__ == "__main__":
    main()
