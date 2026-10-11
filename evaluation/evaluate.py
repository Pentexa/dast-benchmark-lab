#!/usr/bin/env python3
"""
DAST değerlendirme: tarayıcı raporunu ground-truth ile karşılaştırıp
TP / FP / FN / TN + precision / recall / F1 hesaplar (genel + kategori bazlı).

Kullanım:
  python evaluate.py --findings ornek-zap-findings.json
  python evaluate.py --findings rapor.json --format zap
  python evaluate.py --findings rapor.json --format generic

Generic format: [{"url": "http://localhost:3000/xss/reflected?name=...", "name": "Reflected XSS"}, ...]
ZAP format: OWASP ZAP JSON raporundaki "site > alerts" yapısı otomatik parse edilir.
Nuclei format: -jsonl çıktısındaki her satırdaki "matched-at" alanı parse edilir (--format nuclei).
"""
import json, argparse, sys, os
from urllib.parse import urlparse, unquote
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_PATH = os.path.join(BASE, "ground-truth.json")

def load_gt():
    with open(GT_PATH, encoding="utf-8") as f:
        return json.load(f)

def norm_path(url: str) -> str:
    try:
        p = urlparse(url)
        path = unquote(p.path or "/")
        # /csrf/* ve /cors/* alias'ları ground-truth path'leriyle eşleşir zaten
        return path.rstrip("/") or "/"
    except Exception:
        return url

def gt_match_key(g):
    # trailing slash duyarsız eşleşme
    return (g["method"].upper(), g["path"].rstrip("/") or "/")

def load_findings(path, fmt):
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    if fmt == "zap":
        data = json.loads(raw)
        out = []
        # ZAP JSON raporunda "site" bazen null olur (yanlış rapor tipi / boş tarama).
        # None -> [] yapıp çökme yerine boş liste + uyarı ver.
        sites = data.get("site") or data.get("sites") or []
        if isinstance(sites, dict):
            sites = [sites]
        if not sites:
            print("uyarı: bu ZAP raporunda 'site' boş (null/[]). "
                  "Muhtemelen yanlış rapor tipi indirdin (örn. Auth/Log raporu). "
                  "ZAP'ta Report -> Generate Report -> 'JSON Report' (alert'li olan) seçmelisin.", file=sys.stderr)
        for site in sites:
            if not isinstance(site, dict):
                continue
            for a in site.get("alerts") or []:
                if not isinstance(a, dict):
                    continue
                insts = a.get("instances") or [{}]
                for inst in insts:
                    if not isinstance(inst, dict):
                        inst = {}
                    out.append({"url": inst.get("uri", ""), "name": a.get("name", "")})
                if not a.get("instances"):
                    out.append({"url": "", "name": a.get("name", "")})
        return out
    if fmt == "nuclei":
        out = []
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            try:
                j = json.loads(line)
                out.append({"url": j.get("matched-at", ""), "name": j.get("info", {}).get("name", j.get("template-id", ""))})
            except Exception:
                pass
        return out
    if fmt == "zap-xml":
        import xml.etree.ElementTree as ET
        out = []
        root = ET.fromstring(raw)
        for item in root.iter("alertitem"):
            name = ""
            for tag in ("alert", "name"):
                el = item.find(tag)
                if el is not None and (el.text or "").strip():
                    name = el.text.strip()
                    break
            uris = [u.text.strip() for u in item.iter("uri") if (u.text or "").strip()]
            if not uris:
                uris = [""]
            for u in uris:
                out.append({"url": u, "name": name})
        return out
    if fmt == "sarif":
        data = json.loads(raw)
        out = []
        for run in data.get("runs") or []:
            for res in (run.get("results") if isinstance(run, dict) else None) or []:
                name = res.get("ruleId", "") or (res.get("message", {}) or {}).get("text", "")
                locs = (res.get("locations", []) or [{}])
                for loc in locs:
                    uri = (((loc.get("physicalLocation", {}) or {}).get("artifactLocation", {}) or {}).get("uri", ""))
                    out.append({"url": uri, "name": name})
        return out
    # generic (v2: vuln_id + evidence passthrough — vuln-seviyesi güçlü eşleşme için)
    data = json.loads(raw)
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if isinstance(data, dict):
        raise ValueError(
            "generic format liste bekliyor ([{\"url\":..., \"name\":...}]) ama dict geldi: "
            f"keys={list(data.keys())[:8]}. Eğer bu ZAP raporuysa --format zap kullanmalısın."
        )
    return [{"url": x.get("url", ""), "name": x.get("name", x.get("title", "")),
             "vuln_id": x.get("vuln_id") or x.get("vulnId"),
             "evidence": x.get("evidence")} for x in data]

def match_ground_truth(normpath, gt):
    """Normalize edilmiş path'i ground-truth girdisiyle eşleştir (veya None).
    Kurallar: exact (trailing-slash duyarsız) + ':id' placeholder prefix + MIS-DIR-01 dizin."""
    for g in gt:
        gp = (g["path"].rstrip("/") or "/")
        if "/:" in gp:
            prefix = gp.split("/:", 1)[0]
            if normpath == prefix or normpath.startswith(prefix + "/"):
                return g
            continue
        if normpath == gp:
            return g
        if g["id"] == "MIS-DIR-01" and normpath.startswith(gp + "/"):
            return g
    return None


def compute_metrics(findings, gt):
    """Bulguları GT ile karşılaştır; skor + kategori/zorluk kırılımı döndür (yan etkisiz).

    P0 v2 eşleştirme (vuln-seviyesi):
    - Bulgu `vuln_id` taşıyor ve GT'de varsa -> GÜÇLÜ (strong) iddia (doğrudan satır).
    - Yoksa path-fallback -> ZAYIF (weak) iddia (eski davranış, geriye uyumlu).
    - Aynı satırda strong > weak önceliği; skor satır-bazlı hesaplanır.
    """
    gt_by_id = {g["id"]: g for g in gt}
    expected_vuln = {(m, p) for (m, p) in (gt_match_key(g) for g in gt if g["expectation"] == "vulnerable")}
    expected_safe = {(m, p) for (m, p) in (gt_match_key(g) for g in gt if g["expectation"] in ("secure", "fp-trap"))}

    # URL -> ground truth eşleşmesi (method-agnostik; DAST FP ölçümü URL bazlıdır)
    flagged = set()
    strong_rows, weak_rows = set(), set()
    for fl in findings:
        vid = (fl.get("vuln_id") or "").strip() if isinstance(fl.get("vuln_id"), str) else fl.get("vuln_id")
        if vid and vid in gt_by_id:
            g = gt_by_id[vid]
            flagged.add((None, (g["path"].rstrip("/") or "/")))
            strong_rows.add(g["id"])
            continue
        g = match_ground_truth(norm_path(fl.get("url", "")), gt)
        if g:
            flagged.add((None, (g["path"].rstrip("/") or "/")))
            weak_rows.add(g["id"])
    weak_rows -= strong_rows

    vuln_paths = {p for (_, p) in expected_vuln}
    safe_paths = {p for (_, p) in expected_safe}
    flagged_paths = {p for (_, p) in flagged}

    TP = len(vuln_paths & flagged_paths)
    FN = len(vuln_paths - flagged_paths)
    FP = len(safe_paths & flagged_paths)
    TN = len(safe_paths - flagged_paths)

    def prf(tp, fp, fn):
        prec = tp / (tp + fp) if (tp + fp) else 0
        rec = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
        return prec, rec, f1

    prec, rec, f1 = prf(TP, FP, FN)
    cats = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
    for g in gt:
        p = g["path"].rstrip("/") or "/"
        cat = g["category"]
        is_v = g["expectation"] == "vulnerable"
        hit = p in flagged_paths
        if is_v and hit: cats[cat]["TP"] += 1
        elif is_v and not hit: cats[cat]["FN"] += 1
        elif not is_v and hit: cats[cat]["FP"] += 1
        else: cats[cat]["TN"] += 1
    for cat, v in cats.items():
        pv, rv, f1v = prf(v["TP"], v["FP"], v["FN"])
        v.update(precision=round(pv, 4), recall=round(rv, 4), f1=round(f1v, 4))

    diffs = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
    for g in gt:
        p = g["path"].rstrip("/") or "/"
        d = g.get("difficulty") or "medium"
        is_v = g["expectation"] == "vulnerable"
        hit = p in flagged_paths
        if is_v and hit: diffs[d]["TP"] += 1
        elif is_v and not hit: diffs[d]["FN"] += 1
        elif not is_v and hit: diffs[d]["FP"] += 1
        else: diffs[d]["TN"] += 1
    for d, v in diffs.items():
        pv, rv, f1v = prf(v["TP"], v["FP"], v["FN"])
        v.update(precision=round(pv, 4), recall=round(rv, 4), f1=round(f1v, 4))

    fn_list = [g["id"] for g in gt if g["expectation"] == "vulnerable" and (g["path"].rstrip('/') or '/') not in flagged_paths]
    fp_list = [g["id"] for g in gt if g["expectation"] != "vulnerable" and (g["path"].rstrip('/') or '/') in flagged_paths]

    return {
        "TP": TP, "FP": FP, "FN": FN, "TN": TN,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "fpr": round(FP / (FP + TN) if (FP + TN) else 0, 4),
        "by_category": dict(sorted(cats.items())),
        "by_difficulty": dict(sorted(diffs.items())),
        "match_strength": {"strong": len(strong_rows), "weak": len(weak_rows)},
        "fn_list": fn_list, "fp_list": fp_list,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True, help="Tarayıcı bulgu dosyası (json)")
    ap.add_argument("--format", default="generic", choices=["generic", "zap", "zap-xml", "sarif", "nuclei"])
    args = ap.parse_args()

    gt = load_gt()
    findings = load_findings(args.findings, args.format)
    if not findings:
        print("uyarı: 0 bulgu parse edildi. Dosya boş ya da yanlış rapor tipi olabilir. "
              "ZAP için Report -> Generate Report -> JSON Report seçtiğinden emin ol.", file=sys.stderr)
    m = compute_metrics(findings, gt)
    TP, FP, FN, TN = m["TP"], m["FP"], m["FN"], m["TN"]

    print(f"\n=== GENEL SONUÇ ({len(gt)} endpoint, {len(findings)} bulgu) ===")
    print(f"TP={TP}  FP={FP}  FN={FN}  TN={TN}")
    print(f"Precision={m['precision']:.3f}  Recall={m['recall']:.3f}  F1={m['f1']:.3f}  FPR={m['fpr']:.3f}")
    print(f"Eşleşme gücü: strong(vuln_id)={m['match_strength']['strong']} weak(path)={m['match_strength']['weak']}")

    print("\n=== KATEGORİ BAZLI ===")
    print(f"{'Kategori':<22} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  Prec   Rec    F1")
    for cat, v in sorted(m["by_category"].items()):
        print(f"{cat:<22} {v['TP']:>3} {v['FP']:>3} {v['FN']:>3} {v['TN']:>3}  {v['precision']:.2f}  {v['recall']:.2f}  {v['f1']:.2f}")

    print("\n=== ZORLUK BAZLI ===")
    print(f"{'Zorluk':<12} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  Prec   Rec    F1")
    for d, v in sorted(m["by_difficulty"].items()):
        print(f"{d:<12} {v['TP']:>3} {v['FP']:>3} {v['FN']:>3} {v['TN']:>3}  {v['precision']:.2f}  {v['recall']:.2f}  {v['f1']:.2f}")

    gt_by_id = {g["id"]: g for g in gt}
    print("\n--- Kaçanlar (FN: bulamadıkları) ---")
    for fid in m["fn_list"]:
        g = gt_by_id[fid]
        print(f"  [FN] {g['id']} {g['method']} {g['path']} ({g['vuln_type']})")
    print("\n--- Yanlış alarmlar (FP) ---")
    for fid in m["fp_list"]:
        g = gt_by_id[fid]
        print(f"  [FP] {g['id']} {g['method']} {g['path']} ({g['vuln_type']})")

if __name__ == "__main__":
    main()
