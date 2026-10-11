#!/usr/bin/env python3
"""P3 reporting: machine-readable JSON + human-readable Markdown benchmark reports.

Sources (one required):
  --run <evaluation/runs/run-*.json>   stored scan record (scan.py finish output)
  --findings <file> --format <fmt>     fresh findings (log window = whole requests.log)

Report contents: TP/FP/FN/TN, Precision/Recall/F1, by class, by difficulty,
by execution (simulated vs live), match strength (strong/weak), coverage,
request stats, duration. Simulated-vs-live is labeled on every listed item.

Usage:
  python evaluation/report.py --run evaluation/runs/run-20261011-111053-ZAP-2.17.json
  python evaluation/report.py --findings zap.json --format zap --scanner "ZAP 2.17" --mode authenticated-full
"""
import json, os, sys, argparse
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "evaluation"))
from evaluate import load_gt, load_findings, compute_metrics, norm_path, match_ground_truth

REPORT_DIR = os.path.join(BASE, "evaluation", "reports")


def coverage_from_log(gt, entries):
    hit = set()
    for e in entries:
        g = match_ground_truth(norm_path(e.get("url", "")), gt)
        if g:
            hit.add(g["id"])
    return hit


def read_log():
    path = os.path.join(BASE, "logs", "requests.log")
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    except FileNotFoundError:
        pass
    return out


def build_report(metrics, gt, extra):
    gt_by_id = {g["id"]: g for g in gt}
    by_exec = {}
    for key in ("TP", "FP", "FN"):
        pass
    # execution split over FN/FP/TP lists
    exec_split = {"live": {"TP": 0, "FN": 0, "FP": 0}, "simulated": {"TP": 0, "FN": 0, "FP": 0}}
    fn_ids = set(metrics["fn_list"])
    fp_ids = set(metrics["fp_list"])
    tp_ids = {g["id"] for g in gt if g["expectation"] == "vulnerable" and g["id"] not in fn_ids}
    for gid in tp_ids:
        ex = gt_by_id[gid].get("execution", "live")
        if ex in exec_split:
            exec_split[ex]["TP"] += 1
    for gid in fn_ids:
        ex = gt_by_id[gid].get("execution", "live")
        if ex in exec_split:
            exec_split[ex]["FN"] += 1
    for gid in fp_ids:
        exec_split.setdefault("n/a", {"TP": 0, "FN": 0, "FP": 0})["FP"] += 1

    def itemize(ids):
        rows = []
        for gid in ids:
            g = gt_by_id[gid]
            rows.append({"id": gid, "method": g["method"], "path": g["path"],
                         "vuln_type": g["vuln_type"], "difficulty": g.get("difficulty"),
                         "execution": g.get("execution")})
        return rows

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": extra.get("scanner", "unknown"),
        "mode": extra.get("mode", "unauthenticated"),
        "target": extra.get("target"),
        "summary": {k: metrics[k] for k in ("TP", "FP", "FN", "TN", "precision", "recall", "f1", "fpr")},
        "match_strength": metrics.get("match_strength"),
        "by_category": metrics.get("by_category"),
        "by_difficulty": metrics.get("by_difficulty"),
        "by_execution": exec_split,
        "coverage": extra.get("coverage"),
        "requests": extra.get("requests"),
        "duration_sec": extra.get("duration_sec"),
        "missed": itemize(metrics["fn_list"]),
        "false_alarms": itemize(metrics["fp_list"]),
    }


def to_markdown(rep):
    s = rep["summary"]
    L = [f"# DAST Benchmark Report — {rep['scanner']}",
         f"",
         f"- **Mode:** {rep['mode']} | **Target:** {rep['target']} | **Generated:** {rep['generated_at']}",
         f"",
         f"## Summary",
         f"",
         f"| TP | FP | FN | TN | Precision | Recall | F1 | FPR |",
         f"|---|---|---|---|---|---|---|---|",
         f"| {s['TP']} | {s['FP']} | {s['FN']} | {s['TN']} | {s['precision']} | {s['recall']} | {s['f1']} | {s['fpr']} |",
         f""]
    if rep.get("match_strength"):
        ms = rep["match_strength"]
        L += [f"Match strength: **strong(vuln_id)={ms['strong']}** weak(path)={ms['weak']}", ""]
    if rep.get("coverage"):
        c = rep["coverage"]
        L += [f"Coverage: **{c['hit']}/{c['total']} ({c['pct']}%)**", ""]
    L += ["## By difficulty", "",
          "| Difficulty | TP | FP | FN | TN | Prec | Rec | F1 |",
          "|---|---|---|---|---|---|---|---|"]
    for d, v in sorted((rep.get("by_difficulty") or {}).items()):
        L += [f"| {d} | {v['TP']} | {v['FP']} | {v['FN']} | {v['TN']} | {v['precision']} | {v['recall']} | {v['f1']} |"]
    L += ["", "## By execution (simulated vs live)", "",
          "| Execution | TP | FN | FP |",
          "|---|---|---|---|"]
    for ex, v in sorted((rep.get("by_execution") or {}).items()):
        L += [f"| {ex} | {v['TP']} | {v['FN']} | {v['FP']} |"]
    L += ["", "> **simulated** = mock assertion (no backend action); **live** = server really performed it (sleep, crypto, lock, cache, echo, state).",
          "", "## Missed (FN)", ""]
    for m in rep["missed"]:
        L += [f"- [{m['id']}] `{m['method']} {m['path']}` ({m['vuln_type']}) — {m['difficulty']}/{m['execution']}"]
    L += ["", "## False alarms (FP)", ""]
    for m in rep["false_alarms"]:
        L += [f"- [{m['id']}] `{m['method']} {m['path']}` ({m['vuln_type']})"]
    L += ["", "## By category", "",
          "| Category | TP | FP | FN | TN | F1 |",
          "|---|---|---|---|---|---|"]
    for c, v in sorted((rep.get("by_category") or {}).items()):
        L += [f"| {c} | {v['TP']} | {v['FP']} | {v['FN']} | {v['TN']} | {v['f1']} |"]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description="DAST benchmark JSON+Markdown reports")
    ap.add_argument("--run", default=None, help="stored scan record (scan.py finish output)")
    ap.add_argument("--findings", default=None)
    ap.add_argument("--format", default="generic", choices=["generic", "zap", "zap-xml", "sarif", "nuclei"])
    ap.add_argument("--scanner", default=None)
    ap.add_argument("--mode", default="unauthenticated",
                    choices=["unauthenticated", "authenticated-full", "advanced-protocol"])
    ap.add_argument("--target", default=os.environ.get("DAST_TARGET", "http://localhost:8800"))
    ap.add_argument("--out", default=None, help="output basename (default: reports/<ts>-<scanner>)")
    args = ap.parse_args()

    gt = load_gt()
    if args.run:
        run = json.load(open(args.run, encoding="utf-8"))
        metrics = run["metrics"]
        # stored runs predate some keys -> fill defaults
        metrics.setdefault("match_strength", {"strong": 0, "weak": "n/a (legacy run)"})
        metrics.setdefault("by_difficulty", {})
        extra = {"scanner": run.get("scanner"), "mode": run.get("mode", "unauthenticated"),
                 "target": run.get("target"),
                 "coverage": {"hit": run.get("requests", {}).get("coverage_endpoints_hit"),
                              "total": run.get("requests", {}).get("coverage_endpoints_total"),
                              "pct": run.get("requests", {}).get("coverage_pct")},
                 "requests": {"total": run.get("requests", {}).get("total_requests")},
                 "duration_sec": run.get("duration_sec")}
        base = args.out or os.path.splitext(os.path.basename(args.run))[0]
    elif args.findings:
        findings = load_findings(args.findings, args.format)
        metrics = compute_metrics(findings, gt)
        log = read_log()
        hit = coverage_from_log(gt, log)
        extra = {"scanner": args.scanner or "unknown", "mode": args.mode, "target": args.target,
                 "coverage": {"hit": len(hit), "total": len(gt),
                              "pct": round(100 * len(hit) / len(gt), 1) if gt else 0},
                 "requests": {"total": len(log)}, "duration_sec": None}
        from re import sub
        base = args.out or (datetime.now(timezone.utc).strftime("report-%Y%m%d-%H%M%S-")
                            + sub(r"[^a-zA-Z0-9._-]+", "-", extra["scanner"]).strip("-"))
    else:
        ap.error("need --run or --findings")
        return

    os.makedirs(REPORT_DIR, exist_ok=True)
    rep = build_report(metrics, gt, extra)
    jp = os.path.join(REPORT_DIR, base + ".json")
    mp = os.path.join(REPORT_DIR, base + ".md")
    json.dump(rep, open(jp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    open(mp, "w", encoding="utf-8").write(to_markdown(rep))
    s = rep["summary"]
    print(f"\n=== REPORT: {rep['scanner']} [{rep['mode']}] ===")
    print(f"TP={s['TP']} FP={s['FP']} FN={s['FN']} TN={s['TN']} | P={s['precision']} R={s['recall']} F1={s['f1']}")
    print(f"json: evaluation/reports/{os.path.basename(jp)}")
    print(f"md:   evaluation/reports/{os.path.basename(mp)}")


if __name__ == "__main__":
    main()
