#!/usr/bin/env python3
"""
Tarama ölçüm kaydı: DAST taramasını başlat/bitir, TP/FP/FN/TN + süre + hata +
istek/coverage istatistiklerini evaluation/runs/ altında kalıcı JSON olarak sakla.

Akış:
  1) python evaluation/scan.py start --scanner "ZAP 2.14"
  2) <tarayıcıyı çalıştır>
  3) python evaluation/scan.py finish --findings zap-rapor.json --format zap --exit-code 0
  4) python evaluation/scan.py list

Kaydedilen parametreler: run_id, scanner, target, started/finished_at, duration_sec,
scanner exit-code/errors/note, istek sayısı + unique path + status dağılımı + 5xx hataları +
yavaş yanıtlar, GT coverage (genel + kategori), OOB tetik sayısı, metrikler + önceki koşuyla delta.
"""
import json, os, sys, argparse, re
from datetime import datetime, timezone
from collections import Counter, defaultdict
from urllib.request import Request, urlopen

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS_DIR = os.path.join(BASE, "evaluation", "runs")
ACTIVE_FILE = os.path.join(BASE, "evaluation", ".scan-active.json")
REQ_LOG = os.path.join(BASE, "logs", "requests.log")
OOB_LOG = os.path.join(BASE, "logs", "oob.log")
TARGET = os.environ.get("DAST_TARGET", "http://localhost:3000")

sys.path.insert(0, os.path.join(BASE, "evaluation"))
from evaluate import load_gt, load_findings, compute_metrics, norm_path, match_ground_truth


def utcnow():
    return datetime.now(timezone.utc)


def parse_ts(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def read_jsonlines(path, since=None, until=None):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                ts = parse_ts(e.get("ts", ""))
                if since and (not ts or ts < since):
                    continue
                if until and ts and ts > until:
                    continue
                out.append(e)
    except FileNotFoundError:
        pass
    return out


def safe_name(s):
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", s or "scanner").strip("-") or "scanner"


def cmd_start(args):
    scan_id = f"run-{utcnow().strftime('%Y%m%d-%H%M%S')}"
    started_at = utcnow().isoformat()
    marker = {"scan_id": scan_id, "scanner": args.scanner, "target": args.target,
              "mode": args.mode, "started_at": started_at}
    # P0 reset: aynı koşullar için sunucu durumunu sıfırla (+tohumla)
    if args.reset or args.seed is not None:
        try:
            payload = {}
            if args.seed is not None:
                payload["seed"] = args.seed
            req = Request(args.target.rstrip("/") + "/api/admin/reset",
                          data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(req, timeout=10) as r:
                print("reset:", r.read().decode()[:160])
        except Exception as e:
            print(f"uyarı: reset atılamadı ({e}) — mevcut durumla devam ediliyor")
    # sunucuya da işaret bırak (başarısız olursa yerel devam)
    try:
        req = Request(args.target.rstrip("/") + "/api/scan/start",
                      data=json.dumps({"scan_id": scan_id, "scanner": args.scanner}).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=5) as r:
            print("sunucu kaydı:", r.read().decode()[:120])
    except Exception as e:
        print(f"uyarı: sunucuya ulaşılamadı ({e}) — yerel işaretle devam ediliyor")
    with open(ACTIVE_FILE, "w", encoding="utf-8") as f:
        json.dump(marker, f, indent=2)
    print(f"\n[+] Tarama başlatıldı\n    scan_id : {scan_id}\n    scanner : {args.scanner}\n    mode    : {args.mode}\n    target  : {args.target}\n    started : {started_at}")
    print("    Şimdi tarayıcıyı çalıştır, bitince 'scan.py finish ...' komutunu ver.")


def window_stats(entries, gt, started=None, finished=None):
    total = len(entries)
    uniq = len({e.get("url", "").split("?")[0] for e in entries})
    by_status = Counter()
    by_method = Counter()
    errs = Counter()
    slow = 0
    max_ms = 0
    slow_paths = Counter()
    signals = Counter()
    hit_ids = set()
    per_path = Counter()
    total_bytes = 0
    robots = False
    points = []  # (start_ts, end_ts) uçuş-içi eşzamanlılık için
    first_seen = {}  # gt_id -> ilk görülme ts (keşif eğrisi)
    for e in entries:
        st = int(e.get("status") or 0)
        bucket = f"{st // 100}xx" if st else "unknown"
        by_status[bucket] += 1
        by_method[e.get("method", "?") or "?"] += 1
        path_only = e.get("url", "").split("?")[0]
        per_path[path_only] += 1
        if st >= 500:
            errs[path_only] += 1
        ms = int(e.get("ms") or 0)
        max_ms = max(max_ms, ms)
        if ms > 2500:
            slow += 1
            slow_paths[path_only] += 1
        total_bytes += int(e.get("bytes") or 0)
        if path_only in ("/robots.txt", "/files/robots.txt"):
            robots = True
        for s in e.get("signals") or []:
            signals[s] += 1
        ts = parse_ts(e.get("ts", ""))
        if ts:
            points.append((ts.timestamp(), ts.timestamp() + max(ms, 1) / 1000.0))
        g = match_ground_truth(norm_path(e.get("url", "")), gt)
        if g and ts:
            if g["id"] not in first_seen:
                first_seen[g["id"]] = ts
            hit_ids.add(g["id"])
    # --- tarayıcı davranış profili ---
    dur = None
    if started and finished:
        dur = max((finished - started).total_seconds(), 0.1)
    req_per_sec = round(total / dur, 2) if dur else 0
    # 10 sn kayan pencerede tepe hız
    peak = 0
    if points:
        starts = sorted(p[0] for p in points)
        j = 0
        for i, t in enumerate(starts):
            while starts[j] + 10 <= t:
                j += 1
            peak = max(peak, i - j + 1)
    peak_10s_rps = round(peak / 10.0, 2)
    # uçuş-içi en yüksek eşzamanlılık (tarama paralelliği)
    max_conc = 0
    if points:
        evts = []
        for s_, e_ in points:
            evts.append((s_, 1))
            evts.append((e_, -1))
        cur = 0
        for _, d in sorted(evts):
            cur += d
            max_conc = max(max_conc, cur)
    # keşif eğrisi: coverage %25/50/75'e kaçıncı saniyede ulaşıldı
    curve = {}
    if first_seen and started and hit_ids:
        ordered = sorted(first_seen.values())
        n = len(ordered)
        for pct in (25, 50, 75):
            idx = min(int(n * pct / 100), n - 1)
            curve[f"t{pct}"] = round((ordered[idx] - started).total_seconds(), 1)
    top_targets = dict(per_path.most_common(8))
    max_hits_1 = per_path.most_common(1)[0][1] if per_path else 0
    cov_cat = {}
    for g in gt:
        c = cov_cat.setdefault(g["category"], {"hit": 0, "total": 0})
        c["total"] += 1
        if g["id"] in hit_ids:
            c["hit"] += 1
    for c in cov_cat.values():
        c["pct"] = round(100 * c["hit"] / c["total"], 1) if c["total"] else 0
    unhit = sorted({g["category"] for g in gt if g["id"] not in hit_ids and g["expectation"] == "vulnerable"
                    and not any(x["id"] in hit_ids for x in gt if x["category"] == g["category"])})
    return {
        "total_requests": total,
        "unique_paths": uniq,
        "by_status": dict(by_status),
        "by_method": dict(by_method),
        "req_per_sec": req_per_sec,
        "peak_10s_rps": peak_10s_rps,
        "max_concurrency": max_conc,
        "discovery_curve_sec": curve,
        "max_hits_single_path": max_hits_1,
        "top_targets": top_targets,
        "payload_variety_signals": len(signals),
        "total_response_bytes": total_bytes,
        "total_response_mb": round(total_bytes / 1048576, 2),
        "fetched_robots_txt": robots,
        "server_errors_5xx": sum(errs.values()),
        "server_errors_by_path": dict(errs.most_common(10)),
        "slow_responses_over_2500ms": slow,
        "max_response_ms": max_ms,
        "slow_by_path": dict(slow_paths.most_common(5)),
        "probe_signals": dict(signals),
        "coverage_endpoints_hit": len(hit_ids),
        "coverage_endpoints_total": len(gt),
        "coverage_pct": round(100 * len(hit_ids) / len(gt), 1) if gt else 0,
        "coverage_by_category": cov_cat,
        "untouched_categories": unhit,
    }


def prev_run(current_id):
    runs = sorted([f for f in os.listdir(RUNS_DIR) if f.endswith(".json") and not f.endswith(".resources.json")]) if os.path.isdir(RUNS_DIR) else []
    runs = [f for f in runs if not f.startswith(current_id)]
    if not runs:
        return None
    try:
        with open(os.path.join(RUNS_DIR, runs[-1]), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def cmd_finish(args):
    if not os.path.exists(ACTIVE_FILE) and not args.started:
        print("hata: aktif tarama yok. Önce 'scan.py start' çalıştır veya --started ISO8601 ver.")
        sys.exit(1)
    if os.path.exists(ACTIVE_FILE):
        with open(ACTIVE_FILE, encoding="utf-8") as f:
            active = json.load(f)
    else:
        active = {"scan_id": f"run-{utcnow().strftime('%Y%m%d-%H%M%S')}", "scanner": args.scanner or "unknown",
                  "target": args.target, "started_at": args.started,
                  "mode": args.mode or "unauthenticated"}
    if args.mode:
        active["mode"] = args.mode
    scanner = args.scanner or active.get("scanner", "unknown")
    started = parse_ts(active["started_at"])
    finished = utcnow()
    duration = round((finished - started).total_seconds(), 1) if started else None

    gt = load_gt()
    findings = load_findings(args.findings, args.format)
    m = compute_metrics(findings, gt)

    entries = read_jsonlines(REQ_LOG, since=started, until=finished)
    stats = window_stats(entries, gt, started, finished)
    oob = read_jsonlines(OOB_LOG, since=started, until=finished)

    # agent.py ile toplanan tarayıcı-makine kaynak verisini göm (varsa)
    resources = None
    _rid = active.get("scan_id", "")
    if os.path.isdir(RUNS_DIR):
        for fn in os.listdir(RUNS_DIR):
            if fn.startswith(_rid) and fn.endswith(".resources.json"):
                try:
                    with open(os.path.join(RUNS_DIR, fn), encoding="utf-8") as f:
                        resources = json.load(f)
                except Exception:
                    pass

    os.makedirs(RUNS_DIR, exist_ok=True)
    run_id = active["scan_id"]
    fname = f"{run_id}-{safe_name(scanner)}.json"
    run = {
        "run_id": run_id,
        "scanner": scanner,
        "mode": active.get("mode", "unauthenticated"),
        "target": active.get("target", args.target),
        "started_at": active["started_at"],
        "finished_at": finished.isoformat(),
        "duration_sec": duration,
        "findings_count": len(findings),
        "scanner_exit_code": args.exit_code,
        "scanner_errors_reported": args.errors,
        "note": args.note or "",
        "requests": stats,
        "scanner_resources": resources,
        "oob_callbacks_in_window": len(oob),
        "metrics": m,
        "delta_vs_previous": None,
    }
    prev = prev_run(run_id)
    if prev and "metrics" in prev:
        pm = prev["metrics"]
        run["delta_vs_previous"] = {
            "run_id": prev.get("run_id"),
            "d_tp": m["TP"] - pm.get("TP", 0),
            "d_fp": m["FP"] - pm.get("FP", 0),
            "d_fn": m["FN"] - pm.get("FN", 0),
            "d_precision": round(m["precision"] - pm.get("precision", 0), 4),
            "d_recall": round(m["recall"] - pm.get("recall", 0), 4),
            "d_f1": round(m["f1"] - pm.get("f1", 0), 4),
        }
    with open(os.path.join(RUNS_DIR, fname), "w", encoding="utf-8") as f:
        json.dump(run, f, indent=2, ensure_ascii=False)
    if os.path.exists(ACTIVE_FILE):
        os.remove(ACTIVE_FILE)

    print(f"\n=== TARAMA KAYDI: {run_id} ({scanner} [{run['mode']}]) ===")
    print(f"süre: {duration} sn | istek: {stats['total_requests']} ({stats['unique_paths']} unique path) | hız: {stats['req_per_sec']}/sn (tepe {stats['peak_10s_rps']}/sn) | paralellik: ~{stats['max_concurrency']} eşzamanlı")
    print(f"bant: {stats['total_response_mb']} MB | tek path'e max: {stats['max_hits_single_path']} istek | sinyal çeşitliliği: {stats['payload_variety_signals']} | robots.txt: {'evet' if stats['fetched_robots_txt'] else 'hayır'}")
    if stats["discovery_curve_sec"]:
        dc = stats["discovery_curve_sec"]
        print(f"keşif eğrisi: %25->{dc.get('t25')}sn %50->{dc.get('t50')}sn %75->{dc.get('t75')}sn")
    print(f"status: {stats['by_status']} | sunucu 5xx: {stats['server_errors_5xx']} | yavaş(>2.5s): {stats['slow_responses_over_2500ms']} (max {stats['max_response_ms']}ms)")
    if resources:
        print(f"tarayıcı makine: CPU tepe %{resources.get('sys_cpu_peak')} / RAM tepe %{resources.get('sys_mem_peak')} ({resources.get('samples', 0)} örnek, {resources.get('collector', '?')})")
    print(f"coverage: {stats['coverage_endpoints_hit']}/{stats['coverage_endpoints_total']} endpoint (%{stats['coverage_pct']}) | OOB tetik: {len(oob)}")
    if stats["untouched_categories"]:
        print(f"hiç dokunulmayan kategoriler: {', '.join(stats['untouched_categories'])}")
    print(f"bulgu: {len(findings)} | TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']} | P={m['precision']} R={m['recall']} F1={m['f1']}")
    try:
        with open(os.path.join(BASE, "evaluation", "verification.json"), encoding="utf-8") as f:
            v = json.load(f)
        print(f"doğrulanmış zafiyet: {v.get('verified')}/{v.get('total_vulnerable')} ({v.get('timestamp','?')})")
    except Exception:
        print("doğrulanmış zafiyet: bilinmiyor (python evaluation/verify.py çalıştır)")
    print(f"tarayıcı hatası (bildirilen): exit={args.exit_code} errors={args.errors}")
    if run["delta_vs_previous"]:
        d = run["delta_vs_previous"]
        print(f"önceki ({d['run_id']}) vs delta: dTP={d['d_tp']} dFP={d['d_fp']} dFN={d['d_fn']} dF1={d['d_f1']:+}")
    print(f"\nkayıt: evaluation/runs/{fname}")


def cmd_list(args):
    if not os.path.isdir(RUNS_DIR):
        print("kayıt yok.");
        return
    files = sorted(f for f in os.listdir(RUNS_DIR) if f.endswith(".json"))
    if not files:
        print("kayıt yok.");
        return
    print(f"{'run_id':<22} {'scanner':<14} {'mode':<11} {'süre':>7} {'istek':>6} {'hız':>6} {'par':>4} {'cov%':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}   F1    CPU  MEM  5xx  OOB")
    for fn in files if not args.last else files[-args.last:]:
        if fn.endswith(".resources.json"):
            continue
        try:
            with open(os.path.join(RUNS_DIR, fn), encoding="utf-8") as f:
                r = json.load(f)
            m = r.get("metrics", {})
            q = r.get("requests", {})
            res = r.get("scanner_resources") or {}
            print(f"{r.get('run_id','?'):<22} {str(r.get('scanner','?'))[:14]:<14} {str(r.get('mode','-'))[:11]:<11} {str(r.get('duration_sec')):>7} "
                  f"{q.get('total_requests',0):>6} {str(q.get('req_per_sec','-')):>6} {str(q.get('max_concurrency','-')):>4} "
                  f"{str(q.get('coverage_pct','-')):>6} {m.get('TP',0):>4} {m.get('FP',0):>4} "
                  f"{m.get('FN',0):>4} {m.get('TN',0):>4}   {m.get('f1',0):<5} "
                  f"{str(res.get('sys_cpu_peak','-')):>4} {str(res.get('sys_mem_peak','-')):>4} "
                  f"{q.get('server_errors_5xx',0):>4}  {r.get('oob_callbacks_in_window',0):>3}")
        except Exception as e:
            print(f"{fn}: okunamadı ({e})")


def main():
    ap = argparse.ArgumentParser(description="DAST tarama ölçüm kaydı")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start", help="taramayı başlat (işaret koy)")
    s.add_argument("--scanner", required=True, help='tarayıcı adı, örn "ZAP 2.14"')
    s.add_argument("--target", default=TARGET)
    s.add_argument("--mode", default="unauthenticated",
                   choices=["unauthenticated", "authenticated-full", "advanced-protocol"],
                   help="tarama modu (P3)")
    s.add_argument("--reset", action="store_true", help="başlamadan sunucu durumunu sıfırla")
    s.add_argument("--seed", type=int, default=None, help="sıfırlarken tohumla (tekrarlanabilirlik)")
    s.set_defaults(fn=cmd_start)
    f = sub.add_parser("finish", help="taramayı bitir + ölç + kaydet")
    f.add_argument("--findings", required=True)
    f.add_argument("--format", default="generic", choices=["generic", "zap", "zap-xml", "sarif", "nuclei"])
    f.add_argument("--scanner", default=None)
    f.add_argument("--target", default=TARGET)
    f.add_argument("--started", default=None, help="start atlandıysa ISO8601 başlangıç")
    f.add_argument("--exit-code", type=int, default=0, help="tarayıcı çıkış kodu (hata takibi)")
    f.add_argument("--errors", type=int, default=0, help="tarayıcının bildirdiği hata sayısı")
    f.add_argument("--mode", default=None, help="start atlandıysa mod (unauthenticated|authenticated-full|advanced-protocol)")
    f.add_argument("--note", default="", help="serbest not")
    f.set_defaults(fn=cmd_finish)
    l = sub.add_parser("list", help="kayıtlı taramaları listele")
    l.add_argument("--last", type=int, default=20)
    l.set_defaults(fn=cmd_list)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
