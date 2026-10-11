#!/usr/bin/env python3
"""
Tarayıcı-makine kaynak ölçer: tarama sürerken CPU/RAM örnekler,
evaluation/runs/<scan_id>.resources.json dosyasına yazar.
scan.py finish bu dosyayı bulursa koşu kaydına gömer.

Kullanım (tarayıcıyla PARALEL, ayrı terminal):
  pip install psutil            # önerilir (işlem bazında ölçüm için)
  python evaluation/agent.py --scan-id run-20261010-120000 --process java --interval 2
  python evaluation/agent.py --duration 600          # 10 dk sonra otomatik durur
  # durdurmak için Ctrl+C

--process: adında geçen süreçler izlenir (örn "java" ZAP için, "nuclei", "python").
psutil yoksa: sistem CPU/RAM işletim sisteminden okunamazsa sadece zaman damgalı
not düşülür (Windows'ta psutil şart, Linux'ta loadavg yedeği var).
"""
import json, os, sys, argparse, time, subprocess
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS_DIR = os.path.join(BASE, "evaluation", "runs")
ACTIVE_FILE = os.path.join(BASE, "evaluation", ".scan-active.json")

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False


def sys_fallback():
    # psutil yoksa Linux loadavg; Windows'ta ölçüm yok
    try:
        if os.name != "nt" and hasattr(os, "getloadavg"):
            l1, _, _ = os.getloadavg()
            ncpu = os.cpu_count() or 1
            return {"cpu_pct": round(100 * l1 / ncpu, 1), "mem_pct": None}
    except Exception:
        pass
    return {"cpu_pct": None, "mem_pct": None}


def procs(pattern):
    out = []
    if not (HAVE_PSUTIL and pattern):
        return out
    pat = pattern.lower()
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            hay = ((p.info.get("name") or "") + " " + " ".join(p.info.get("cmdline") or [])).lower()
            if pat in hay:
                with p.oneshot():
                    out.append({"pid": p.pid, "name": p.info.get("name"),
                                "cpu": p.cpu_percent(interval=None),
                                "rss_mb": round(p.memory_info().rss / 1048576, 1)})
        except Exception:
            continue
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-id", default=None)
    ap.add_argument("--process", default="", help="izlenecek süreç adı parçası (java/nuclei/...)")
    ap.add_argument("--interval", type=float, default=2)
    ap.add_argument("--duration", type=float, default=0, help="sn (0=sınırsız, Ctrl+C ile dur)")
    args = ap.parse_args()

    scan_id = args.scan_id
    if not scan_id and os.path.exists(ACTIVE_FILE):
        scan_id = json.load(open(ACTIVE_FILE, encoding="utf-8")).get("scan_id", "manual")
    scan_id = scan_id or ("manual-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    os.makedirs(RUNS_DIR, exist_ok=True)
    out_path = os.path.join(RUNS_DIR, f"{scan_id}.resources.json")

    if HAVE_PSUTIL:
        psutil.cpu_percent(interval=None)
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass

    series, t0 = [], time.time()
    n = 0
    print(f"[agent] scan_id={scan_id} process='{args.process or '-'}' interval={args.interval}sn "
          f"collector={'psutil' if HAVE_PSUTIL else 'fallback (pip install psutil önerilir)'}")
    print("[agent] durdurmak için Ctrl+C")
    try:
        while True:
            time.sleep(args.interval)
            n += 1
            if HAVE_PSUTIL:
                sample = {"t": round(time.time() - t0, 1),
                          "sys_cpu": psutil.cpu_percent(interval=None),
                          "sys_mem": psutil.virtual_memory().percent,
                          "procs": procs(args.process)}
            else:
                fb = sys_fallback()
                sample = {"t": round(time.time() - t0, 1),
                          "sys_cpu": fb["cpu_pct"], "sys_mem": fb["mem_pct"], "procs": []}
            series.append(sample)
            if n % 15 == 0:
                print(f"[agent] {sample['t']}sn cpu={sample['sys_cpu']} mem={sample['sys_mem']} izlenen_süreç={len(sample['procs'])}")
            if args.duration and (time.time() - t0) >= args.duration:
                break
    except KeyboardInterrupt:
        pass

    cpus = [s["sys_cpu"] for s in series if s["sys_cpu"] is not None]
    mems = [s["sys_mem"] for s in series if s["sys_mem"] is not None]
    summary = {
        "scan_id": scan_id,
        "collector": "psutil" if HAVE_PSUTIL else "fallback",
        "process_filter": args.process or None,
        "samples": len(series),
        "duration_sec": round(time.time() - t0, 1),
        "sys_cpu_avg": round(sum(cpus) / len(cpus), 1) if cpus else None,
        "sys_cpu_peak": max(cpus) if cpus else None,
        "sys_mem_avg": round(sum(mems) / len(mems), 1) if mems else None,
        "sys_mem_peak": max(mems) if mems else None,
        "series": series[-1800:],  # son ~1 saatlik örnek (2sn aralıkla)
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"[agent] kayıt: evaluation/runs/{os.path.basename(out_path)} "
          f"({len(series)} örnek, cpu_tepe={summary['sys_cpu_peak']}, mem_tepe={summary['sys_mem_peak']})")


if __name__ == "__main__":
    main()
