#!/usr/bin/env python3
"""Scores cwe-scan, the Clang Static Analyzer (through clang-tidy) and
cppcheck on NIST's Juliet C/C++ 1.3 suite, CWEs 476, 416, 415 and 401.

Scoring is per test case (one flaw, possibly spread over several files):
  hit         a finding of the case's CWE inside a function whose name has "bad"
  false alarm a finding of the case's CWE inside a function whose name has "good"
Function boundaries come from the source text, the same way for every tool.

  python3 bench/juliet.py --juliet ~/juliet/C --out results
"""
import argparse, json, os, re, subprocess, sys, tempfile, time
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CWES = {476: "CWE476_NULL_Pointer_Dereference", 416: "CWE416_Use_After_Free",
        415: "CWE415_Double_Free", 401: "CWE401_Memory_Leak"}
CASE = re.compile(r"^(CWE\d+_.*?_(\d\d))(?:[a-e]|_\w+)?\.(?:c|cpp)$")
FUNC = re.compile(r"^[A-Za-z_][^;=#]*?([A-Za-z_][\w:~]*)\s*\([^;]*$")


def cases(root, cwe):
    groups = defaultdict(list)
    for f in sorted((root / "testcases" / CWES[cwe]).rglob("*")):
        m = CASE.match(f.name)
        if m and f.suffix in (".c", ".cpp"):
            groups[m.group(1)].append(f)
    return groups


def function_map(path):
    """line -> enclosing function name, from Juliet's fixed formatting."""
    lines = path.read_text(errors="replace").splitlines()
    owner, cur = {}, None
    for i, line in enumerate(lines, 1):
        if cur is None:
            m = FUNC.match(line)
            if m and i < len(lines) and lines[i].startswith("{"):
                cur = m.group(1)
        if cur:
            owner[i] = cur
            if line.startswith("}"):
                cur = None
    return owner


def region(fmap, line):
    name = fmap.get(line, "").lower()
    return "bad" if "bad" in name else "good" if "good" in name else None


# ------------------------------------------------------------------ tools

def flags(root):
    return ["-I", str(root / "testcasesupport")]


def run_cwescan(tool, files, extra, root):
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as t:
        out = t.name
    subprocess.run([tool, "--quiet", "--sarif", out, *extra, *map(str, files), "--", *flags(root)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res = []
    try:
        doc = json.load(open(out))
        for r in doc["runs"][0]["results"]:
            loc = r["locations"][0]["physicalLocation"]
            res.append((os.path.realpath(loc["artifactLocation"]["uri"]), loc["region"]["startLine"],
                        int(r["ruleId"].split("-")[1]), r["properties"]["confidence"]))
    except (OSError, ValueError, KeyError):
        pass
    os.unlink(out)
    return res


TIDY = re.compile(r"^(.*?):(\d+):\d+: warning: (.*) \[(clang-analyzer-[\w.\-,]+)\]$")


def tidy_cwe(check, msg):
    if "NullDereference" in check or "NonNullParam" in check or "null" in msg.lower() and "CallAndMessage" in check:
        return 476
    if check.endswith(("unix.Malloc", "cplusplus.NewDelete", "NewDeleteLeaks", "unix.MismatchedDeallocator")):
        m = msg.lower()
        if "leak" in m:
            return 401
        if "released memory" in m or "freed memory" in m and "attempt" in m:
            return 415
        if "after it is freed" in m or "after it is released" in m or "use of memory" in m:
            return 416
    return None


WIDEN = ["-Xclang", "-analyzer-config", "-Xclang", "widen-loops=true"]


def run_tidy(tidy, files, root, extra=()):
    p = subprocess.run([tidy, "--quiet", "-checks=-*,clang-analyzer-*", *map(str, files), "--", *flags(root), "-w",
                        *extra],
                       capture_output=True, text=True)
    res = []
    for line in p.stdout.splitlines():
        m = TIDY.match(line)
        if m:
            cwe = tidy_cwe(m.group(4), m.group(3))
            if cwe:
                res.append((os.path.realpath(m.group(1)), int(m.group(2)), cwe, m.group(3)))
    return res


def run_cppcheck(cppcheck, files, root):
    p = subprocess.run([cppcheck, "-q", "--xml", "--enable=warning", *flags(root), *map(str, files)],
                       capture_output=True, text=True)
    res = []
    try:
        for e in ET.fromstring(p.stderr).iter("error"):
            loc = e.find("location")
            if loc is not None and e.get("cwe"):
                res.append((os.path.realpath(loc.get("file")), int(loc.get("line")), int(e.get("cwe")),
                            e.get("msg")))
    except ET.ParseError:
        pass
    return res


# ------------------------------------------------------------------ scoring

def score(groups, findings, cwe, fmaps):
    by_file = defaultdict(list)
    for f, line, c, msg in findings:
        if c == cwe:
            by_file[f].append(line)
    per_case = {}
    for case, files in groups.items():
        hit = fa = False
        for f in files:
            rp = os.path.realpath(f)
            for line in by_file.get(rp, []):
                r = region(fmaps[rp], line)
                hit |= r == "bad"
                fa |= r == "good"
        per_case[case] = (hit, fa)
    return per_case


def metrics(per_case):
    n = len(per_case)
    tp = sum(h for h, _ in per_case.values())
    fp = sum(f for _, f in per_case.values())
    disc = sum(h and not f for h, f in per_case.values())
    return {"cases": n, "hits": tp, "false_alarm_cases": fp, "recall": tp / n if n else 0,
            "precision": tp / (tp + fp) if tp + fp else 0, "discrimination": disc / n if n else 0}


def chunks(xs, n):
    return [xs[i:i + n] for i in range(0, len(xs), n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--juliet", type=Path, default=Path.home() / "juliet" / "C")
    ap.add_argument("--tool", default=str(Path(__file__).resolve().parent.parent / "build" / "cwe-scan"))
    ap.add_argument("--tidy", default="clang-tidy")
    ap.add_argument("--cppcheck", default="cppcheck")
    ap.add_argument("--tools", default="cwe-scan,cwe-scan-whole,csa,csa-widen,cppcheck")
    ap.add_argument("--cwes", default="476,416,415,401")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--out", type=Path, default=Path("results"))
    a = ap.parse_args()
    root = a.juliet.resolve()
    io_c = root / "testcasesupport" / "io.c"
    a.out.mkdir(parents=True, exist_ok=True)
    tools = a.tools.split(",")
    report = {"tools": {}, "env": {}}
    raw = {}
    for cwe in map(int, a.cwes.split(",")):
        groups = cases(root, cwe)
        files = [f for fs in groups.values() for f in fs]
        fmaps = {os.path.realpath(f): function_map(f) for f in files}
        for tool in tools:
            t0 = time.time()
            with ThreadPoolExecutor(a.jobs) as ex:
                if tool == "cwe-scan":
                    jobs = [ex.submit(run_cwescan, a.tool, c, ["--per-file"], root) for c in chunks(files, 40)]
                elif tool == "cwe-scan-whole":
                    jobs = [ex.submit(run_cwescan, a.tool, fs + [io_c], [], root) for fs in groups.values()]
                elif tool == "csa":
                    jobs = [ex.submit(run_tidy, a.tidy, c, root) for c in chunks(files, 20)]
                elif tool == "csa-widen":  # CSA with loop widening, so paths survive long loops
                    jobs = [ex.submit(run_tidy, a.tidy, c, root, WIDEN) for c in chunks(files, 20)]
                elif tool == "cppcheck":
                    jobs = [ex.submit(run_cppcheck, a.cppcheck, c, root) for c in chunks(files, 40)]
                found = [x for j in jobs for x in j.result()]
            secs = time.time() - t0
            variants = [(tool, found)]
            if tool.startswith("cwe-scan"):  # the same run, keeping only findings true on every path
                variants.append((tool + "-definite", [f for f in found if f[3] == "definite"]))
            for name, fs in variants:
                record(report, raw, name, cwe, score(groups, fs, cwe, fmaps), secs)
    (a.out / "juliet.json").write_text(json.dumps(report, indent=1))
    (a.out / "juliet_cases.json").write_text(json.dumps(raw))


def record(report, raw, tool, cwe, per_case, secs):
    m = metrics(per_case)
    m["seconds"] = round(secs, 1)
    by_variant = defaultdict(dict)
    for case, v in per_case.items():
        by_variant[CASE.match(case + ".c").group(2)][case] = v
    m["by_variant"] = {k: metrics(v) for k, v in sorted(by_variant.items())}
    report["tools"].setdefault(tool, {})[str(cwe)] = m
    raw.setdefault(tool, {})[str(cwe)] = {c: list(v) for c, v in per_case.items()}
    print(f"CWE-{cwe} {tool:24s} cases={m['cases']:5d} recall={m['recall']:.3f} "
          f"precision={m['precision']:.3f} false-alarm cases={m['false_alarm_cases']:4d} "
          f"({secs:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
