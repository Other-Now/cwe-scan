#!/usr/bin/env python3
"""Checks cwe-scan against `// expect: CWE-NNN` markers.

Every marked line must get exactly that finding and nothing else may be
reported. A marker ending in `whole-program` is expected only when the
files are analysed together, not with --per-file.
"""
import json, re, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = sys.argv[1] if len(sys.argv) > 1 else str(HERE.parent / "build" / "cwe-scan")
MARK = re.compile(r"//\s*expect:\s*CWE-(\d+)(\s+whole-program)?")


def expected(files, whole):
    want = set()
    for f in files:
        for n, line in enumerate(f.read_text().splitlines(), 1):
            m = MARK.search(line)
            if m and (whole or not m.group(2)):
                want.add((f.name, n, int(m.group(1))))
    return want


def run(files, extra):
    with tempfile.NamedTemporaryFile(suffix=".sarif") as out:
        subprocess.run([TOOL, "--quiet", "--sarif", out.name, *extra, *map(str, files), "--"],
                       check=False, stderr=subprocess.DEVNULL)
        doc = json.load(open(out.name))
    got = set()
    for r in doc["runs"][0]["results"]:
        loc = r["locations"][0]["physicalLocation"]
        got.add((Path(loc["artifactLocation"]["uri"]).name, loc["region"]["startLine"],
                 int(r["ruleId"].split("-")[1])))
    return got


failures = 0
checks = 0
groups = [([f], ["--per-file"], False) for f in sorted((HERE / "cases").iterdir())]
xf = sorted((HERE / "xfile").glob("*.c"))
groups += [(xf, [], True), (xf, ["--per-file"], False)]
for files, extra, whole in groups:
    want, got = expected(files, whole), run(files, extra)
    label = ",".join(f.name for f in files) + (" " + " ".join(extra) if extra else "")
    for w in sorted(want - got):
        print(f"MISSING   {label}: {w}")
    for g in sorted(got - want):
        print(f"UNEXPECTED {label}: {g}")
    failures += len(want ^ got)
    checks += len(want) + 1
    print(f"{'ok  ' if want == got else 'FAIL'} {label}: {len(want & got)}/{len(want)} expected findings")
print(f"{'PASS' if failures == 0 else 'FAIL'}: {failures} mismatches")
sys.exit(1 if failures else 0)
