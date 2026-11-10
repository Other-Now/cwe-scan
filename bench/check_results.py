#!/usr/bin/env python3
"""Fails if a fresh Juliet run disagrees with the committed numbers."""
import json, sys

want, got = (json.load(open(p))["tools"] for p in sys.argv[1:3])
bad = 0
for tool in sys.argv[3:]:
    for cwe, m in want[tool].items():
        g = got[tool][cwe]
        for k in ("cases", "hits", "false_alarm_cases"):
            if m[k] != g[k]:
                print(f"{tool} CWE-{cwe} {k}: committed {m[k]}, got {g[k]}")
                bad += 1
        print(f"{tool} CWE-{cwe}: hits {g['hits']}/{g['cases']}, false-alarm cases {g['false_alarm_cases']}")
sys.exit(1 if bad else 0)
