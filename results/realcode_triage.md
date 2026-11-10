# Real-code triage

cwe-scan was run on four mature C libraries it was never developed against,
and I read the code behind every finding. Whole-program mode, default
options. Commits as cloned on 2026-11-10.

| Project | Commit | Files | Lines | cwe-scan findings | Real bugs | CSA findings (same classes) |
| --- | --- | --- | --- | --- | --- | --- |
| cJSON | 6d9f244 | 2 | 4,959 | 18 | 0 | 0 |
| zlib | 99623ef | 15 (3 did not compile with `-I.` alone) | 9,864 | 2 | 0 | 0 |
| Lua | 8cb93ba | 33 | 28,106 | 3 | 0 | 3 (not triaged) |
| libyaml | 90a56d4 | 8 | 10,312 | 9 | 0 | 0 |
| **Total** | | | **53,241** | **32** | **0** | **3** |

Before the fixes described in `docs/findings.md` (null-return summaries,
`__builtin_expect`, macro defensive checks, copies of parameters), the same
code produced **181** findings.

All 32 are false positives. Only one is in the `definite` tier (true on every
path); the other 31 are `may` findings.

## By cause

**Correlated variables (25).** The pointer is null only when some other
variable says so, and a path-insensitive analysis doesn't relate the two.

| Finding | Correlation |
| --- | --- |
| cJSON.c:1550, 1713 | `current_item` is null only while `head == NULL`, and that branch assigns it |
| cJSON.c:2649, 2689, 2729, 2769 | `p` is null only at `i == 0`, which takes the `a->child = n` branch instead |
| cJSON_Utils.c:556, 578, 588 | `result_tail` is null exactly when `result` is |
| cJSON_Utils.c:1245, 1256, 1261, 1268 | which of `from_child`/`to_child` is null is encoded in the integer `diff` |
| cJSON_Utils.c:1442, 1449, 1459, 1463, 1464 | the same, in `generate_merge_patch` |
| zlib inftrees.c:229, 230 | `base`/`extra` are null only for `type == CODES`, where `match = 20` makes the indexing branch unreachable |
| libyaml parser.c:391 (`definite`) | NULL is passed for all three `*_ref` parameters; the callee dereferences `tag_directives_end_ref` only inside `if (tag_directives_start_ref)` |
| libyaml parser.c:625, 632 | `tag_handle` and `tag_suffix` are always set together from the token |
| libyaml parser.c:1295 (leak) | freed exactly when `version_directive_ref` is NULL, stored through it otherwise |
| libyaml scanner.c:2613 | `head` is NULL only when `length` is 0; the `memcpy` is under `length > 1` |

**`&&` evaluated as a value under `!` (3).** `!LuaClosure(f)` expands to
`!((f) != NULL && ...)`. Clang's CFG evaluates the `&&` as a value, merges
both arms, and only then branches, so the `f != NULL` refinement is lost in
the join. Lua ldebug.c:337, 351, 420.

**Program invariant (4).** `PEEK_TOKEN` is `... ? head : NULL`, dereferenced
unchecked; the parser's state machine guarantees a token is buffered at those
points. libyaml parser.c:751, 859, 974, 1130.

## What this says

On Juliet the tool's precision is near 1.0, because Juliet's flaws are
straight-line code with one variable. On real code the dominant false-positive
class is correlation between variables, which is exactly what CSA's
path-sensitive symbolic execution handles and this dataflow analysis doesn't.
Reporting only `definite` findings removes 31 of the 32.
