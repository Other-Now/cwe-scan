# Findings

What I learned while building and measuring this, with the evidence for each.
Everything ran on a 4-vCPU WSL2 VM with Clang/LLVM 20.1.2, clang-tidy 20.1.2
and cppcheck 2.13, against Juliet C/C++ 1.3 and four libraries cloned on
2026-11-10.

## 1. At its defaults, the Clang Static Analyzer misses most of Juliet's use-after-free cases

On CWE-416, CSA found 209 of 459 cases (0.455). cwe-scan, a far simpler
analysis, found 378. I didn't trust that, so I ran CSA by hand on the
simplest missed case, `malloc_free_int64_t_01`:

```c
data = (int64_t *)malloc(100*sizeof(int64_t));
if (data == NULL) {exit(-1);}
for(i = 0; i < 100; i++) data[i] = 5LL;
free(data);
printLongLongLine(data[0]);   /* the flaw */
```

| CSA configuration | Warning on the flaw |
| --- | --- |
| default | none |
| `-analyzer-config widen-loops=true` | `Use of memory after it is freed` |
| `-analyzer-max-loop 200` | `Use of memory after it is freed` |

CSA explores a loop at most 4 times by default. A path that would need more
iterations is dropped, with no warning that anything after the loop went
unchecked. Most Juliet buffers are filled by a 100-iteration loop right before
the flaw. With widening, CSA's CWE-416 recall goes from 0.455 to **0.847**,
higher than cwe-scan's 0.824, so both CSA configurations are in the results.
The general point: an analyzer's silence after a loop says nothing about the
code after the loop.

## 2. Juliet precision was 1.000; real-code precision was 0 of 32

| Corpus | Findings | Real | Precision |
| --- | --- | --- | --- |
| Juliet, whole program, four CWEs | hits in 2,389 of 3,427 cases | | 1.000 (0 false-alarm cases) |
| cJSON + zlib + Lua + libyaml, 53k lines | 32 | 0 | 0 |

Every real-code finding was read by hand (`results/realcode_triage.md`).
There were three causes:

- **25 are correlations between variables.** A pointer is null only when
  another variable says so: `p` at `i == 0`, `result_tail` when `result` is
  NULL, `from_child` encoded in an integer `diff`. A path-insensitive dataflow
  analysis joins those paths and loses the link.
- **3 come from a `!(p != NULL && …)` macro.** Clang's CFG evaluates the
  `&&` as a value under `!`, so the refinement dies in the join.
- **4 depend on a parser invariant.**

CSA, which is path-sensitive, reported 3 findings on the same code.

Juliet's flaws are single-variable, straight-line flows, which is exactly what
this design handles. I also developed the tool while looking at Juliet, which
CSA and cppcheck weren't. Both facts inflate its Juliet numbers, and I'd only
have seen how much by running it on code it had never seen.

**The fix was a confidence tier, not more tuning.** A finding is `definite`
when its condition holds on every path reaching the line (null on all paths,
freed on all paths, live at every exit). Otherwise it is `may`. 31 of the 32
real-code false positives are `may`. On Juliet, keeping only `definite`
findings costs 2–4 points of recall per CWE and keeps 0 false alarms. In SARIF,
`definite` is level `warning` and `may` is `note`.

## 3. Five real-code false-positive sources, and their fixes

The first real-code run produced 181 findings. Each fix below is a general
rule, not a special case for one library. Each has a regression case in
`tests/cases/realcode.c`, and none changed a Juliet count.

| Source | Example | Fix |
| --- | --- | --- |
| "Returns null on some path" summaries | `getthread()` returns `lua_tothread()`, which is NULL only for non-threads, and callers check `lua_isthread` first. Nearly every Lua report. | `retNull` only for functions that return null on *every* path. Juliet's `badSource` (`data = NULL; return data;`) still qualifies. CSA has the same problem and suppresses null-return paths by default. |
| Null tests in macros | cJSON's `can_access_at_index(b, i)` is `((b != NULL) && ...)`, used everywhere, so every use looked like the programmer saying `b` may be NULL. | A null test spelled inside a macro body only refines its non-null edge and is never reported as a check after a dereference. This is the same idea as CSA's `suppress-inlined-defensive-checks`. |
| `__builtin_expect` | Lua's `l_unlikely(lb != NULL)` is `__builtin_expect(((lb != NULL) != 0), 0)`, so no refinement happened. | Branch matching looks through `__builtin_expect` and `!= 0` / `== 0`. |
| Assignment in a condition | zlib `gzdopen`: `if (fd < 0 || (path = malloc(...)) == NULL) return NULL;`. The failed-malloc path wasn't refined, so it looked like a leak. | `(p = e) == NULL` refines `p`. |
| Parameter summary through a copy | cJSON `decode_pointer_inplace` does `decoded = string; if (string == NULL) return;` and then writes through `decoded`. Refining `string` doesn't refine `decoded`, so the parameter looked "dereferenced unchecked" and callers passing NULL were flagged. | Only a dereference of the parameter variable itself sets the summary bit. |

After the first four, the count was 181 → 34. After the last one it was 32.

## 4. A path-insensitive join invents a double free in correct realloc code

```c
char *t = realloc(d, 100);
if (t != NULL) d = t;
free(d);
```

On the `t != NULL` path the old block is freed and `d` points to the new one.
On the other path, `d` still points to the old, live block. The join
produced "`d` may point to the old block" and "the old block may be freed",
so `free(d)` looked like a double free. The real information was that on the
first path nothing could reach the old block any more. The fix is to drop an
allocation site from the state as soon as no variable references it on that
path, so its state there can't pollute paths where it is still reachable.
`realloc` itself is modelled as freeing the old block only on the edge where
its result is tested non-null.

## 5. "Loops that run once" was the biggest false-alarm source on Juliet

Juliet flow variant 17 wraps the source and sink in
`for (i = 0; i < 1; i++)`. A plain dataflow analysis also follows the path
where the loop never runs, and the path where it runs twice. So the good
variant, which frees inside the loop, looked like a leak (the zero-iteration
path) and like a double free (the second iteration). With whole-program
analysis that was 34 leak and 20 double-free false-alarm cases.

The fix needs no general loop reasoning. For a `for` whose condition holds for
its initial value and whose body doesn't write the counter, the state arriving
from outside the loop is kept separate at the loop header, and its exit edge is
dropped. If one increment already makes the condition false, the back-edge
state's re-entry is dropped too. Both false-alarm counts went to 0.

## 6. A rule that was right for C was wrong for C++, and hid behind correct answers

"A function in a system header never takes ownership of a pointer" is right
for libc. For `std::vector::insert` it is wrong: the vector keeps the pointer.
Variants 72 and 73 put the pointer in a vector or list and pass the container
on, so the rule produced 68 false-alarm cases in `good` functions. It also
produced *hits* in the `bad` functions, which happen to leak too, but for the
wrong reason. Limiting the rule to C functions removed the false alarms and
those hits: CWE-401 recall went from 0.745 to 0.704. The lower number is the
honest one.

## 7. Per-file and whole-program are different questions

| Mode | CWE-476 | CWE-415 | CWE-401 recall | False-alarm cases |
| --- | --- | --- | --- | --- |
| one file at a time | 0.638 | 0.499 | 0.569 | 170 |
| whole program (case files + `io.c`) | 0.698 | 0.624 | 0.704 | 0 |

The 170 per-file false alarms are exactly variants 09–14, where the guard is
`if (globalTrue)` and `globalTrue` lives in `io.c`. From one file, the
branch can't be proven dead, so per-file mode is correctly conservative. The
recall gains are the multi-file flows (variants 22, 51–54, 61, 65), carried by
summaries keyed by symbol name across translation units. CSA and cppcheck ran
one file at a time. CSA's cross-TU mode, which needs an index built per
project, was not run.
