# cwe-scan

A static analyzer for C and C++, built on Clang's libTooling and CFG. It finds
four memory-safety defect classes and reports them as SARIF 2.1.0, each mapped
to its CWE and CERT C rule:

| CWE | Defect | CERT C |
| --- | --- | --- |
| 476 | NULL pointer dereference, including a null check after the dereference | EXP34-C |
| 416 | Use after free (dereference, call argument, return) | MEM30-C |
| 415 | Double free | MEM30-C |
| 401 | Memory leak, including the `p = realloc(p, n)` idiom | MEM31-C |

It is scored against NIST's Juliet C/C++ 1.3 suite next to the Clang Static
Analyzer and cppcheck, and then run on 53,000 lines of real C (cJSON, zlib,
Lua, libyaml), where every finding was read by hand. **The two corpora tell
very different stories, and both are reported here.**

## How it works

```
 files ──► Clang ASTs ──► program facts ──► summaries (iterate to fixed point) ──► report pass ──► SARIF / text
                          (constant globals,   per function: returns null on every path?
                           constant functions)   returns its own allocation? each pointer
                                                  parameter dereferenced / freed / escaped?
```

For each function, one forward dataflow pass runs over Clang's CFG to a fixed
point. The per-path state is:

- for each local pointer: its nullness as a may-set of {null, non-null,
  unknown}, the allocation sites it may point to, and whether it has been
  dereferenced on every path since its last assignment;
- for each allocation site: live, freed or escaped, again as a may-set over
  paths.

On top of that state:

- **Branches refine it.** On the edges of `p`, `!p`, `p == NULL` and
  `p != NULL`, the state is refined per edge, looking through
  `__builtin_expect`, `!= 0` and `(p = f()) == NULL`. A refinement that
  contradicts what is known makes the edge infeasible.
- **Constant guards are pruned.** That covers literals (`if (5 == 5)`), and
  globals that are never written and functions that just return a constant,
  found across the whole program (`if (staticTrue)`, `if (globalReturnsTrue())`).
  A `for` loop whose condition holds on entry has its zero-iteration exit
  removed. If its second test always fails, its back edge is removed too.
- **Aliases are followed:** C++ references, `T **pp = &v`, and function
  pointers set once. Variables whose address escapes are not tracked.
- **Ownership follows convention.** C library functions and parameters that
  point to `const` never take ownership. Other unknown calls are treated as
  escapes. Summaries replace both rules for functions in the program.
- **Each finding has a confidence.** `definite` (SARIF `warning`) means the
  condition holds on every path reaching the line. `may` (SARIF `note`) means
  it holds on some path.

## Results

### Juliet C/C++ 1.3

There are 3,427 test cases. Scoring is per test case: a hit is a finding of
the case's CWE inside a function whose name contains `bad`. A false alarm is
one inside a `good` function. Function boundaries come from the source text,
the same way for every tool. Raw data is in [results/](results/), and
`bench/juliet.py` reproduces it. CI reruns cwe-scan on Juliet on every push
and fails if a single count changes.

| Tool | CWE-476 recall | CWE-416 recall | CWE-415 recall | CWE-401 recall | False-alarm cases (all four) |
| --- | --- | --- | --- | --- | --- |
| **cwe-scan, whole program** | **0.698** | 0.824 | **0.624** | **0.704** | **0** |
| cwe-scan, whole program, `definite` only | 0.678 | 0.780 | 0.603 | 0.684 | 0 |
| cwe-scan, one file at a time | 0.638 | 0.824 | 0.499 | 0.569 | 170 (all CWE-401) |
| Clang Static Analyzer 20 (clang-tidy), defaults | 0.586 | 0.455 | 0.478 | 0.511 | 238 |
| Clang Static Analyzer 20, `widen-loops=true` | 0.586 | **0.847** | 0.478 | 0.511 | 238 |
| cppcheck 2.13 | 0.480 | 0.031 | 0.291 | 0.174 | 156 |

How to read this:

- **Per-file mode is the like-for-like comparison.** CSA and cppcheck analyse
  one file at a time, so "one file at a time" is the row to compare with
  them. Whole-program mode also sees `io.c`, where Juliet's `globalTrue` and
  friends are defined, and the other files of multi-file cases. Its gains
  (variants 22, 51–54, 61, 65) are cross-file flows that CSA would need its
  cross-translation-unit mode for, and I did not run that.
- **CSA's defaults hide use-after-free.** At its defaults CSA scores 0.455 on
  CWE-416 because it stops exploring a path after 4 loop iterations and
  reports nothing for it. Most Juliet UAF cases fill the buffer in a
  100-iteration loop just before the flaw. With `widen-loops=true` it reaches
  0.847, above cwe-scan.
- **Most false alarms come from constant guards.** cwe-scan's 170 per-file
  false alarms are exactly variants 09–14. There the guard is
  `if (globalTrue)`, defined in another file, so a single-file analysis can't
  know the branch is dead. CSA's 238 cover those same variants plus two
  others:
  - variants 05 and 07, where the guard is a file-static global that is never
    written (`static int staticTrue = 1`); cwe-scan proves it constant within
    the file, and CSA doesn't;
  - 28 from variant 34, the union.
- **No tool finds the hardest variants.** None of the three tools finds
  variants 62–84: pointers through arrays, structs, `void *`, STL containers
  and virtual calls.

### Real code: four libraries, every finding triaged

| Project | Lines | cwe-scan findings | Real bugs | CSA findings |
| --- | --- | --- | --- | --- |
| cJSON 6d9f244 | 4,959 | 18 | 0 | 0 |
| zlib 99623ef | 9,864 | 2 | 0 | 0 |
| Lua 8cb93ba | 28,106 | 3 | 0 | 3 (not triaged) |
| libyaml 90a56d4 | 10,312 | 9 | 0 | 0 |

The tool ran on code it was not developed against. **All 32 findings are false
positives** ([results/realcode_triage.md](results/realcode_triage.md)), and
they have three causes:

- **25 are correlations between variables.** For example, `p` is null only
  when `i == 0`, and that case takes another branch. A path-insensitive
  analysis can't see this, and a path-sensitive one like CSA can.
- **3 come from a `!(p != NULL && …)` macro.** Clang's CFG evaluates the
  `&&` as a value, so the refinement is lost.
- **4 rely on a parser invariant.**

31 of the 32 are in the `may` tier. Reporting only `definite` findings leaves
one false positive on real code, at a cost of 2–4 points of Juliet recall.

Before five fixes driven by this triage, the same code produced **181**
findings (details in [docs/findings.md](docs/findings.md)).

**So:** Juliet rewards exactly what this tool does well, single-variable
straight-line flows, and its precision there is 1.000. Real code punishes what
it doesn't do. A benchmark score alone would have misrepresented it.

## Not done

- **No data-flow through memory:** struct fields, arrays and unions are not
  tracked, and there is no heap model.
- **No path sensitivity beyond edge refinement**, which is the cause of most
  real-code false positives.
- **No C++ object model:** no virtual dispatch, constructors or destructors.
  STL calls are treated as escapes.
- **CSA's cross-TU mode was not run**, so the whole-program gains are not
  compared against CSA at its strongest.
- **Unscored and unbuilt:** no MISRA mapping (it's a paid standard I didn't
  check against), no Windows build or CI (Linux only), and no AI triage of
  findings.
- **Speed is not a claim.** Timings in `results/juliet.json` are wall-clock
  on a shared 4-vCPU WSL2 VM, with four jobs in parallel.

## Build and run

Linux with LLVM/Clang 20 development packages (Ubuntu 24.04:
`llvm-20-dev libclang-20-dev libclang-cpp20-dev`), CMake and Ninja.

```sh
cmake -S . -B build -G Ninja && cmake --build build
python3 tests/run_tests.py                       # expected-finding markers in tests/cases
./build/cwe-scan --sarif out.sarif src/*.c -- -Iinclude
./build/cwe-scan --per-file file.c -- <flags>    # no cross-file facts or summaries
python3 bench/juliet.py --juliet path/to/juliet/C --out results
```

Options: `--fold none|literal|program`, `--no-summaries`, `--per-file`,
`--sarif <file>`, `--quiet`. Compiler flags go after `--`.
