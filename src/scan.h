// cwe-scan: intraprocedural dataflow over Clang's CFG, with function
// summaries, for four CWE classes: 476 (null dereference), 416 (use after
// free), 415 (double free) and 401 (memory leak).
#pragma once
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace clang {
class ASTContext;
class FunctionDecl;
class NamedDecl;
}  // namespace clang

namespace cwescan {

struct Finding {
  int cwe = 0;
  std::string file;
  unsigned line = 0, col = 0;
  std::string function;
  std::string message;
  bool definite = false;  // holds on every path, not just some
};

// What a function does to each pointer parameter, as seen by its callers.
enum ParamBits : uint8_t {
  P_DEREF = 1,   // dereferenced before any null check
  P_FREE = 2,    // freed on some path
  P_ESCAPE = 4,  // stored somewhere the caller can't see, or returned
};

struct Summary {
  bool retNull = false;   // may return a null pointer
  bool retAlloc = false;  // may return memory it allocated
  std::vector<uint8_t> params;
  bool operator==(const Summary& o) const {
    return retNull == o.retNull && retAlloc == o.retAlloc && params == o.params;
  }
  bool operator!=(const Summary& o) const { return !(*this == o); }
};

enum class Fold { None, Literal, Program };

struct Options {
  bool perFile = false;  // no facts or summaries cross a file boundary
  Fold fold = Fold::Program;
  bool summaries = true;
};

// Facts gathered from every translation unit before any function is analysed.
struct Program {
  Options opts;
  std::map<std::string, long long> initVals;    // globals with a constant initializer
  std::set<std::string> written;                // globals assigned, incremented or address-taken
  std::map<std::string, long long> constVars;   // initVals minus written
  std::map<std::string, long long> constFuncs;  // functions whose body is `return <constant>;`
  std::map<std::string, Summary> summaries;
};

// Names with internal linkage, and every name in per-file mode, are
// qualified by their translation unit so they never match across files.
std::string symbolKey(const clang::NamedDecl* d, int tu, const Options& o);

void collectFacts(clang::ASTContext& ctx, int tu, Program& p);
void finishFacts(Program& p);

// Analyses one function and returns its summary. Findings are appended only
// when `out` is non-null, so the same code serves the summary rounds and the
// final reporting pass.
Summary analyzeFunction(const clang::FunctionDecl* fd, clang::ASTContext& ctx, int tu,
                        const Program& p, std::vector<Finding>* out);

const char* cweTitle(int cwe);
const char* certRule(int cwe);

}  // namespace cwescan
