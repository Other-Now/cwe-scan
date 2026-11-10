// cwe-scan driver: builds the ASTs, gathers program facts, iterates function
// summaries to a fixed point, then reports.
//
//   cwe-scan [options] <files...> -- <compiler flags>
//
// By default every input file is one program: facts and summaries flow
// between files. --per-file analyses each file alone, which is what the
// baseline tools see.
#include <chrono>
#include <fstream>
#include <iostream>

#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/ArgumentsAdjusters.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/JSON.h"
#include "scan.h"

using namespace clang;
using namespace clang::tooling;
using namespace cwescan;

static llvm::cl::OptionCategory Cat("cwe-scan options");
static llvm::cl::opt<std::string> SarifOut("sarif", llvm::cl::desc("Write SARIF 2.1.0 to this file"),
                                           llvm::cl::value_desc("file"), llvm::cl::cat(Cat));
static llvm::cl::opt<bool> PerFile("per-file",
                                   llvm::cl::desc("Analyse each file alone: no cross-file facts or summaries"),
                                   llvm::cl::cat(Cat));
static llvm::cl::opt<std::string> FoldOpt("fold", llvm::cl::init("program"),
                                          llvm::cl::desc("Guard folding: none | literal | program"),
                                          llvm::cl::cat(Cat));
static llvm::cl::opt<bool> NoSummaries("no-summaries", llvm::cl::desc("Treat every call as unknown"),
                                       llvm::cl::cat(Cat));
static llvm::cl::opt<bool> Quiet("quiet", llvm::cl::desc("Do not print findings"), llvm::cl::cat(Cat));

namespace {

struct Fn {
  int tu;
  ASTContext* ctx;
  const FunctionDecl* fd;
};

class FnCollector : public RecursiveASTVisitor<FnCollector> {
 public:
  FnCollector(ASTContext& c, int tu, std::vector<Fn>& out) : ctx(c), tu(tu), out(out) {}
  bool VisitFunctionDecl(FunctionDecl* fd) {
    if (!fd->doesThisDeclarationHaveABody() || fd->isDependentContext() || fd->isImplicit())
      return true;
    if (!ctx.getSourceManager().isInMainFile(ctx.getSourceManager().getExpansionLoc(fd->getLocation())))
      return true;
    out.push_back({tu, &ctx, fd});
    return true;
  }

 private:
  ASTContext& ctx;
  int tu;
  std::vector<Fn>& out;
};

int analyzeProgram(std::vector<std::unique_ptr<ASTUnit>>& asts, Options opts, std::vector<Finding>& findings,
                   int tuBase) {
  Program prog;
  prog.opts = opts;
  std::vector<Fn> fns;
  for (size_t i = 0; i < asts.size(); ++i) {
    ASTContext& ctx = asts[i]->getASTContext();
    collectFacts(ctx, tuBase + static_cast<int>(i), prog);
    FnCollector c(ctx, tuBase + static_cast<int>(i), fns);
    c.TraverseDecl(ctx.getTranslationUnitDecl());
  }
  finishFacts(prog);
  int rounds = 0;
  if (opts.summaries) {
    for (; rounds < 8; ++rounds) {
      bool changed = false;
      for (auto& f : fns) {
        Summary s = analyzeFunction(f.fd, *f.ctx, f.tu, prog, nullptr);
        std::string key = symbolKey(f.fd, f.tu, opts);
        auto it = prog.summaries.find(key);
        if (it == prog.summaries.end() || it->second != s) {
          prog.summaries[key] = s;
          changed = true;
        }
      }
      if (!changed) break;
    }
  }
  for (auto& f : fns) analyzeFunction(f.fd, *f.ctx, f.tu, prog, &findings);
  return rounds;
}

llvm::json::Value sarif(const std::vector<Finding>& fs) {
  llvm::json::Array rules;
  for (int cwe : {476, 416, 415, 401}) {
    std::string id = "CWE-" + std::to_string(cwe);
    rules.push_back(llvm::json::Object{
        {"id", id},
        {"name", cweTitle(cwe)},
        {"shortDescription", llvm::json::Object{{"text", cweTitle(cwe)}}},
        {"helpUri", "https://cwe.mitre.org/data/definitions/" + std::to_string(cwe) + ".html"},
        {"properties", llvm::json::Object{{"cert", certRule(cwe)}}},
    });
  }
  llvm::json::Array results;
  for (const Finding& f : fs) {
    results.push_back(llvm::json::Object{
        {"ruleId", "CWE-" + std::to_string(f.cwe)},
        {"level", f.definite ? "warning" : "note"},
        {"message", llvm::json::Object{{"text", f.message}}},
        {"locations",
         llvm::json::Array{llvm::json::Object{
             {"physicalLocation",
              llvm::json::Object{
                  {"artifactLocation", llvm::json::Object{{"uri", f.file}}},
                  {"region", llvm::json::Object{{"startLine", static_cast<int64_t>(f.line)},
                                                {"startColumn", static_cast<int64_t>(f.col)}}},
              }},
             {"logicalLocations",
              llvm::json::Array{llvm::json::Object{{"fullyQualifiedName", f.function}, {"kind", "function"}}}},
         }}},
        {"properties", llvm::json::Object{{"cert", certRule(f.cwe)}, {"confidence", f.definite ? "definite" : "may"}}},
    });
  }
  return llvm::json::Object{
      {"$schema", "https://json.schemastore.org/sarif-2.1.0.json"},
      {"version", "2.1.0"},
      {"runs", llvm::json::Array{llvm::json::Object{
                   {"tool", llvm::json::Object{{"driver", llvm::json::Object{
                                                              {"name", "cwe-scan"},
                                                              {"version", "0.1.0"},
                                                              {"informationUri", "https://github.com/Other-Now/cwe-scan"},
                                                              {"rules", std::move(rules)},
                                                          }}}},
                   {"results", std::move(results)},
               }}},
  };
}

}  // namespace

int main(int argc, const char** argv) {
  auto parser = CommonOptionsParser::create(argc, argv, Cat, llvm::cl::OneOrMore);
  if (!parser) {
    llvm::errs() << llvm::toString(parser.takeError());
    return 2;
  }
  Options opts;
  opts.perFile = PerFile;
  opts.summaries = !NoSummaries;
  if (FoldOpt == "none") opts.fold = Fold::None;
  else if (FoldOpt == "literal") opts.fold = Fold::Literal;
  else if (FoldOpt == "program") opts.fold = Fold::Program;
  else {
    llvm::errs() << "--fold must be none, literal or program\n";
    return 2;
  }

  const std::vector<std::string>& files = parser->getSourcePathList();
  auto build = [&](const std::vector<std::string>& srcs, std::vector<std::unique_ptr<ASTUnit>>& asts) {
    ClangTool tool(parser->getCompilations(), srcs);
    tool.appendArgumentsAdjuster(
        getInsertArgumentAdjuster("-resource-dir=" CWE_SCAN_RESOURCE_DIR, ArgumentInsertPosition::BEGIN));
    tool.appendArgumentsAdjuster(getInsertArgumentAdjuster("-w", ArgumentInsertPosition::END));
    return tool.buildASTs(asts);
  };

  auto t0 = std::chrono::steady_clock::now();
  std::vector<Finding> findings;
  int failed = 0;
  if (opts.perFile) {
    for (size_t i = 0; i < files.size(); ++i) {
      std::vector<std::unique_ptr<ASTUnit>> asts;
      build({files[i]}, asts);
      for (auto& a : asts)
        if (a->getDiagnostics().hasErrorOccurred()) ++failed;
      analyzeProgram(asts, opts, findings, static_cast<int>(i));
    }
  } else {
    std::vector<std::unique_ptr<ASTUnit>> asts;
    build(files, asts);
    for (auto& a : asts)
      if (a->getDiagnostics().hasErrorOccurred()) ++failed;
    analyzeProgram(asts, opts, findings, 0);
  }
  double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

  if (!Quiet)
    for (const Finding& f : findings)
      llvm::outs() << f.file << ":" << f.line << ":" << f.col << ": warning: " << f.message << " [CWE-"
                   << f.cwe << ", CERT " << certRule(f.cwe) << "] in '" << f.function << "'\n";
  if (!SarifOut.empty()) {
    std::error_code ec;
    llvm::raw_fd_ostream os(SarifOut, ec);
    if (ec) {
      llvm::errs() << "cannot write " << SarifOut << ": " << ec.message() << "\n";
      return 2;
    }
    os << llvm::formatv("{0:2}", sarif(findings)) << "\n";
  }
  llvm::errs() << "cwe-scan: " << files.size() << " files, " << findings.size() << " findings, " << failed
               << " files with errors, " << llvm::formatv("{0:F2}", secs) << " s\n";
  return failed ? 3 : 0;
}
