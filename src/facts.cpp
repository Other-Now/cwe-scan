// Program-wide facts used to fold branch guards: globals that are never
// written after their constant initializer, and functions that just return a
// constant. Juliet's flow variants 04-14 hide their branches behind exactly
// these (`if (staticTrue)`, `if (globalReturnsTrue())`), and real code does
// the same with configuration flags.
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "scan.h"

using namespace clang;

namespace cwescan {

std::string symbolKey(const NamedDecl* d, int tu, const Options& o) {
  std::string name = d->getQualifiedNameAsString();
  if (auto fd = dyn_cast<FunctionDecl>(d)) name += "/" + std::to_string(fd->getNumParams());
  if (o.perFile || !d->isExternallyVisible()) return std::to_string(tu) + ":" + name;
  return name;
}

namespace {

const VarDecl* globalRef(const Expr* e) {
  if (!e) return nullptr;
  if (auto dr = dyn_cast<DeclRefExpr>(e->IgnoreParenImpCasts()))
    if (auto v = dyn_cast<VarDecl>(dr->getDecl()))
      if (v->hasGlobalStorage() && !v->isStaticLocal()) return v;
  return nullptr;
}

class FactVisitor : public RecursiveASTVisitor<FactVisitor> {
 public:
  FactVisitor(ASTContext& c, int tu, Program& p) : ctx(c), tu(tu), p(p) {}

  bool VisitVarDecl(VarDecl* v) {
    if (!v->hasGlobalStorage() || v->isStaticLocal() || !v->getInit()) return true;
    if (!v->getType()->isIntegralOrEnumerationType()) return true;
    // In per-file mode another file could write an external global, so only
    // file-static or const ones are known constants.
    if (p.opts.perFile && v->isExternallyVisible() && !v->getType().isConstQualified()) return true;
    Expr::EvalResult r;
    if (v->getInit()->EvaluateAsInt(r, ctx))
      p.initVals[symbolKey(v, tu, p.opts)] = r.Val.getInt().getExtValue();
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator* b) {
    if (b->isAssignmentOp())
      if (auto v = globalRef(b->getLHS())) p.written.insert(symbolKey(v, tu, p.opts));
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator* u) {
    if (u->isIncrementDecrementOp() || u->getOpcode() == UO_AddrOf)
      if (auto v = globalRef(u->getSubExpr())) p.written.insert(symbolKey(v, tu, p.opts));
    return true;
  }

  bool VisitFunctionDecl(FunctionDecl* fd) {
    if (!fd->doesThisDeclarationHaveABody() || fd->getNumParams() != 0) return true;
    auto body = dyn_cast<CompoundStmt>(fd->getBody());
    if (!body || body->size() != 1) return true;
    auto ret = dyn_cast<ReturnStmt>(body->body_front());
    if (!ret || !ret->getRetValue()) return true;
    Expr::EvalResult r;
    if (ret->getRetValue()->EvaluateAsInt(r, ctx))
      p.constFuncs[symbolKey(fd, tu, p.opts)] = r.Val.getInt().getExtValue();
    return true;
  }

 private:
  ASTContext& ctx;
  int tu;
  Program& p;
};

}  // namespace

void collectFacts(ASTContext& ctx, int tu, Program& p) {
  FactVisitor v(ctx, tu, p);
  v.TraverseDecl(ctx.getTranslationUnitDecl());
}

void finishFacts(Program& p) {
  p.constVars.clear();
  for (auto& [k, val] : p.initVals)
    if (!p.written.count(k)) p.constVars[k] = val;
}

const char* cweTitle(int cwe) {
  switch (cwe) {
    case 476: return "NULL Pointer Dereference";
    case 416: return "Use After Free";
    case 415: return "Double Free";
    case 401: return "Missing Release of Memory after Effective Lifetime";
  }
  return "";
}

const char* certRule(int cwe) {
  switch (cwe) {
    case 476: return "EXP34-C";
    case 416: return "MEM30-C";
    case 415: return "MEM30-C";
    case 401: return "MEM31-C";
  }
  return "";
}

}  // namespace cwescan
