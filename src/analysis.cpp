// The dataflow engine. One forward pass over the function's CFG, to a fixed
// point, over this per-path state:
//
//   for each tracked pointer variable:
//     nullness   a set of {null, non-null, unknown}; "may be null" means the
//                null bit is set on some path reaching here
//     sites      which allocation sites it may point to
//     derefd     dereferenced on every path since its last assignment
//   for each allocation site:
//     live / freed / escaped, again as a may-set over paths
//
// Joins are unions (derefd is an intersection). Branches on `p`, `!p`,
// `p == NULL` and `p != NULL` refine the state on each edge, and branches on
// guards that are constant (literally, or across the program) are pruned.
// After the fixed point, a second pass over every reached block reports.
#include <deque>
#include <optional>

#include "clang/AST/ASTContext.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/Builtins.h"
#include "clang/Basic/SourceManager.h"
#include "scan.h"

using namespace clang;

namespace cwescan {
namespace {

enum : uint8_t { NB_NULL = 1, NB_NONNULL = 2, NB_UNKNOWN = 4 };
enum : uint8_t { S_LIVE = 1, S_FREED = 2, S_ESCAPED = 4 };

struct Val {
  uint8_t nb = NB_UNKNOWN;
  std::set<int> sites;
  std::set<int> reallocOld;  // blocks a pending `realloc` frees only if it succeeds
  bool derefd = false;
  bool operator==(const Val& o) const {
    return nb == o.nb && sites == o.sites && reallocOld == o.reallocOld && derefd == o.derefd;
  }
};

struct State {
  bool reached = false;
  std::map<const VarDecl*, Val> vars;
  std::map<int, uint8_t> sites;
  bool operator==(const State& o) const {
    return reached == o.reached && vars == o.vars && sites == o.sites;
  }
  bool operator!=(const State& o) const { return !(*this == o); }
};

State join(const State& a, const State& b) {
  if (!a.reached) return b;
  if (!b.reached) return a;
  State r = a;
  for (auto& [v, val] : r.vars)
    if (!b.vars.count(v)) val.derefd = false;
  for (auto& [v, bv] : b.vars) {
    auto it = r.vars.find(v);
    if (it == r.vars.end()) {
      Val x = bv;
      x.derefd = false;
      r.vars[v] = x;
      continue;
    }
    Val& x = it->second;
    x.nb |= bv.nb;
    x.sites.insert(bv.sites.begin(), bv.sites.end());
    x.reallocOld.insert(bv.reallocOld.begin(), bv.reallocOld.end());
    x.derefd = x.derefd && bv.derefd;
  }
  for (auto& [s, bits] : b.sites) r.sites[s] |= bits;
  return r;
}

struct Site {
  SourceLocation loc;
  int param = -1;  // >= 0: the object a pointer parameter points to on entry
  SourceLocation freedAt;
};

bool isNull(const Expr* e, ASTContext& ctx) {
  if (!e) return false;
  e = e->IgnoreParens();
  if (auto ic = dyn_cast<ImplicitCastExpr>(e))
    if (ic->getCastKind() == CK_NullToPointer) return true;
  return e->isNullPointerConstant(ctx, Expr::NPC_ValueDependentIsNotNull) ||
         e->IgnoreParenCasts()->isNullPointerConstant(ctx, Expr::NPC_ValueDependentIsNotNull);
}

bool topLevelNamed(const FunctionDecl* fd, std::initializer_list<const char*> names) {
  if (!fd || !fd->getIdentifier()) return false;
  const DeclContext* dc = fd->getDeclContext()->getRedeclContext();
  if (!dc->isTranslationUnit() && !dc->isExternCContext() && !dc->isStdNamespace()) return false;
  StringRef n = fd->getName();
  for (auto x : names)
    if (n == x) return true;
  return false;
}

bool isAllocFn(const FunctionDecl* fd) {
  return topLevelNamed(fd, {"malloc", "calloc", "realloc", "strdup", "strndup", "wcsdup",
                            "aligned_alloc"});
}
bool isReallocFn(const FunctionDecl* fd) { return topLevelNamed(fd, {"realloc"}); }
bool isFreeFn(const FunctionDecl* fd) { return topLevelNamed(fd, {"free"}); }

bool isNonnullParam(const FunctionDecl* fd, unsigned i) {
  if (i < fd->getNumParams() && fd->getParamDecl(i)->hasAttr<NonNullAttr>()) return true;
  for (const auto* a : fd->specific_attrs<NonNullAttr>()) {
    if (a->args_size() == 0) return true;
    for (const ParamIdx& idx : a->args())
      if (idx.getASTIndex() == i) return true;
  }
  return false;
}

bool pointsToConst(QualType t) {
  return t->isPointerType() && t->getPointeeType().isConstQualified();
}

class Analyzer {
 public:
  Analyzer(const FunctionDecl* fd, ASTContext& ctx, int tu, const Program& p,
           std::vector<Finding>* out)
      : fd(fd), ctx(ctx), sm(ctx.getSourceManager()), tu(tu), prog(p), out(out) {}

  Summary run();

 private:
  // ---- prepass: aliases and variables whose address escapes ----
  friend class Prepass;
  std::map<const VarDecl*, const VarDecl*> refAlias;  // T &r = v      : r names v
  std::map<const VarDecl*, const VarDecl*> ptrAlias;  // T **pp = &v   : *pp names v
  std::set<const VarDecl*> untracked;
  std::set<const Expr*> assignedRhs;
  std::map<const VarDecl*, const FunctionDecl*> fnPtr;
  // `for (i = C; cond; inc)` loops whose condition holds for i == C and
  // whose body doesn't write i: the first test of the condition can't fail.
  std::set<const ForStmt*> entersOnce;
  std::set<const ForStmt*> runsOnce;  // ...and whose second test always fails
  void prepass();
  void findEntersOnce();

  bool tracked(const VarDecl* v) const {
    if (!v || !v->hasLocalStorage() || v->getType()->isReferenceType()) return false;
    QualType t = v->getType();
    if (!t->isPointerType() || t->getPointeeType()->isFunctionType()) return false;
    return !untracked.count(v) && !ptrAlias.count(v);
  }
  const VarDecl* resolveVar(const Expr* e) const;
  const FunctionDecl* calleeOf(const CallExpr* c) const;
  const Summary* summaryOf(const FunctionDecl* callee) const;

  // ---- transfer ----
  int siteFor(const Expr* e);
  Val eval(const Expr* e, State& st);
  void transfer(const Stmt* s, State& st);
  void declVar(const VarDecl* v, State& st);
  void assignTo(const Expr* lhs, const Expr* rhs, SourceLocation loc, State& st);
  void assignVar(const VarDecl* v, Val nv, SourceLocation loc, State& st);
  void deref(const Expr* base, SourceLocation loc, State& st);
  void useVal(const Val& v, SourceLocation loc, const std::string& how, State& st);
  void freeVal(const Val& v, SourceLocation loc, State& st);
  void escapeVal(const Val& v, State& st);
  void call(const CallExpr* c, State& st);
  void construct(const CXXConstructExpr* c, State& st);
  void ret(const ReturnStmt* r, State& st);
  void nullTest(const Expr* ptr, SourceLocation loc, State& st);
  bool heldElsewhere(int site, const VarDecl* except, const State& st) const;

  // ---- edges ----
  std::optional<bool> foldBool(const Expr* c) const;
  std::optional<long long> evalInt(const Expr* e) const;
  const VarDecl* matchNullTest(const Expr* c, bool& trueMeansNonNull) const;
  const VarDecl* matchNullTestInner(const Expr* c, bool& trueMeansNonNull) const;
  mutable bool testInMacro = false;  // set by matchNullTest
  State edge(const CFGBlock* b, unsigned succIndex, const State& in) const;

  // definite: the condition holds on every path reaching here (null on all
  // paths, freed on all paths...), not just on some.
  void report(int cwe, SourceLocation loc, std::string msg, bool definite);
  std::string name(const VarDecl* v) const { return v->getNameAsString(); }
  unsigned lineOf(SourceLocation l) const { return sm.getExpansionLineNumber(l); }

  const FunctionDecl* fd;
  ASTContext& ctx;
  SourceManager& sm;
  int tu;
  const Program& prog;
  std::vector<Finding>* out;
  bool reporting = false;

  std::map<const Expr*, int> siteOf;
  std::vector<Site> sites;
  std::map<const VarDecl*, SourceLocation> derefAt;
  std::set<std::tuple<int, unsigned, unsigned>> seen;
  Summary sum;
  // A callee that returns null on only some paths usually does so under a
  // precondition its callers know about (lua_tothread after lua_isthread).
  // Only a function that returns null on every path gets retNull.
  bool sawNullReturn = false, sawOtherReturn = false;
};

// ---------------------------------------------------------------- prepass

class Prepass : public RecursiveASTVisitor<Prepass> {
 public:
  explicit Prepass(Analyzer& a) : a(a) {}

  bool VisitVarDecl(VarDecl* v) {
    if (!v->hasLocalStorage() || !v->getInit()) return true;
    const Expr* init = v->getInit();
    if (v->getType()->isReferenceType()) {
      if (auto dr = dyn_cast<DeclRefExpr>(init->IgnoreParenImpCasts()))
        if (auto t = dyn_cast<VarDecl>(dr->getDecl())) a.refAlias[v] = t;
      return true;
    }
    a.assignedRhs.insert(init->IgnoreParenCasts());
    pointerAssign(v, init, false);
    if (v->getType()->isFunctionPointerType())
      if (auto dr = dyn_cast<DeclRefExpr>(init->IgnoreParenImpCasts()))
        if (auto f = dyn_cast<FunctionDecl>(dr->getDecl())) a.fnPtr[v] = f;
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator* b) {
    if (!b->isAssignmentOp()) return true;
    a.assignedRhs.insert(b->getRHS()->IgnoreParenCasts());
    if (auto dr = dyn_cast<DeclRefExpr>(b->getLHS()->IgnoreParenImpCasts()))
      if (auto v = dyn_cast<VarDecl>(dr->getDecl())) {
        pointerAssign(v, b->getRHS(), b->getOpcode() != BO_Assign);
        if (v->getType()->isFunctionPointerType()) fnPtrWritten.insert(v);
      }
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator* u) {
    if (u->getOpcode() == UO_AddrOf)
      if (auto dr = dyn_cast<DeclRefExpr>(u->getSubExpr()->IgnoreParens()))
        if (auto v = dyn_cast<VarDecl>(dr->getDecl())) addrOf.push_back({u, v});
    if (u->isIncrementDecrementOp())
      if (auto dr = dyn_cast<DeclRefExpr>(u->getSubExpr()->IgnoreParens()))
        if (auto v = dyn_cast<VarDecl>(dr->getDecl())) notAlias.insert(v);
    return true;
  }

  void finish() {
    for (auto& [uo, v] : addrOf)
      if (!consumedBy.count(uo)) a.untracked.insert(v);
    for (auto& [pp, ts] : targets)
      if (!notAlias.count(pp) && !a.untracked.count(pp) && ts.size() == 1)
        a.ptrAlias[pp] = *ts.begin();
    for (auto& [uo, pp] : consumedBy)
      if (!a.ptrAlias.count(pp))
        for (auto& [u2, v] : addrOf)
          if (u2 == uo) a.untracked.insert(v);
    for (auto v : fnPtrWritten) a.fnPtr.erase(v);
  }

 private:
  // Records `pp = &v` (a candidate alias) or any other write to pp.
  void pointerAssign(const VarDecl* pp, const Expr* rhs, bool compound) {
    if (!pp->hasLocalStorage() || !pp->getType()->isPointerType()) return;
    if (!pp->getType()->getPointeeType()->isPointerType()) return;
    const Expr* r = rhs->IgnoreParenCasts();
    auto u = dyn_cast<UnaryOperator>(r);
    if (!compound && u && u->getOpcode() == UO_AddrOf)
      if (auto dr = dyn_cast<DeclRefExpr>(u->getSubExpr()->IgnoreParens()))
        if (auto t = dyn_cast<VarDecl>(dr->getDecl())) {
          targets[pp].insert(t);
          consumedBy[u] = pp;
          return;
        }
    notAlias.insert(pp);
  }

  Analyzer& a;
  std::vector<std::pair<const UnaryOperator*, const VarDecl*>> addrOf;
  std::map<const UnaryOperator*, const VarDecl*> consumedBy;
  std::map<const VarDecl*, std::set<const VarDecl*>> targets;
  std::set<const VarDecl*> notAlias;
  std::set<const VarDecl*> fnPtrWritten;
};

void Analyzer::prepass() {
  Prepass p(*this);
  p.TraverseStmt(const_cast<Stmt*>(fd->getBody()));
  p.finish();
  findEntersOnce();
}

namespace {

const VarDecl* intVarOf(const Expr* e) {
  if (auto dr = dyn_cast<DeclRefExpr>(e->IgnoreParenImpCasts()))
    if (auto v = dyn_cast<VarDecl>(dr->getDecl()))
      if (v->hasLocalStorage() && v->getType()->isIntegralOrEnumerationType()) return v;
  return nullptr;
}

bool writes(const Stmt* s, const VarDecl* v) {
  if (!s) return false;
  if (auto b = dyn_cast<BinaryOperator>(s); b && b->isAssignmentOp() && intVarOf(b->getLHS()) == v) return true;
  if (auto u = dyn_cast<UnaryOperator>(s)) {
    if ((u->isIncrementDecrementOp() || u->getOpcode() == UO_AddrOf) && intVarOf(u->getSubExpr()) == v) return true;
  }
  for (const Stmt* c : s->children())
    if (writes(c, v)) return true;
  return false;
}

class ForFinder : public RecursiveASTVisitor<ForFinder> {
 public:
  std::vector<const ForStmt*> loops;
  bool VisitForStmt(ForStmt* f) {
    loops.push_back(f);
    return true;
  }
};

}  // namespace

void Analyzer::findEntersOnce() {
  ForFinder ff;
  ff.TraverseStmt(const_cast<Stmt*>(fd->getBody()));
  for (const ForStmt* f : ff.loops) {
    const Expr* cond = f->getCond();
    if (!f->getInit() || !cond) continue;
    const VarDecl* v = nullptr;
    const Expr* initVal = nullptr;
    if (auto b = dyn_cast<BinaryOperator>(f->getInit()); b && b->getOpcode() == BO_Assign) {
      v = intVarOf(b->getLHS());
      initVal = b->getRHS();
    } else if (auto ds = dyn_cast<DeclStmt>(f->getInit()); ds && ds->isSingleDecl()) {
      if (auto vd = dyn_cast<VarDecl>(ds->getSingleDecl()); vd && vd->getType()->isIntegralOrEnumerationType()) {
        v = vd;
        initVal = vd->getInit();
      }
    }
    if (!v || !initVal || writes(f->getBody(), v)) continue;
    auto c0 = evalInt(initVal);
    auto b = dyn_cast<BinaryOperator>(cond->IgnoreParenImpCasts());
    if (!c0 || !b || !b->isComparisonOp() || intVarOf(b->getLHS()) != v) continue;
    auto bound = evalInt(b->getRHS());
    if (!bound) continue;
    bool holds = false;
    switch (b->getOpcode()) {
      case BO_LT: holds = *c0 < *bound; break;
      case BO_LE: holds = *c0 <= *bound; break;
      case BO_GT: holds = *c0 > *bound; break;
      case BO_GE: holds = *c0 >= *bound; break;
      case BO_NE: holds = *c0 != *bound; break;
      default: break;
    }
    if (!holds) continue;
    entersOnce.insert(f);
    // `for (i = C; i < C + 1; i++)` (or the mirror with >, --) runs exactly
    // once, so the state coming back round can only leave.
    const Expr* inc = f->getInc() ? f->getInc()->IgnoreParenImpCasts() : nullptr;
    auto u = inc ? dyn_cast<UnaryOperator>(inc) : nullptr;
    if (!u || !u->isIncrementDecrementOp() || intVarOf(u->getSubExpr()) != v) continue;
    long long next = *c0 + (u->isIncrementOp() ? 1 : -1);
    bool again = false;
    switch (b->getOpcode()) {
      case BO_LT: again = next < *bound; break;
      case BO_LE: again = next <= *bound; break;
      case BO_GT: again = next > *bound; break;
      case BO_GE: again = next >= *bound; break;
      case BO_NE: again = next != *bound; break;
      default: again = true; break;
    }
    if (!again) runsOnce.insert(f);
  }
}

// ---------------------------------------------------------------- helpers

const VarDecl* Analyzer::resolveVar(const Expr* e) const {
  if (!e) return nullptr;
  e = e->IgnoreParenCasts();
  if (auto dr = dyn_cast<DeclRefExpr>(e)) {
    auto v = dyn_cast<VarDecl>(dr->getDecl());
    if (!v) return nullptr;
    auto it = refAlias.find(v);
    if (it != refAlias.end()) v = it->second;
    return tracked(v) ? v : nullptr;
  }
  if (auto u = dyn_cast<UnaryOperator>(e); u && u->getOpcode() == UO_Deref)
    if (auto dr = dyn_cast<DeclRefExpr>(u->getSubExpr()->IgnoreParenCasts()))
      if (auto pp = dyn_cast<VarDecl>(dr->getDecl())) {
        auto it = ptrAlias.find(pp);
        if (it != ptrAlias.end() && tracked(it->second)) return it->second;
      }
  return nullptr;
}

const FunctionDecl* Analyzer::calleeOf(const CallExpr* c) const {
  if (auto f = c->getDirectCallee()) return f;
  const Expr* e = c->getCallee()->IgnoreParenImpCasts();
  if (auto u = dyn_cast<UnaryOperator>(e); u && u->getOpcode() == UO_Deref)
    e = u->getSubExpr()->IgnoreParenImpCasts();
  if (auto dr = dyn_cast<DeclRefExpr>(e))
    if (auto v = dyn_cast<VarDecl>(dr->getDecl())) {
      auto it = fnPtr.find(v);
      if (it != fnPtr.end()) return it->second;
    }
  return nullptr;
}

const Summary* Analyzer::summaryOf(const FunctionDecl* callee) const {
  if (!callee || !prog.opts.summaries) return nullptr;
  auto it = prog.summaries.find(symbolKey(callee, tu, prog.opts));
  return it == prog.summaries.end() ? nullptr : &it->second;
}

int Analyzer::siteFor(const Expr* e) {
  auto it = siteOf.find(e);
  if (it != siteOf.end()) return it->second;
  int id = static_cast<int>(sites.size());
  sites.push_back({e->getBeginLoc(), -1, {}});
  siteOf[e] = id;
  return id;
}

bool Analyzer::heldElsewhere(int site, const VarDecl* except, const State& st) const {
  for (auto& [v, val] : st.vars) {
    if (val.reallocOld.count(site)) return true;
    if (v != except && val.sites.count(site)) return true;
  }
  return false;
}

void Analyzer::report(int cwe, SourceLocation loc, std::string msg, bool definite) {
  if (!reporting || !out) return;
  SourceLocation e = sm.getExpansionLoc(loc);
  if (e.isInvalid() || !sm.isInMainFile(e)) return;
  unsigned line = sm.getExpansionLineNumber(e), col = sm.getExpansionColumnNumber(e);
  if (!seen.insert({cwe, line, col}).second) return;
  Finding f;
  f.cwe = cwe;
  f.file = sm.getFilename(e).str();
  f.line = line;
  f.col = col;
  f.function = fd->getQualifiedNameAsString();
  f.message = std::move(msg);
  f.definite = definite;
  out->push_back(std::move(f));
}

// ---------------------------------------------------------------- values

Val Analyzer::eval(const Expr* e, State& st) {
  if (!e) return {};
  const Expr* p = e->IgnoreParens();
  if (isNull(p, ctx)) return Val{NB_NULL, {}, {}, false};
  if (auto ic = dyn_cast<ImplicitCastExpr>(p)) {
    auto k = ic->getCastKind();
    if (k == CK_ArrayToPointerDecay || k == CK_FunctionToPointerDecay)
      return Val{NB_NONNULL, {}, {}, false};
  }
  p = p->IgnoreParenCasts();
  if (auto v = resolveVar(p)) {
    auto it = st.vars.find(v);
    if (it == st.vars.end()) return Val{};
    Val r = it->second;
    r.derefd = false;
    r.reallocOld.clear();
    return r;
  }
  if (isa<StringLiteral>(p) || isa<CXXThisExpr>(p)) return Val{NB_NONNULL, {}, {}, false};
  if (auto u = dyn_cast<UnaryOperator>(p); u && u->getOpcode() == UO_AddrOf)
    return Val{NB_NONNULL, {}, {}, false};
  if (auto n = dyn_cast<CXXNewExpr>(p)) {
    int s = siteFor(n);
    st.sites[s] = S_LIVE;
    return Val{NB_NONNULL, {s}, {}, false};
  }
  if (auto c = dyn_cast<CallExpr>(p)) {
    const FunctionDecl* f = calleeOf(c);
    if (isAllocFn(f)) {
      int s = siteFor(c);
      st.sites[s] = S_LIVE;
      Val r{NB_UNKNOWN, {s}, {}, false};
      if (isReallocFn(f) && c->getNumArgs() > 0) {
        Val old = eval(c->getArg(0), st);
        for (int o : old.sites)
          if (o != s) r.reallocOld.insert(o);
      }
      return r;
    }
    if (const Summary* fs = summaryOf(f)) {
      Val r{NB_UNKNOWN, {}, {}, false};
      if (fs->retNull) r.nb |= NB_NULL;
      if (fs->retAlloc) {
        int s = siteFor(c);
        st.sites[s] = S_LIVE;
        r.sites.insert(s);
      }
      return r;
    }
    return Val{};
  }
  if (auto co = dyn_cast<ConditionalOperator>(p)) {
    Val a = eval(co->getTrueExpr(), st), b = eval(co->getFalseExpr(), st);
    a.nb |= b.nb;
    a.sites.insert(b.sites.begin(), b.sites.end());
    return a;
  }
  if (auto b = dyn_cast<BinaryOperator>(p)) {
    if (b->getOpcode() == BO_Comma) return eval(b->getRHS(), st);
    if (b->isAdditiveOp()) {
      const Expr* ptr = b->getLHS()->getType()->isPointerType() ? b->getLHS() : b->getRHS();
      Val r = eval(ptr, st);
      r.reallocOld.clear();
      return r;
    }
  }
  return Val{};
}

// ---------------------------------------------------------------- transfer

void Analyzer::transfer(const Stmt* s, State& st) {
  if (auto ds = dyn_cast<DeclStmt>(s)) {
    for (auto d : ds->decls())
      if (auto v = dyn_cast<VarDecl>(d)) declVar(v, st);
    return;
  }
  if (auto b = dyn_cast<BinaryOperator>(s)) {
    if (b->getOpcode() == BO_Assign) {
      assignTo(b->getLHS(), b->getRHS(), b->getOperatorLoc(), st);
    } else if (b->isEqualityOp()) {
      if (isNull(b->getRHS(), ctx)) nullTest(b->getLHS(), b->getOperatorLoc(), st);
      else if (isNull(b->getLHS(), ctx)) nullTest(b->getRHS(), b->getOperatorLoc(), st);
    }
    return;
  }
  if (auto u = dyn_cast<UnaryOperator>(s)) {
    if (u->getOpcode() == UO_Deref) deref(u->getSubExpr(), u->getOperatorLoc(), st);
    else if (u->getOpcode() == UO_LNot && u->getSubExpr()->IgnoreParenImpCasts()->getType()->isPointerType())
      nullTest(u->getSubExpr(), u->getOperatorLoc(), st);
    return;
  }
  if (auto a = dyn_cast<ArraySubscriptExpr>(s)) {
    deref(a->getBase(), a->getBeginLoc(), st);
    return;
  }
  if (auto m = dyn_cast<MemberExpr>(s)) {
    if (m->isArrow()) deref(m->getBase(), m->getOperatorLoc(), st);
    return;
  }
  if (auto ic = dyn_cast<ImplicitCastExpr>(s)) {
    if (ic->getCastKind() == CK_PointerToBoolean) nullTest(ic->getSubExpr(), ic->getBeginLoc(), st);
    return;
  }
  if (auto d = dyn_cast<CXXDeleteExpr>(s)) {
    freeVal(eval(d->getArgument(), st), d->getBeginLoc(), st);
    return;
  }
  if (auto c = dyn_cast<CallExpr>(s)) {
    call(c, st);
    return;
  }
  if (auto c = dyn_cast<CXXConstructExpr>(s)) {
    construct(c, st);
    return;
  }
  if (auto r = dyn_cast<ReturnStmt>(s)) {
    ret(r, st);
    return;
  }
}

void Analyzer::declVar(const VarDecl* v, State& st) {
  if (!v->hasLocalStorage() || v->getType()->isReferenceType()) return;
  const Expr* init = v->getInit();
  if (!tracked(v)) {
    // A pointer stored into anything we don't follow (an untracked variable,
    // an aggregate initializer) has escaped.
    if (init && v->getType()->isPointerType()) escapeVal(eval(init, st), st);
    if (auto il = init ? dyn_cast<InitListExpr>(init->IgnoreParenImpCasts()) : nullptr)
      for (const Expr* x : il->inits())
        if (x->getType()->isPointerType()) escapeVal(eval(x, st), st);
    return;
  }
  assignVar(v, init ? eval(init, st) : Val{}, v->getLocation(), st);
}

void Analyzer::assignTo(const Expr* lhs, const Expr* rhs, SourceLocation loc, State& st) {
  if (const VarDecl* v = resolveVar(lhs)) {
    if (auto c = dyn_cast<CallExpr>(rhs->IgnoreParenCasts()); c && isReallocFn(calleeOf(c)) && c->getNumArgs() > 0) {
      if (resolveVar(c->getArg(0)) == v) {
        Val old = eval(c->getArg(0), st);
        bool reported = false;
        for (int s : old.sites)
          if (st.sites[s] & S_LIVE) {
            if (!reported)
              report(401, loc,
                     "'realloc' result is assigned to '" + name(v) +
                         "', its only pointer to the original block; if realloc fails, that block leaks",
                     st.sites[s] == S_LIVE);
            reported = true;
            st.sites[s] &= ~S_LIVE;  // reported once here, not again at exit
          }
      }
    }
    assignVar(v, eval(rhs, st), loc, st);
    return;
  }
  if (lhs->getType()->isPointerType()) escapeVal(eval(rhs, st), st);
}

void Analyzer::assignVar(const VarDecl* v, Val nv, SourceLocation loc, State& st) {
  auto it = st.vars.find(v);
  if (it != st.vars.end()) {
    for (int s : it->second.sites) {
      if (nv.sites.count(s) || nv.reallocOld.count(s) || sites[s].param >= 0) continue;
      if (heldElsewhere(s, v, st)) continue;
      if (st.sites[s] & S_LIVE)
        report(401, sites[s].loc,
               "memory allocated here is lost when '" + name(v) + "' is overwritten at line " +
                   std::to_string(lineOf(loc)),
               st.sites[s] == S_LIVE);
      // Nothing points to this block any more on this path. Dropping it keeps
      // its state here from polluting paths where it is still reachable.
      st.sites.erase(s);
    }
  }
  nv.derefd = false;
  st.vars[v] = std::move(nv);
}

void Analyzer::deref(const Expr* base, SourceLocation loc, State& st) {
  const VarDecl* v = resolveVar(base);
  if (!v) return;
  Val& val = st.vars[v];
  if (val.nb & NB_NULL)
    report(476, loc,
           val.nb == NB_NULL ? "'" + name(v) + "' is null here on every path"
                             : "'" + name(v) + "' may be null here: it is null, or was checked against null, on some path",
           val.nb == NB_NULL);
  useVal(val, loc, "dereferenced", st);
  // Only a dereference of the parameter itself counts. A copy taken before
  // the parameter's null check (`q = p; if (!p) return; *q`) still looks
  // unchecked, because refining p doesn't refine q.
  if (reporting && (val.nb & NB_UNKNOWN))
    if (auto pv = dyn_cast<ParmVarDecl>(v))
      for (int s : val.sites)
        if (sites[s].param >= 0 && fd->getParamDecl(sites[s].param) == pv) sum.params[sites[s].param] |= P_DEREF;
  val.nb = NB_NONNULL;
  val.derefd = true;
  derefAt[v] = loc;
}

void Analyzer::useVal(const Val& v, SourceLocation loc, const std::string& how, State& st) {
  for (int s : v.sites) {
    auto it = st.sites.find(s);
    if (it != st.sites.end() && (it->second & S_FREED)) {
      std::string where = sites[s].freedAt.isValid()
                              ? " (freed at line " + std::to_string(lineOf(sites[s].freedAt)) + ")"
                              : "";
      report(416, loc, "memory that may already be freed" + where + " is " + how,
             it->second == S_FREED && v.sites.size() == 1);
      return;
    }
  }
}

void Analyzer::freeVal(const Val& v, SourceLocation loc, State& st) {
  for (int s : v.sites) {
    uint8_t& b = st.sites[s];
    if (b & S_FREED) {
      std::string where = sites[s].freedAt.isValid()
                              ? " at line " + std::to_string(lineOf(sites[s].freedAt))
                              : "";
      report(415, loc, "memory that may already have been freed" + where + " is freed again",
             b == S_FREED && v.sites.size() == 1);
    }
    b = (b & ~S_LIVE) | S_FREED;
    sites[s].freedAt = loc;
  }
}

void Analyzer::escapeVal(const Val& v, State& st) {
  for (int s : v.sites) {
    uint8_t& b = st.sites[s];
    b = (b & ~S_LIVE) | S_ESCAPED;
  }
}

void Analyzer::call(const CallExpr* c, State& st) {
  const FunctionDecl* f = calleeOf(c);
  if (isFreeFn(f)) {
    if (c->getNumArgs() > 0) freeVal(eval(c->getArg(0), st), c->getBeginLoc(), st);
    return;
  }
  if (isReallocFn(f)) return;  // handled where its result is assigned
  const Summary* summary = summaryOf(f);
  std::string callee = f ? f->getNameAsString() : "an indirect call";
  // The C library never takes ownership of a pointer it is passed. C++
  // library calls can (std::vector::insert stores it), so they don't qualify.
  bool system = f && sm.isInSystemHeader(f->getLocation()) &&
                (f->isExternC() || !ctx.getLangOpts().CPlusPlus);
  for (unsigned i = 0; i < c->getNumArgs(); ++i) {
    const Expr* arg = c->getArg(i);
    const ParmVarDecl* pd = f && i < f->getNumParams() ? f->getParamDecl(i) : nullptr;
    // A non-const reference to a pointer lets the callee reassign it.
    if (pd && pd->getType()->isLValueReferenceType() &&
        pd->getType().getNonReferenceType()->isPointerType() &&
        !pd->getType().getNonReferenceType().isConstQualified()) {
      if (const VarDecl* v = resolveVar(arg)) {
        escapeVal(st.vars[v], st);
        st.vars[v] = Val{};
      }
      continue;
    }
    if (!arg->getType()->isPointerType()) continue;
    Val v = eval(arg, st);
    if (v.sites.empty() && !(v.nb & NB_NULL)) continue;
    useVal(v, arg->getBeginLoc(), "passed to '" + callee + "'", st);
    if ((v.nb & NB_NULL) && f) {
      if (isNonnullParam(f, i))
        report(476, arg->getBeginLoc(),
               "a pointer that may be null is passed to '" + callee + "', whose parameter is declared nonnull",
               v.nb == NB_NULL);
      else if (summary && i < summary->params.size() && (summary->params[i] & P_DEREF))
        report(476, arg->getBeginLoc(),
               "a pointer that may be null is passed to '" + callee + "', which dereferences it",
               v.nb == NB_NULL);
    }
    uint8_t effect;
    if (summary) effect = i < summary->params.size() ? summary->params[i] : 0;
    else if (system || isAllocFn(f)) effect = 0;           // libc never takes ownership
    else if (pd && pointsToConst(pd->getType())) effect = 0;  // nor does a const parameter
    else effect = P_ESCAPE;
    if (effect & P_FREE) freeVal(v, arg->getBeginLoc(), st);
    if (effect & P_ESCAPE) escapeVal(v, st);
  }
}

void Analyzer::construct(const CXXConstructExpr* c, State& st) {
  const CXXConstructorDecl* ctor = c->getConstructor();
  if (ctor && (ctor->isCopyOrMoveConstructor())) return;
  for (unsigned i = 0; i < c->getNumArgs(); ++i) {
    const Expr* arg = c->getArg(i);
    if (!arg->getType()->isPointerType()) continue;
    Val v = eval(arg, st);
    useVal(v, arg->getBeginLoc(), "passed to a constructor", st);
    const ParmVarDecl* pd = ctor && i < ctor->getNumParams() ? ctor->getParamDecl(i) : nullptr;
    if (!(pd && pointsToConst(pd->getType()))) escapeVal(v, st);
  }
}

void Analyzer::ret(const ReturnStmt* r, State& st) {
  const Expr* e = r->getRetValue();
  if (!e || !e->getType()->isPointerType()) return;
  Val v = eval(e, st);
  useVal(v, r->getBeginLoc(), "returned", st);
  if (reporting) {
    if (v.nb & NB_NULL) sawNullReturn = true;
    if (v.nb & (NB_NONNULL | NB_UNKNOWN)) sawOtherReturn = true;
    for (int s : v.sites)
      if (sites[s].param < 0 && (st.sites[s] & S_LIVE)) sum.retAlloc = true;
  }
  escapeVal(v, st);
}

void Analyzer::nullTest(const Expr* ptr, SourceLocation loc, State& st) {
  if (loc.isMacroID()) return;  // defensive checks in macros: see matchNullTestInner
  const VarDecl* v = resolveVar(ptr);
  if (!v) return;
  auto it = st.vars.find(v);
  if (it == st.vars.end() || !it->second.derefd || (it->second.nb & NB_NULL)) return;
  auto d = derefAt.find(v);
  std::string where = d != derefAt.end() ? " at line " + std::to_string(lineOf(d->second)) : "";
  report(476, loc, "'" + name(v) + "' is checked for null after it was dereferenced" + where, true);
}

// ---------------------------------------------------------------- edges

std::optional<long long> Analyzer::evalInt(const Expr* e) const {
  e = e->IgnoreParenImpCasts();
  if (auto i = dyn_cast<IntegerLiteral>(e)) return i->getValue().getSExtValue();
  if (auto b = dyn_cast<CXXBoolLiteralExpr>(e)) return b->getValue() ? 1 : 0;
  if (auto c = dyn_cast<CharacterLiteral>(e)) return c->getValue();
  if (auto dr = dyn_cast<DeclRefExpr>(e)) {
    if (auto ec = dyn_cast<EnumConstantDecl>(dr->getDecl())) return ec->getInitVal().getSExtValue();
    auto v = dyn_cast<VarDecl>(dr->getDecl());
    if (!v) return std::nullopt;
    if (v->getType().isConstQualified() && v->getInit()) {
      Expr::EvalResult r;
      if (v->getInit()->EvaluateAsInt(r, ctx)) return r.Val.getInt().getExtValue();
    }
    if (v->hasGlobalStorage() && !v->isStaticLocal()) {
      auto it = prog.constVars.find(symbolKey(v, tu, prog.opts));
      if (it != prog.constVars.end()) return it->second;
    }
    return std::nullopt;
  }
  if (auto c = dyn_cast<CallExpr>(e)) {
    if (auto f = c->getDirectCallee(); f && c->getNumArgs() == 0) {
      auto it = prog.constFuncs.find(symbolKey(f, tu, prog.opts));
      if (it != prog.constFuncs.end()) return it->second;
    }
    return std::nullopt;
  }
  if (auto u = dyn_cast<UnaryOperator>(e)) {
    auto x = evalInt(u->getSubExpr());
    if (!x) return std::nullopt;
    switch (u->getOpcode()) {
      case UO_LNot: return !*x;
      case UO_Minus: return -*x;
      case UO_Plus: return *x;
      default: return std::nullopt;
    }
  }
  if (auto b = dyn_cast<BinaryOperator>(e)) {
    auto l = evalInt(b->getLHS());
    if (b->getOpcode() == BO_LAnd && l && !*l) return 0;
    if (b->getOpcode() == BO_LOr && l && *l) return 1;
    auto r = evalInt(b->getRHS());
    if (!l || !r) return std::nullopt;
    switch (b->getOpcode()) {
      case BO_EQ: return *l == *r;
      case BO_NE: return *l != *r;
      case BO_LT: return *l < *r;
      case BO_GT: return *l > *r;
      case BO_LE: return *l <= *r;
      case BO_GE: return *l >= *r;
      case BO_LAnd: return *l && *r;
      case BO_LOr: return *l || *r;
      case BO_Add: return *l + *r;
      case BO_Sub: return *l - *r;
      case BO_Mul: return *l * *r;
      default: return std::nullopt;
    }
  }
  return std::nullopt;
}

std::optional<bool> Analyzer::foldBool(const Expr* c) const {
  if (prog.opts.fold != Fold::Program) return std::nullopt;
  auto v = evalInt(c);
  if (!v) return std::nullopt;
  return *v != 0;
}

// Strips what wraps a null test without changing it: __builtin_expect (the
// likely/unlikely macros), `(test) != 0`, and an assignment `(p = f())`,
// which tests the variable it assigns.
const Expr* unwrapTest(const Expr* c, bool& inverted) {
  for (;;) {
    c = c->IgnoreParenImpCasts();
    if (auto call = dyn_cast<CallExpr>(c);
        call && call->getBuiltinCallee() == Builtin::BI__builtin_expect && call->getNumArgs() == 2) {
      c = call->getArg(0);
      continue;
    }
    if (auto b = dyn_cast<BinaryOperator>(c); b && b->isEqualityOp()) {
      const Expr* r = b->getRHS()->IgnoreParenImpCasts();
      auto lit = dyn_cast<IntegerLiteral>(r);
      if (lit && lit->getValue() == 0 && !b->getLHS()->IgnoreParenImpCasts()->getType()->isPointerType()) {
        if (b->getOpcode() == BO_EQ) inverted = !inverted;
        c = b->getLHS();
        continue;
      }
    }
    return c;
  }
}

const Expr* assignedVarExpr(const Expr* e) {
  if (auto b = dyn_cast<BinaryOperator>(e->IgnoreParenImpCasts()); b && b->getOpcode() == BO_Assign)
    return b->getLHS();
  return e;
}

const VarDecl* Analyzer::matchNullTest(const Expr* c, bool& trueMeansNonNull) const {
  bool inv = false;
  c = unwrapTest(c, inv);
  const VarDecl* v = matchNullTestInner(c, trueMeansNonNull);
  if (inv) trueMeansNonNull = !trueMeansNonNull;
  return v;
}

const VarDecl* Analyzer::matchNullTestInner(const Expr* c, bool& trueMeansNonNull) const {
  c = c->IgnoreParens();
  // A test written inside a macro body is defensive boilerplate
  // (`#define can_read(b) ((b) != NULL && ...)`), not the programmer saying
  // this pointer can be null here. Following its null edge floods real code
  // with reports, so only its non-null edge refines.
  testInMacro = c->getExprLoc().isMacroID();
  if (auto b = dyn_cast<BinaryOperator>(c); b && b->isEqualityOp()) testInMacro = b->getOperatorLoc().isMacroID();
  if (auto ic = dyn_cast<ImplicitCastExpr>(c); ic && ic->getCastKind() == CK_PointerToBoolean) {
    trueMeansNonNull = true;
    return resolveVar(assignedVarExpr(ic->getSubExpr()));
  }
  if (auto u = dyn_cast<UnaryOperator>(c); u && u->getOpcode() == UO_LNot) {
    const VarDecl* v = matchNullTest(u->getSubExpr(), trueMeansNonNull);
    if (!v && u->getSubExpr()->IgnoreParenImpCasts()->getType()->isPointerType()) {
      trueMeansNonNull = true;
      v = resolveVar(assignedVarExpr(u->getSubExpr()));
    }
    trueMeansNonNull = !trueMeansNonNull;
    return v;
  }
  if (auto b = dyn_cast<BinaryOperator>(c); b && b->isEqualityOp()) {
    const Expr* other = isNull(b->getRHS(), ctx) ? b->getLHS() : isNull(b->getLHS(), ctx) ? b->getRHS() : nullptr;
    if (!other) return nullptr;
    trueMeansNonNull = b->getOpcode() == BO_NE;
    return resolveVar(assignedVarExpr(other));
  }
  if (c->getType()->isPointerType()) {  // C: `if (p)` with no cast node
    trueMeansNonNull = true;
    return resolveVar(assignedVarExpr(c));
  }
  return nullptr;
}

State Analyzer::edge(const CFGBlock* b, unsigned succIndex, const State& in) const {
  if (b->succ_size() != 2) return in;
  const Expr* cond = b->getLastCondition();
  if (!cond) return in;
  bool takeTrue = succIndex == 0;
  if (auto f = foldBool(cond)) {
    if (*f != takeTrue) return State{};
    return in;
  }
  bool trueNonNull = false;
  const VarDecl* v = matchNullTest(cond, trueNonNull);
  if (!v) return in;
  State st = in;
  Val& val = st.vars[v];
  bool nonnull = trueNonNull == takeTrue;
  if (nonnull) {
    if (val.nb == NB_NULL) return State{};  // infeasible: known null
    val.nb = NB_NONNULL;
    for (int s : val.reallocOld) {  // realloc succeeded: the old block is gone
      uint8_t& bits = st.sites[s];
      bits = (bits & ~S_LIVE) | S_FREED;
    }
    val.reallocOld.clear();
  } else {
    if (val.nb == NB_NONNULL) return State{};  // infeasible: known non-null
    if (testInMacro) return st;
    val.nb = NB_NULL;
    // A null result means nothing was allocated on this path.
    for (int s : val.sites)
      if (sites[s].param < 0 && !heldElsewhere(s, v, st)) st.sites[s] = 0;
    val.sites.clear();
    val.reallocOld.clear();
  }
  return st;
}

// ---------------------------------------------------------------- driver

Summary Analyzer::run() {
  CFG::BuildOptions bo;
  bo.PruneTriviallyFalseEdges = prog.opts.fold != Fold::None;
  bo.AddImplicitDtors = false;
  bo.AddInitializers = true;
  bo.setAllAlwaysAdd();
  std::unique_ptr<CFG> cfg = CFG::buildCFG(fd, fd->getBody(), &ctx, bo);
  sum.params.assign(fd->getNumParams(), 0);
  if (!cfg) return sum;
  prepass();

  State entry;
  entry.reached = true;
  for (unsigned i = 0; i < fd->getNumParams(); ++i) {
    const ParmVarDecl* p = fd->getParamDecl(i);
    if (!tracked(p)) continue;
    int s = static_cast<int>(sites.size());
    sites.push_back({p->getLocation(), static_cast<int>(i), {}});
    entry.sites[s] = 0;
    entry.vars[p] = Val{NB_UNKNOWN, {s}, {}, false};
  }

  std::vector<State> in(cfg->getNumBlockIDs());
  const CFGBlock& entryBlock = cfg->getEntry();
  in[entryBlock.getBlockID()] = entry;

  auto runBlock = [&](const CFGBlock* b, State st) {
    for (const CFGElement& el : *b)
      if (auto cs = el.getAs<CFGStmt>()) transfer(cs->getStmt(), st);
    return st;
  };

  // Headers of loops that always run at least once keep the state arriving
  // from outside the loop apart; from that state the exit edge is infeasible.
  std::vector<State> first(cfg->getNumBlockIDs());
  std::vector<const Stmt*> headerInc(cfg->getNumBlockIDs(), nullptr);
  std::vector<char> onceOnly(cfg->getNumBlockIDs(), 0);
  for (const CFGBlock* b : *cfg)
    if (auto f = dyn_cast_or_null<ForStmt>(b->getTerminatorStmt()))
      if (entersOnce.count(f) && f->getInc()) {
        headerInc[b->getBlockID()] = f->getInc();
        onceOnly[b->getBlockID()] = runsOnce.count(f);
      }
  auto isBackEdge = [](const CFGBlock* from, const Stmt* inc) {
    for (const CFGElement& el : *from)
      if (auto cs = el.getAs<CFGStmt>(); cs && cs->getStmt() == inc) return true;
    return false;
  };

  std::deque<const CFGBlock*> work{&entryBlock};
  std::vector<char> queued(cfg->getNumBlockIDs(), 0);
  queued[entryBlock.getBlockID()] = 1;
  auto propagate = [&](const CFGBlock* b, const State& outSt, bool firstEntry) {
    if (b->hasNoReturnElement()) return;  // exit(), abort(): nothing flows on
    unsigned idx = 0;
    for (auto it = b->succ_begin(); it != b->succ_end(); ++it, ++idx) {
      const CFGBlock* s = it->getReachableBlock();
      if (!s || (firstEntry && idx == 1)) continue;
      if (!firstEntry && onceOnly[b->getBlockID()] && idx == 0) continue;
      State e = edge(b, idx, outSt);
      if (!e.reached) continue;
      unsigned sid = s->getBlockID();
      State& target = headerInc[sid] && !isBackEdge(b, headerInc[sid]) ? first[sid] : in[sid];
      State j = join(target, e);
      if (j != target) {
        target = std::move(j);
        if (!queued[sid]) {
          queued[sid] = 1;
          work.push_back(s);
        }
      }
    }
  };
  size_t steps = 0, limit = 200 * cfg->getNumBlockIDs() + 1000;
  while (!work.empty() && steps++ < limit) {
    const CFGBlock* b = work.front();
    work.pop_front();
    queued[b->getBlockID()] = 0;
    if (in[b->getBlockID()].reached) propagate(b, runBlock(b, in[b->getBlockID()]), false);
    if (first[b->getBlockID()].reached) propagate(b, runBlock(b, first[b->getBlockID()]), true);
  }

  // Reporting pass over the fixed point.
  reporting = true;
  for (const CFGBlock* b : *cfg) {
    if (in[b->getBlockID()].reached) runBlock(b, in[b->getBlockID()]);
    if (first[b->getBlockID()].reached) runBlock(b, first[b->getBlockID()]);
  }

  sum.retNull = sawNullReturn && !sawOtherReturn;
  const State& exit = in[cfg->getExit().getBlockID()];
  if (exit.reached) {
    for (auto& [s, bits] : exit.sites) {
      if (sites[s].param >= 0) {
        if (bits & S_FREED) sum.params[sites[s].param] |= P_FREE;
        if (bits & S_ESCAPED) sum.params[sites[s].param] |= P_ESCAPE;
      } else if (bits & S_LIVE) {
        report(401, sites[s].loc,
               bits == S_LIVE
                   ? "memory allocated here is never freed in '" + fd->getNameAsString() + "'"
                   : "memory allocated here is not freed on some path through '" + fd->getNameAsString() + "'",
               bits == S_LIVE);
      }
    }
  }
  return sum;
}

}  // namespace

Summary analyzeFunction(const FunctionDecl* fd, ASTContext& ctx, int tu, const Program& p,
                        std::vector<Finding>* out) {
  Analyzer a(fd, ctx, tu, p, out);
  return a.run();
}

}  // namespace cwescan
