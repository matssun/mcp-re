#!/usr/bin/env python3
"""Stage-1 deterministic structural pre-scan — POLYGLOT and ROLE-AWARE.

NOT a vulnerability scanner. It asserts the *structural floor* a codebase must
clear before a full multi-agent security audit is worth its tokens, and it does
so for both Python and Rust, applying each check only where the file's ROLE makes
it meaningful. Language-aware is not enough: a Rust library legitimately defines
types its downstream consumers construct ("exists but not wired here" is not a
defect), whereas a Rust binary/proxy/demo that serves requests without a
verification path is the analogue of "FastAPI app with no auth middleware" — a
BLOCK.

Pipeline:
  classify language  ->  classify role  ->  language+role-specific checks  ->  one GO/NO-GO

Roles: library | binary | comproot | adapter | demo | test | generated | migration | script

Checks (role-sensitive):
  Rust, any production file:
    - todo!() / unimplemented!() on a production path                         BLOCK
    - unsafe (unless allowlisted)                                             BLOCK
    - panic/unwrap/expect/assert in a SECURITY-path file (unless allowlisted) BLOCK
  Rust binary / comproot / demo crate:
    - serving surface (TcpListener/serve/accept) with no verification call    BLOCK
    - a Noop/Null/InMemory security impl wired in the binary's comproot        BLOCK
  Rust library crate:
    - a security struct/impl never constructed in-repo                        advisory
  Python SERVICE (has a composition root or HTTP surface):
    - dead-wired orchestration class / not-in-comproot long-runner           BLOCK
    - Noop/Null impl wired in the composition root                            BLOCK
    - HTTP endpoints with no inbound auth wired                               BLOCK
    - NotImplementedError-only methods                                        warn
  Python LIBRARY (no comproot, no endpoints): dead-wiring downgraded to advisory.
  Tests / generated / migrations / scripts: excluded from production checks.

Deterministic, stdlib-only, zero LLM cost. HEURISTICS with false positives — a
NO-GO is decisive; a GO means "audit-ready", never "secure". Confirm every finding
from source before asserting it.

Allowlist (for the strict unsafe / panic / serve-without-verify blocks):
  - inline: a comment containing `prescan-allow: <kind>` on the offending line;
  - file:   --allow <json> mapping kind -> list of substrings (file path or symbol)
            to suppress, e.g. {"unsafe": ["sandbox_linux.rs"], "panic": []}.

Usage:
  python3 prescan.py <dir> [--json <out.json>] [--allow <allow.json>]
"""

import ast
import json
import os
import re
import sys

# ----------------------------------------------------------------------------- #
# Shared vocabulary                                                             #
# ----------------------------------------------------------------------------- #
# Roles excluded from the production structural floor (tooling / non-shipped).
NON_PROD_ROLES = {"test", "generated", "script", "migration"}

# Directories that never hold first-party source: build output, VCS metadata,
# and vendored/third-party dependency trees. Also skipped: any `.venv*` and any
# `bazel-*` convenience symlink (handled at the walk site).
VENDOR_DIRS = {
    "target", ".git", "__pycache__", "node_modules", "venv", "env",
    "site-packages", "dist-packages", "vendor", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".bazel", "bazel-out",
}

SECURITY_HINT = re.compile(
    r"(verify|sign|signature|auth|trust|resolver|replay|nonce|token|cert|tls|mtls"
    r"|crypt|key|policy|binding|admission|revoc|freshness|canonical|principal|tenant)",
    re.IGNORECASE,
)

# ---- Python (service composition-root model, from the original prescan) ------ #
PY_WIREABLE = re.compile(
    r"(Service|Handler|Persister|Consumer|ConsumerLoop|Loop|Publisher|Projector"
    r"|Bridge|Writer|Janitor|Coordinator|Dispatcher|Processor|Worker|Listener"
    r"|Subscriber|Producer|Sink|Pipeline|Gateway|Reconciler|Scheduler|Poller"
    r"|Verifier|Resolver|Emitter|Forwarder|Relay)$"
)
PY_NOOP = re.compile(r"^(Noop|NoOp|Null|Dummy|Fake|Stub|InMemory)")
PY_COMPROOT_NAMES = {
    "dependencies.py", "container_config.py", "container.py", "main.py",
    "app.py", "application.py", "wiring.py", "composition.py", "bootstrap.py",
    "startup.py", "server.py",
}
PY_COMPROOT_HINT = re.compile(
    r"(def lifespan|@asynccontextmanager|def build_container|build_container\s*\("
    r"|def create_app|create_app\s*\(|FastAPI\s*\(|def register_dependencies)")
PY_AUTH_MARKERS = re.compile(
    r"(add_middleware\([^)]*[Aa]uth|AuthenticationMiddleware|AuthMiddleware"
    r"|require_scope|require_auth|Depends\([^)]*[Aa]uth|HTTPBearer|OAuth2"
    r"|security_scopes|token_verifier|verify_bearer)")
PY_AUTH_FILE_HINT = re.compile(r"(middleware|auth|security)", re.IGNORECASE)
# Composition-root-wide inbound-auth / PEP wiring signals. Unlike PY_AUTH_MARKERS
# (which is gated behind a middleware/auth/security FILE-NAME hint), these are
# recognised anywhere in the comproot set — a service routinely wires its inbound
# PEP from `main.py`/`app.py`, not from a file literally named `*auth*`. Any one
# of these is sufficient evidence that inbound authentication is installed:
#   - a resource-server PEP install / object (install_resource_server, ResourceServer)
#   - a per-route scope guard (require_scope(...))
#   - an auth/verification/scope middleware added via add_middleware(...)
#   - a bearer/token validator install
PY_INBOUND_AUTH_WIRING = re.compile(
    r"(install_resource_server|\bResourceServer\b|\bresource_server\b"
    r"|require_scope\s*\(|require_auth\s*\("
    r"|add_middleware\s*\(\s*[A-Za-z_][\w.]*"
    r"(?:Auth|Authentication|Scope|Verification|Bearer|Token|Security|PEP)[\w.]*"
    r"|AuthenticationMiddleware|AuthMiddleware|VerificationMiddleware|ScopeMiddleware"
    r"|build_token_validator|token_validator|HTTPBearer|OAuth2|verify_bearer)")
PY_ENDPOINT_MARKERS = re.compile(
    r"(APIRouter|include_router|add_api_route|@router\.|@app\.(get|post|put|patch|delete)"
    r"|FastAPI\(|add_route|Starlette\()")
PY_LONG_RUNNER = re.compile(
    r"(Persister|Consumer|Loop|Janitor|Poller|Worker|Listener|Subscriber"
    r"|Scheduler|Reconciler)$")

# ---- Rust ------------------------------------------------------------------- #
RS_STUB = re.compile(r"\b(todo!|unimplemented!)\s*\(")
# `.expect(` requires a STRING-LITERAL argument to count as the panicking
# Result/Option::expect — this excludes parser-combinator / domain methods named
# `expect` that take a non-string (e.g. `self.expect(ch)?`).
RS_PANIC = re.compile(
    r"\.unwrap\(\)|\.expect\(\s*r?#*\"|\bpanic!\s*\(|\bunreachable!\s*\("
    r"|\bassert!\s*\(|\bassert_eq!\s*\(|\bassert_ne!\s*\(")
RS_UNSAFE = re.compile(r"\bunsafe\s*\{|\bunsafe\s+fn\b")
RS_SERVE = re.compile(r"\bTcpListener\b|\bfn\s+serve(?:_\w+)?\s*\(|\.accept\s*\(")
RS_VERIFY = re.compile(
    r"\bverify_request\b|\bverify_response\b|\bcheck_and_insert\b|\.resolve\s*\("
    r"|\bTransportBindingPolicy\b|\bbinding\.check\b|\.evaluate\s*\(")
RS_FN = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
RS_NOOP_CTOR = re.compile(
    r"\b((?:InMemory|Noop|NoOp|Null|Dummy|Fake|Stub|Mock|Static|Always)\w*)\s*(::|\{)")
RS_SEC_IMPL = re.compile(
    r"\bimpl\b[^\n{]*\b(TrustResolver|ResponseSigner|KeySource|TransportBindingProvider"
    r"|ReplayCache|AtomicReplayStore|PolicyEvaluator|Verifier|Authorizer)\b\s+for\s+"
    r"([A-Za-z_]\w*)")


# ----------------------------------------------------------------------------- #
# Classification                                                                #
# ----------------------------------------------------------------------------- #
def language(path):
    if path.endswith(".py"):
        return "python"
    if path.endswith(".rs"):
        return "rust"
    return None


def is_test_path(path):
    p = path.replace(os.sep, "/")
    base = os.path.basename(p)
    return ("/tests/" in p or "/test/" in p or base.startswith("test_")
            or base.endswith("_test.rs"))


def base_role(path):
    """Role determinable from the path alone (language-agnostic)."""
    p = path.replace(os.sep, "/")
    if is_test_path(p):
        return "test"
    if "/generated/" in p:
        return "generated"
    if "/migrations/" in p or "/migration/" in p:
        return "migration"
    if "/scripts/" in p or "/examples/" in p:
        return "script"
    if "/adapters/" in p or "/adapter/" in p:
        return "adapter"
    return None  # decided by language-specific logic


_RS_TEST_ATTR = re.compile(r"#\[cfg\((?:all\()?test\b[^\]]*\]")


def rust_prod_slice(src):
    """The production text of a .rs file: every test-gated ITEM blanked out.

    An item is test-gated when `#[cfg(test)]` or `#[cfg(all(test, ...))]` stands on
    it — the whole `mod tests` at the end, and equally an indented test-only helper
    inside an `impl`. Each is blanked from its attribute to the end of the item (its
    matching `}`, or its `;`), keeping newlines, so line numbers stay true and code
    AFTER a test helper is still scanned. Cutting at the first such attribute instead
    hid every production line below an indented helper; recognising only
    `#[cfg(test)]` scanned every `cfg(all(test, unix))` module as production.
    `cfg(not(test))` and `cfg(any(test, ..))` are not test-gated and stay.
    """
    out = list(src)
    for m in _RS_TEST_ATTR.finditer(src):
        brace = src.find("{", m.end())
        semi = src.find(";", m.end())
        if brace == -1 or (semi != -1 and semi < brace):
            stop = semi + 1 if semi != -1 else len(src)
        else:
            depth, i = 0, brace
            while i < len(src):
                if src[i] == "{":
                    depth += 1
                elif src[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            stop = min(i + 1, len(src))
        for k in range(m.start(), stop):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def find_crate_root(path):
    d = os.path.dirname(os.path.abspath(path))
    while True:
        if os.path.isfile(os.path.join(d, "Cargo.toml")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def crate_info(crate_root, cache):
    if crate_root in cache:
        return cache[crate_root]
    name = os.path.basename(crate_root)
    is_bin = os.path.isfile(os.path.join(crate_root, "src", "main.rs")) or \
        os.path.isdir(os.path.join(crate_root, "src", "bin"))
    try:
        with open(os.path.join(crate_root, "Cargo.toml"), encoding="utf-8") as fh:
            toml = fh.read()
        if "[[bin]]" in toml:
            is_bin = True
    except OSError:
        toml = ""
    is_demo = "demo" in name or "example" in name
    info = {"name": name, "is_bin": is_bin, "is_demo": is_demo,
            "has_serve": False, "has_verify": False, "serve_file": None}
    cache[crate_root] = info
    return info


def line_of(src, idx):
    return src.count("\n", 0, idx) + 1


def line_text(src, idx):
    start = src.rfind("\n", 0, idx) + 1
    end = src.find("\n", idx)
    return src[start: end if end != -1 else len(src)]


# `const _: () = { assert!(..) };` is a const-eval block: the assertions are checked by
# the compiler and cannot execute at runtime, so they are not a denial-of-service path.
# Masked (offsets preserved, so reported line numbers stay correct) rather than
# allowlisted, because no member of this category is ever a runtime panic.
RS_CONST_BLOCK = re.compile(r"\bconst\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*\(\s*\)\s*=\s*\{")


def mask_const_eval(src):
    out = list(src)
    for m in RS_CONST_BLOCK.finditer(src):
        depth, i = 0, m.end() - 1
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        for k in range(m.end(), min(i, len(src))):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def enclosing_fn(src, idx):
    last = None
    for m in RS_FN.finditer(src, 0, idx):
        last = m.group(1)
    return last or "<fn>"


# ----------------------------------------------------------------------------- #
# Allowlist                                                                     #
# ----------------------------------------------------------------------------- #
def load_allow(args):
    allow = {}
    if "--allow" in args:
        try:
            with open(args[args.index("--allow") + 1], encoding="utf-8") as fh:
                allow = json.load(fh)
        except (OSError, ValueError, IndexError):
            allow = {}
    return allow


def allowed(kind, rel, symbol, line, allow):
    # inline marker on the offending line
    if line and "prescan-allow" in line:
        if re.search(r"prescan-allow:\s*" + re.escape(kind), line) or \
                "prescan-allow: all" in line:
            return True
    for needle in allow.get(kind, []):
        if needle and (needle in rel or needle == symbol):
            return True
    return False


# ----------------------------------------------------------------------------- #
# Python service analyzer (port of the original class/comproot prescan)         #
# ----------------------------------------------------------------------------- #
def py_class_is_abstract(node):
    for base in node.bases:
        name = base.id if isinstance(base, ast.Name) else (
            base.attr if isinstance(base, ast.Attribute) else "")
        if name in {"ABC", "ABCMeta", "Protocol"}:
            return True
    for kw in node.keywords:
        if kw.arg == "metaclass":
            return True
    for item in node.body:
        for deco in getattr(item, "decorator_list", []):
            dname = deco.id if isinstance(deco, ast.Name) else (
                deco.attr if isinstance(deco, ast.Attribute) else "")
            if dname == "abstractmethod":
                return True
    return False


def py_nie_methods(node):
    out = []
    for item in node.body:
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = [b for b in item.body if not isinstance(b, ast.Expr)
                or not isinstance(b.value, ast.Constant)]
        if len(body) == 1 and isinstance(body[0], ast.Raise):
            exc = body[0].exc
            nm = ""
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                nm = exc.func.id
            elif isinstance(exc, ast.Name):
                nm = exc.id
            if nm == "NotImplementedError":
                out.append(item.name)
    return out


def py_class_bases(node):
    """Names of a ClassDef's base classes (best-effort, dotted attr -> attr)."""
    out = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            out.add(base.id)
        elif isinstance(base, ast.Attribute):
            out.add(base.attr)
    return out


def _callee_name(call):
    """Resolve the simple callee name of an ast.Call (``Foo(...)`` -> ``Foo``,
    ``mod.Foo(...)`` -> ``Foo``)."""
    if not isinstance(call, ast.Call):
        return None
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


def _terminal_name(expr):
    """Terminal identifier of a name/attribute chain, for binding lookup.

    ``ingestion.persister`` -> ``persister``; ``checkpoint_scheduler`` ->
    ``checkpoint_scheduler``; ``a.b.c`` -> ``c``. Returns None for anything else.
    """
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    return None


def py_construction_bindings(tree, known_classes):
    """Map identifier -> set of known class names it is bound to a *construction*
    of, anywhere in this module. Captures the three indirection forms the wiring
    uses to hand a long-runner instance to the comproot:

      name = Cls(...)                         (local assignment)
      ...(field=Cls(...))                     (keyword: attr/param name -> Cls)
      return Wrapper(field=Cls(...))          (object attribute -> Cls)

    so a comproot ``create_task(obj.field.run())`` / ``wrapper(obj.field)`` can be
    resolved back to the long-runner class ``Cls`` even when the construction
    lives in a separate builder file.
    """
    bindings = {}

    def bind(identifier, cls):
        if identifier and cls in known_classes:
            bindings.setdefault(identifier, set()).add(cls)

    for node in ast.walk(tree):
        # `name = Cls(...)`  /  `name: T = Cls(...)`
        targets = []
        value = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        cls = _callee_name(value) if isinstance(value, ast.Call) else None
        if cls:
            for tgt in targets:
                bind(_terminal_name(tgt), cls)
        # keyword args binding a field/param name to a construction:
        #   Wrapper(persister=AuditStreamPersister(...))
        #   build(scheduler=CheckpointSealScheduler(...))
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg and isinstance(kw.value, ast.Call):
                    bind(kw.arg, _callee_name(kw.value))
    return bindings


def py_alias_bindings(tree):
    """Map identifier -> terminal name of its RHS for simple aliasing assigns:
        checkpoint_scheduler = checkpoint_seal_components.scheduler   (-> scheduler)
        p = ingestion.persister                                       (-> persister)
    Lets a comproot ``create_task(checkpoint_scheduler.run())`` resolve through the
    alias to the binder name (``scheduler``) and on to its long-runner class."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = _terminal_name(node.targets[0])
            rhs = _terminal_name(node.value)
            if tgt and rhs and tgt != rhs:
                aliases[tgt] = rhs
    return aliases


def _create_task_driven_exprs(tree):
    """Yield the expression each ``asyncio.create_task(...)`` (or bare
    ``create_task(...)``) drives, plus, for a wrapper-coroutine form, the wrapper
    callee name and its first positional arg.

    Yields tuples ``(driven_expr, wrapper_name, wrapper_first_arg)`` where:
      - ``create_task(X.run())``      -> (X, None, None)
      - ``create_task(wrap(inst,..))``-> (None, "wrap", inst)
      - ``create_task(Cls(...).run())``-> (Cls(...)-call, None, None)
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _callee_name(node) != "create_task":
            continue
        if not node.args:
            continue
        inner = node.args[0]
        if not isinstance(inner, ast.Call):
            yield (inner, None, None)
            continue
        fn = inner.func
        # create_task(X.run()) / create_task(X.start()) — driven instance is X.
        if isinstance(fn, ast.Attribute) and fn.attr in {"run", "start",
                                                          "serve", "run_forever",
                                                          "main", "loop"}:
            yield (fn.value, None, None)
        else:
            # create_task(wrapper(instance, ...)) — wrapper coroutine form.
            wname = _callee_name(inner)
            first = inner.args[0] if inner.args else None
            yield (None, wname, first)


def py_lifecycle_driven_names(tree, wrapper_first_param_is_instance):
    """Set of terminal identifiers that this comproot module *drives* as a
    long-running task. Combines:
      - the instance behind every ``create_task(...)``;
      - any ``create_task(wrapper(inst, ...))`` whose ``wrapper`` is a function
        defined here (or anywhere) that takes the instance as its first param;
      - ``await X.stop()`` calls (lifecycle stop is start-symmetric evidence).
    A construction inside the create_task (``create_task(Cls().run())``) yields
    the class name directly.
    """
    driven_names = set()
    driven_classes = set()
    for driven, wname, warg in _create_task_driven_exprs(tree):
        if driven is not None:
            if isinstance(driven, ast.Call):
                cls = _callee_name(driven)
                if cls:
                    driven_classes.add(cls)
            else:
                nm = _terminal_name(driven)
                if nm:
                    driven_names.add(nm)
        elif warg is not None:
            # Wrapper coroutine: treat its first arg as the driven instance when
            # the wrapper is recognised as an instance-driving wrapper, OR
            # conservatively whenever the wrapper is a plain coroutine call (the
            # arg is still the thing being run on a cadence).
            if wname in wrapper_first_param_is_instance or wname is not None:
                nm = _terminal_name(warg)
                if nm:
                    driven_names.add(nm)
    # `await X.stop()` — lifecycle teardown of a long-runner (start-symmetric).
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in {"stop", "shutdown"}:
            nm = _terminal_name(node.func.value)
            if nm:
                driven_names.add(nm)
    return driven_names, driven_classes


def py_wrapper_funcs(tree):
    """Names of module-level (async) functions whose FIRST param is a plausible
    long-runner instance — used to confirm a ``create_task(wrapper(inst,...))``
    form actually hands an instance to a driving wrapper."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args.posonlyargs + node.args.args
            if args:
                out.add(node.name)
    return out


def _comproot_construction_guard(tree, cls_name):
    """True iff every textual *construction* of ``cls_name`` in this module sits
    under a documented production-refusal guard — i.e. the same function body
    that constructs it also ``raise``s (the fail-closed `is_production()` path
    that refuses the Noop). Such a Noop is an explicitly-refused fallback, NOT
    the production wiring, so it must not BLOCK."""
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        constructs = any(
            isinstance(c, ast.Call) and _callee_name(c) == cls_name
            for c in ast.walk(fn))
        if not constructs:
            continue
        raises = any(isinstance(r, ast.Raise) for r in ast.walk(fn))
        if not raises:
            return False  # an unguarded construction exists -> genuinely wired
    return True


def python_pass(py_files, root, add, allow):
    """py_files: list of (path, src, role). Mirrors the original prescan; gated so
    composition-root/dead-wiring checks only BLOCK when the tree is a service."""
    class_defs, comproot_files = {}, []
    has_endpoints = has_auth = False
    parsed = []
    for path, src, role in py_files:
        try:
            tree = ast.parse(src, filename=path)
        except (SyntaxError, ValueError):
            continue
        parsed.append((path, src, role, tree))
        if role in NON_PROD_ROLES:
            continue
        base = os.path.basename(path)
        if base in PY_COMPROOT_NAMES or PY_COMPROOT_HINT.search(src):
            comproot_files.append(path)
        if PY_ENDPOINT_MARKERS.search(src):
            has_endpoints = True
        if PY_AUTH_FILE_HINT.search(base) and PY_AUTH_MARKERS.search(src):
            has_auth = True
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_defs.setdefault(node.name, {
                    "file": path, "abstract": py_class_is_abstract(node),
                    "noop": bool(PY_NOOP.match(node.name)),
                    "bases": py_class_bases(node),
                    "nie": py_nie_methods(node)})

    # The tree is a SERVICE iff it has a comproot or an HTTP surface. For a pure
    # library, dead-wiring is advisory (consumers wire it), mirroring Rust libs.
    is_service = bool(comproot_files) or has_endpoints
    wiring_sev = "block" if is_service else "warn"

    # Interfaces (I-prefixed base classes) -> the CONCRETE non-Noop impls that are
    # actually CONSTRUCTED in the comproot set. If a real impl of an interface is
    # constructed+wired in the comproot, a Noop of the same interface is not the
    # production wiring (it is the refused fallback).
    real_impl_ifaces_in_comproot = set()

    # ── Cross-file construction bindings + comproot lifecycle driving ──
    # The instance a comproot drives is frequently reached through a builder's
    # returned-object attribute (``ingestion.persister``), so the long-runner's
    # class name never appears in the comproot. Bind identifier -> class across
    # ALL prod files, then resolve the names the comproot create_task / stop()
    # actually drive back to long-runner classes.
    long_runner_classes = {n for n, i in class_defs.items()
                           if PY_LONG_RUNNER.search(n) and not i["abstract"]}
    construction_bindings = {}   # identifier -> {class, ...} (all prod files)
    comproot_driven = []         # (driven_names, driven_classes, aliases) per comproot

    for path, src, role, tree in parsed:
        if role in NON_PROD_ROLES:
            continue
        for ident, classes in py_construction_bindings(
                tree, long_runner_classes).items():
            construction_bindings.setdefault(ident, set()).update(classes)
        if path in comproot_files:
            wrappers = py_wrapper_funcs(tree)
            driven_names, driven_classes = py_lifecycle_driven_names(
                tree, wrappers)
            comproot_driven.append(
                (driven_names, driven_classes, py_alias_bindings(tree)))
            # real (non-Noop) impls of an interface constructed in the comproot.
            for node in ast.walk(tree):
                cls = _callee_name(node) if isinstance(node, ast.Call) else None
                if cls and cls in class_defs and not class_defs[cls]["noop"]:
                    for b in class_defs[cls]["bases"]:
                        if b.startswith("I") and len(b) > 1 and b[1:2].isupper():
                            real_impl_ifaces_in_comproot.add(b)

    # Resolve driven names to long-runner classes AFTER all bindings + aliases are
    # collected (a builder file may be parsed after its comproot). A driven name
    # resolves directly, or through one alias hop (``checkpoint_scheduler`` ->
    # ``scheduler`` -> ``CheckpointSealScheduler``).
    started_long_runners = set()
    for driven_names, driven_classes, aliases in comproot_driven:
        started_long_runners.update(driven_classes & long_runner_classes)
        for nm in driven_names:
            for candidate in (nm, aliases.get(nm)):
                if candidate:
                    started_long_runners.update(
                        construction_bindings.get(candidate, set())
                        & long_runner_classes)

    prod_refs = {n: set() for n in class_defs}
    comproot_refs = {n: 0 for n in class_defs}
    noop_in_comproot = []
    for path, src, role, tree in parsed:
        if role in NON_PROD_ROLES:
            continue
        in_comproot = path in comproot_files
        names = set()
        # A Noop is only "wired as prod impl" when it is CONSTRUCTED (a Call to
        # the class), not merely imported / annotated / used as a `| None = None`
        # default. Collect constructed class names separately from referenced.
        constructed_here = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            if isinstance(node, ast.Call):
                cls = _callee_name(node)
                if cls in class_defs:
                    constructed_here.add(cls)
        for name in names:
            if name not in class_defs:
                continue
            if path != class_defs[name]["file"]:
                prod_refs[name].add(path)
            if in_comproot:
                comproot_refs[name] += 1
        if in_comproot:
            for name in constructed_here:
                if not class_defs[name]["noop"]:
                    continue
                # Guarded by a documented production-refusal (raise) — the Noop
                # is the explicitly-refused fallback, not the prod wiring.
                if _comproot_construction_guard(tree, name):
                    continue
                # A real impl of the same interface is constructed in the
                # comproot — the Noop is not the production substitution.
                ifaces = {b for b in class_defs[name]["bases"]
                          if b.startswith("I") and len(b) > 1 and b[1:2].isupper()}
                if ifaces & real_impl_ifaces_in_comproot:
                    continue
                noop_in_comproot.append((name, os.path.relpath(path, root)))

    for name, info in sorted(class_defs.items()):
        if info["abstract"] or info["noop"]:
            continue
        if (PY_WIREABLE.search(name) and not prod_refs[name]
                and not allowed("dead-wired",
                                os.path.relpath(info["file"], root), name, None, allow)):
            add("dead-wired", wiring_sev, name, info["file"], None,
                "Orchestration class is never referenced in any production file "
                "outside its own definition." + ("" if is_service else
                " (advisory: this tree is a library; consumers may wire it.)"))
        elif (PY_WIREABLE.search(name) and comproot_refs[name] == 0
              and PY_LONG_RUNNER.search(name)
              and name not in started_long_runners):
            add("not-in-comproot", wiring_sev, name, info["file"], None,
                "Long-running class referenced in production but never in the "
                "composition root / lifespan — likely constructed but never started.")
        if info["nie"]:
            add("stub-method", "warn", name, info["file"], None,
                "Concrete class has NotImplementedError-only method(s): "
                + ", ".join(info["nie"]))

    for name, rel in sorted(set(noop_in_comproot)):
        add("noop-in-comproot", "block", name, os.path.join(root, rel), None,
            "Noop/Null/InMemory implementation instantiated and wired as the "
            "production implementation in the composition root, with no real "
            "alternative of the same interface and no documented prod-refusal "
            "guard — a real implementation is likely being silently substituted.")

    # Composition-root-wide inbound-auth wiring: a PEP install / scope guard /
    # auth-verification-scope middleware anywhere in the comproot set counts,
    # regardless of the file's name (services wire their inbound PEP from
    # main.py/app.py, not from a file literally named `*auth*`).
    if not has_auth:
        for path, src, role, tree in parsed:
            if role in NON_PROD_ROLES or path not in comproot_files:
                continue
            if PY_INBOUND_AUTH_WIRING.search(src):
                has_auth = True
                break

    if has_endpoints and not has_auth:
        add("no-inbound-auth", "block", "<http surface>", None, None,
            "Service exposes HTTP endpoints but no inbound authentication is wired "
            "in any middleware or composition-root file.")
    elif has_endpoints:
        add("auth-manual-verify", "warn", "<http surface>", None, None,
            "Auth wiring present, but Stage 1 cannot tell it actually enforces. "
            "Stage 2 must confirm endpoints are genuinely gated.")


# ----------------------------------------------------------------------------- #
# Rust analyzer (role-aware)                                                     #
# ----------------------------------------------------------------------------- #
def rust_pass(rs_files, root, add, allow, crates):
    """rs_files: list of (path, prod_src, role, crate_root). Per-file structural
    checks now; per-crate serve/verify aggregated after."""
    lib_impls = {}          # symbol -> file for security impls
    prod_ctor_refs = set()  # symbols constructed somewhere in prod

    for path, src, role, crate_root in rs_files:
        rel = os.path.relpath(path, root)
        sec_file = bool(SECURITY_HINT.search(rel))
        info = crates.get(crate_root)
        if info:
            if RS_SERVE.search(src):
                info["has_serve"] = True
                info["serve_file"] = info["serve_file"] or rel
            if RS_VERIFY.search(src):
                info["has_verify"] = True

        # BLOCK: unimplemented contract on a production path.
        for m in RS_STUB.finditer(src):
            add("stub-body", "block", enclosing_fn(src, m.start()), path,
                line_of(src, m.start()),
                f"Production code contains `{m.group(1)}` — an unimplemented contract "
                "on a shipped path; a consumer reaching it panics.")

        # BLOCK (unless allowlisted): unsafe in production.
        for m in RS_UNSAFE.finditer(src):
            sym, lt = enclosing_fn(src, m.start()), line_text(src, m.start())
            if allowed("unsafe", rel, sym, lt, allow):
                continue
            add("unsafe-block", "block", sym, path, line_of(src, m.start()),
                "`unsafe` in production without an allowlist entry — requires an "
                "explicit memory-safety justification (`// prescan-allow: unsafe`).")

        # BLOCK (unless allowlisted): panic-on-input in a SECURITY-path file.
        if sec_file:
            scan = mask_const_eval(src)
            panics = [m for m in RS_PANIC.finditer(scan)
                      if not allowed("panic", rel, enclosing_fn(src, m.start()),
                                     line_text(src, m.start()), allow)]
            if panics:
                add("panic-in-security-path", "block", os.path.basename(path), path,
                    line_of(src, panics[0].start()),
                    f"{len(panics)} non-allowlisted panicking call(s) "
                    "(unwrap/expect/panic!/assert!) in a security-relevant production "
                    "file. A panic on untrusted input is a denial-of-service; convert "
                    "to a fail-closed error or allowlist a proven-infallible call.")

        # Security impls + constructors (library advisory / binary noop-wiring).
        for m in RS_SEC_IMPL.finditer(src):
            lib_impls.setdefault(m.group(2), path)
        for m in re.finditer(r"\b([A-Z][A-Za-z0-9_]*)\s*(::new\b|\{)", src):
            prod_ctor_refs.add(m.group(1))

        # BLOCK: a Noop/Null/InMemory SECURITY impl wired in a binary's comproot.
        if role in ("binary", "comproot") and info and (info["is_bin"] or info["is_demo"]):
            for m in RS_NOOP_CTOR.finditer(src):
                sym, lt = m.group(1), line_text(src, m.start())
                if not SECURITY_HINT.search(sym):
                    continue
                if allowed("noop-in-binary", rel, sym, lt, allow):
                    continue
                add("noop-in-binary", "block", sym, path, line_of(src, m.start()),
                    "A reference/no-op security implementation is wired in a binary's "
                    "composition root — confirm it is not standing in for a real "
                    "verifier/resolver/policy on a production request path.")

    # advisory: a security impl in a LIBRARY crate constructed nowhere in-repo.
    for sym, path in sorted(lib_impls.items()):
        info = crates.get(find_crate_root(path))
        if info and (info["is_bin"] or info["is_demo"]):
            continue
        if sym not in prod_ctor_refs:
            add("unconstructed-impl", "warn", sym, path, None,
                "A security trait impl is never constructed in this repo. In a library "
                "this is usually fine (downstream consumers construct it); confirm it "
                "is not dead code or a forgotten wiring.")

    # BLOCK: a serving binary/demo crate with no verification call anywhere in it.
    for crate_root, info in sorted(crates.items()):
        if not info["has_serve"] or not (info["is_bin"] or info["is_demo"]):
            continue
        if allowed("serve-without-verify", info["name"], info["name"], "", allow):
            continue
        loc = os.path.join(root, info["serve_file"] or os.path.relpath(crate_root, root))
        if not info["has_verify"]:
            add("serve-without-verify", "block", info["name"], loc, None,
                "A serving binary/demo accepts connections (TcpListener/serve/accept) "
                "but no verification/authorization/binding call was found in the crate "
                "— the Rust analogue of an HTTP app with no auth. If this is an "
                "intentionally-unverified inner server behind the proxy, allowlist it "
                "(serve-without-verify).")
        else:
            add("verify-manual-verify", "warn", info["name"], loc, None,
                "Serving surface and a verification call both exist, but Stage 1 "
                "cannot prove the verify gate is on every request path and "
                "unbypassable. Stage 2 must confirm.")


# ----------------------------------------------------------------------------- #
# Role resolution + driver                                                       #
# ----------------------------------------------------------------------------- #
def rust_role(path, crate_root, crates):
    pr = base_role(path)
    if pr:
        return pr
    # ONLY the binary entry points are composition roots. A crate that is lib+bin
    # (e.g. mcps-proxy) still has mostly LIBRARY files — they must NOT inherit the
    # binary's comproot checks, or every reference impl defined in the crate would
    # falsely look "wired in the comproot".
    base = os.path.basename(path)
    p = path.replace(os.sep, "/")
    if base == "main.rs" or "/src/bin/" in p:
        return "comproot"
    # Production library code lives under `<crate>/src/`. Anything else (generators,
    # benches, examples, fixture builders under conformance/, build.rs) is tooling,
    # not a shipped path — exclude it from the production floor.
    if "/src/" not in p or base == "build.rs":
        return "script"
    return "library"


def python_role(path, src):
    pr = base_role(path)
    if pr:
        return pr
    base = os.path.basename(path)
    if base in PY_COMPROOT_NAMES or PY_COMPROOT_HINT.search(src):
        return "comproot"
    if "__name__" in src and "__main__" in src:
        return "binary"
    return "library"


def main():
    args = sys.argv[1:]
    pos = [a for a in args if not a.startswith("--")]
    if not pos:
        print("usage: prescan.py <dir> [--json out.json] [--allow allow.json]",
              file=sys.stderr)
        return 2
    root = os.path.abspath(pos[0])
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    json_out = args[args.index("--json") + 1] if "--json" in args else None
    allow = load_allow(args)

    findings = []

    def add(kind, severity, symbol, file, line, detail):
        findings.append({
            "kind": kind, "severity": severity, "symbol": symbol,
            "file": os.path.relpath(file, root) if file else None,
            "line": line, "detail": detail})

    py_files, rs_files = [], []
    crates = {}
    roles_seen = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in VENDOR_DIRS and not d.startswith(".venv")
                       and not d.startswith("bazel-")]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            lang = language(path)
            if lang is None:
                continue
            try:
                with open(path, encoding="utf-8") as fh:
                    src = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            if lang == "python":
                role = python_role(path, src)
                roles_seen[role] = roles_seen.get(role, 0) + 1
                py_files.append((path, src, role))
            else:
                crate_root = find_crate_root(path)
                if crate_root:
                    crate_info(crate_root, crates)
                role = rust_role(path, crate_root, crates)
                roles_seen[role] = roles_seen.get(role, 0) + 1
                if role in NON_PROD_ROLES:
                    continue
                rs_files.append((path, rust_prod_slice(src), role, crate_root))

    if py_files:
        python_pass(py_files, root, add, allow)
    if rs_files:
        rust_pass(rs_files, root, add, allow, crates)

    blocks = [f for f in findings if f["severity"] == "block"]
    warns = [f for f in findings if f["severity"] == "warn"]
    verdict = "NO-GO" if blocks else "GO"

    languages = (["python"] if py_files else []) + (["rust"] if rs_files else [])
    result = {
        "service_src": root,
        "languages": languages,
        "verdict": verdict,
        "counts": {
            "block": len(blocks), "warn": len(warns),
            "py_files": len(py_files), "rs_files": len(rs_files),
            "crates": len(crates),
        },
        "roles": roles_seen,
        "crates": {info["name"]: {"is_bin": info["is_bin"], "is_demo": info["is_demo"],
                                  "has_serve": info["has_serve"],
                                  "has_verify": info["has_verify"]}
                   for info in crates.values()},
        "findings": findings,
    }

    if json_out:
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)

    langs = "+".join(languages) or "none"
    print(f"\n=== STRUCTURAL PRE-SCAN [{langs}]: {os.path.basename(root)} ===",
          file=sys.stderr)
    print(f"verdict: {verdict}   ({len(blocks)} blocking, {len(warns)} warnings; "
          f"{len(py_files)} py, {len(rs_files)} rs, {len(crates)} crates)",
          file=sys.stderr)
    for info in sorted(crates.values(), key=lambda i: i["name"]):
        if info["has_serve"]:
            kind = "bin" if info["is_bin"] else "demo" if info["is_demo"] else "lib"
            print(f"  crate {info['name']:24} [{kind}] serve=True "
                  f"verify={info['has_verify']}", file=sys.stderr)
    for f in blocks + warns:
        tag = "BLOCK" if f["severity"] == "block" else "warn "
        loc = f"{f['file']}:{f['line']}" if f["file"] and f["line"] else (f["file"] or "-")
        print(f"  [{tag}] {f['kind']:22} {f['symbol']}  ({loc})\n           {f['detail']}",
              file=sys.stderr)
    if verdict == "NO-GO":
        print("\nNO-GO: fix the blocking structural defects before spending the "
              "full-scan token budget.", file=sys.stderr)
    else:
        print("\nGO: structural floor clear — proceed to Stage 2 (pre-run review). "
              "(GO means audit-ready, NOT secure.)", file=sys.stderr)

    print(json.dumps(result))
    return 1 if verdict == "NO-GO" else 0


if __name__ == "__main__":
    sys.exit(main())
