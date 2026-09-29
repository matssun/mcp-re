#!/usr/bin/env python3
"""Regression tests for the Stage-1 structural pre-scan (``prescan.py``).

Pins the three production-wiring recognitions that previously mis-fired on real
composition roots, in BOTH directions:

  not-in-comproot   legitimate indirect start (builder attr / wrapper coroutine
                    / aliased instance driven by create_task or stop())  -> GO
                    long-runner constructed but never started             -> NO-GO
  noop-in-comproot  Noop merely imported / annotated / `| None = None` /
                    guarded by a prod-refusal raise / real impl present    -> GO
                    Noop instantiated unconditionally as the prod impl     -> NO-GO
  no-inbound-auth   PEP / require_scope / auth-verification-scope middleware
                    wired anywhere in the comproot set                     -> GO
                    HTTP surface with no auth anywhere                     -> NO-GO

Stdlib only. Run: ``python3 test_prescan.py``.
"""

import importlib.util
import os
import tempfile
import unittest


# ----------------------------------------------------------------------------- #
# Load prescan.py as a module (no package install / PYTHONPATH).                 #
# ----------------------------------------------------------------------------- #
_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "prescan_under_test", os.path.join(_HERE, "prescan.py"))
prescan = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(prescan)


def run_python_pass(files):
    """files: {relpath: source}. Returns the list of findings dicts that
    ``python_pass`` would emit for a synthetic tree rooted at a temp dir."""
    with tempfile.TemporaryDirectory() as root:
        py_files = []
        for rel, src in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(src)
            role = prescan.python_role(path, src)
            py_files.append((path, src, role))

        findings = []

        def add(kind, severity, symbol, file, line, detail):
            findings.append({"kind": kind, "severity": severity,
                             "symbol": symbol, "line": line})

        prescan.python_pass(py_files, root, add, {})
        return findings


def kinds(findings, severity=None):
    return {f["kind"] for f in findings
            if severity is None or f["severity"] == severity}


def symbols(findings, kind):
    return {f["symbol"] for f in findings if f["kind"] == kind}


# A minimal HTTP surface so the synthetic tree is classified as a SERVICE
# (so wiring checks BLOCK rather than downgrade to advisory warn).
_HTTP_SURFACE = (
    "from fastapi import FastAPI\n"
    "def create_app():\n"
    "    application = FastAPI()\n"
    "    application.include_router(router)\n"
    "    return application\n"
)


# ----------------------------------------------------------------------------- #
# Pattern 1 — not-in-comproot (long-runner start detection)                      #
# ----------------------------------------------------------------------------- #
class NotInComprootTests(unittest.TestCase):

    def test_GO_started_via_builder_attribute(self):
        """create_task(ingestion.persister.run()) where the persister is built in
        a separate builder file and reached via a returned-object attribute."""
        files = {
            "services/stream_persister.py":
                "class AuditStreamPersister:\n"
                "    async def run(self): ...\n",
            "stream_ingestion_config.py":
                "from demo_service.services.stream_persister import "
                "AuditStreamPersister\n"
                "def build_stream_ingestion():\n"
                "    persister = AuditStreamPersister()\n"
                "    return StreamIngestion(persister=persister)\n",
            "dependencies.py":
                "import asyncio\n"
                "from contextlib import asynccontextmanager\n"
                "@asynccontextmanager\n"
                "async def lifespan(app):\n"
                "    ingestion = build_stream_ingestion()\n"
                "    persister_task = asyncio.create_task(ingestion.persister.run())\n"
                "    yield\n",
            "main.py": _HTTP_SURFACE,
        }
        f = run_python_pass(files)
        self.assertNotIn("AuditStreamPersister", symbols(f, "not-in-comproot"))

    def test_GO_started_via_wrapper_coroutine(self):
        """create_task(_run_janitor_periodically(ingestion.janitor, ...)) — driven
        through a wrapper coroutine that takes the instance as its first arg."""
        files = {
            "services/stream_janitor.py":
                "class AuditStreamJanitor:\n"
                "    async def run_once(self): ...\n",
            "stream_ingestion_config.py":
                "from demo_service.services.stream_janitor import "
                "AuditStreamJanitor\n"
                "def build_stream_ingestion():\n"
                "    janitor = AuditStreamJanitor()\n"
                "    return StreamIngestion(janitor=janitor)\n",
            "dependencies.py":
                "import asyncio\n"
                "from contextlib import asynccontextmanager\n"
                "async def _run_janitor_periodically(janitor, interval):\n"
                "    while True:\n"
                "        await janitor.run_once()\n"
                "@asynccontextmanager\n"
                "async def lifespan(app):\n"
                "    ingestion = build_stream_ingestion()\n"
                "    janitor_task = asyncio.create_task(\n"
                "        _run_janitor_periodically(ingestion.janitor, 5))\n"
                "    yield\n",
            "main.py": _HTTP_SURFACE,
        }
        f = run_python_pass(files)
        self.assertNotIn("AuditStreamJanitor", symbols(f, "not-in-comproot"))

    def test_GO_started_via_alias_and_stop(self):
        """checkpoint_scheduler = components.scheduler; create_task(
        checkpoint_scheduler.run()); await components.scheduler.stop()."""
        files = {
            "services/checkpoint/seal_scheduler.py":
                "class CheckpointSealScheduler:\n"
                "    async def run(self): ...\n"
                "    async def stop(self): ...\n",
            "checkpoint_config.py":
                "from demo_service.services.checkpoint.seal_scheduler "
                "import CheckpointSealScheduler\n"
                "def build_seal_components():\n"
                "    scheduler = CheckpointSealScheduler()\n"
                "    return Components(scheduler=scheduler)\n",
            "dependencies.py":
                "import asyncio\n"
                "from contextlib import asynccontextmanager\n"
                "@asynccontextmanager\n"
                "async def lifespan(app):\n"
                "    components = build_seal_components()\n"
                "    checkpoint_scheduler = components.scheduler\n"
                "    task = asyncio.create_task(checkpoint_scheduler.run())\n"
                "    yield\n"
                "    await components.scheduler.stop()\n",
            "main.py": _HTTP_SURFACE,
        }
        f = run_python_pass(files)
        self.assertNotIn("CheckpointSealScheduler",
                         symbols(f, "not-in-comproot"))

    def test_NOGO_constructed_but_never_started(self):
        """A long-runner constructed in a builder but never create_task'd / run /
        stopped anywhere — the genuine defect MUST still BLOCK."""
        files = {
            "services/drain_consumer.py":
                "class OrphanConsumer:\n"
                "    async def run(self): ...\n",
            "stream_ingestion_config.py":
                "from demo_service.services.drain_consumer import OrphanConsumer\n"
                "def build_stream_ingestion():\n"
                "    consumer = OrphanConsumer()\n"
                "    return StreamIngestion(consumer=consumer)\n",
            "dependencies.py":
                "from contextlib import asynccontextmanager\n"
                "@asynccontextmanager\n"
                "async def lifespan(app):\n"
                "    ingestion = build_stream_ingestion()\n"
                "    yield\n",
            "main.py": _HTTP_SURFACE,
        }
        f = run_python_pass(files)
        self.assertIn("OrphanConsumer", symbols(f, "not-in-comproot"))
        self.assertEqual(
            "block",
            next(x["severity"] for x in f
                 if x["kind"] == "not-in-comproot"
                 and x["symbol"] == "OrphanConsumer"))


# ----------------------------------------------------------------------------- #
# Pattern 2 — noop-in-comproot (Noop wired as prod impl)                         #
# ----------------------------------------------------------------------------- #
class NoopInComprootTests(unittest.TestCase):

    _NOOP_DEF = (
        "class NoopRegistryMutationPublisher(IRegistryMutationPublisher):\n"
        "    async def publish(self, event): ...\n"
    )
    _REAL_DEF = (
        "class AuditRegistryMutationPublisher(IRegistryMutationPublisher):\n"
        "    async def publish(self, event): ...\n"
    )

    def test_GO_noop_only_imported_and_annotated(self):
        """The Noop is imported, used in a type annotation and a `| None = None`
        default — but never instantiated as the prod impl."""
        files = {
            "publishers.py": self._NOOP_DEF + self._REAL_DEF,
            "container_config.py":
                "from demo_service.publishers import "
                "NoopRegistryMutationPublisher\n"
                "def build_container(\n"
                "    registry_mutation_publisher: "
                "NoopRegistryMutationPublisher | None = None,\n"
                "):\n"
                "    container = Container()\n"
                "    return container\n",
            "dependencies.py":
                "from demo_service.publishers import "
                "AuditRegistryMutationPublisher\n"
                "from contextlib import asynccontextmanager\n"
                "@asynccontextmanager\n"
                "async def lifespan(app):\n"
                "    publisher = AuditRegistryMutationPublisher()\n"
                "    container = build_container(\n"
                "        registry_mutation_publisher=publisher)\n"
                "    yield\n",
            "main.py": _HTTP_SURFACE,
        }
        f = run_python_pass(files)
        self.assertNotIn("NoopRegistryMutationPublisher",
                         symbols(f, "noop-in-comproot"))

    def test_GO_noop_guarded_by_prod_refusal(self):
        """The Noop is constructed only on the non-prod branch of a function that
        raises in production — a documented fail-closed fallback, not the wiring."""
        files = {
            "publishers.py": self._NOOP_DEF,
            "container_config.py":
                "from demo_service.publishers import "
                "NoopRegistryMutationPublisher\n"
                "def build_container():\n"
                "    return Container()\n"
                "def _resolve_publisher(settings, provided):\n"
                "    if provided is not None:\n"
                "        return provided\n"
                "    if settings.is_production():\n"
                "        raise RuntimeError('refusing to start without a real "
                "publisher')\n"
                "    return NoopRegistryMutationPublisher()\n",
            "main.py": _HTTP_SURFACE,
        }
        f = run_python_pass(files)
        self.assertNotIn("NoopRegistryMutationPublisher",
                         symbols(f, "noop-in-comproot"))

    def test_GO_real_impl_of_same_interface_in_comproot(self):
        """Even an unguarded Noop construction is not the prod wiring when a real
        impl of the SAME interface is constructed in the comproot."""
        files = {
            "publishers.py": self._NOOP_DEF + self._REAL_DEF,
            "container_config.py":
                "from demo_service.publishers import (\n"
                "    NoopRegistryMutationPublisher,\n"
                "    AuditRegistryMutationPublisher,\n"
                ")\n"
                "def build_container():\n"
                "    real = AuditRegistryMutationPublisher()\n"
                "    fallback = NoopRegistryMutationPublisher()\n"
                "    return Container()\n",
            "main.py": _HTTP_SURFACE,
        }
        f = run_python_pass(files)
        self.assertNotIn("NoopRegistryMutationPublisher",
                         symbols(f, "noop-in-comproot"))

    def test_NOGO_noop_instantiated_as_prod_impl(self):
        """The Noop is instantiated unconditionally and registered as THE impl,
        with no real alternative and no prod-refusal guard — MUST still BLOCK."""
        files = {
            "publishers.py": self._NOOP_DEF,
            "container_config.py":
                "from demo_service.publishers import "
                "NoopRegistryMutationPublisher\n"
                "def build_container():\n"
                "    container = Container()\n"
                "    container.register_instance(\n"
                "        IRegistryMutationPublisher,\n"
                "        NoopRegistryMutationPublisher(),\n"
                "    )\n"
                "    return container\n",
            "main.py": _HTTP_SURFACE,
        }
        f = run_python_pass(files)
        self.assertIn("NoopRegistryMutationPublisher",
                      symbols(f, "noop-in-comproot"))
        self.assertEqual(
            "block",
            next(x["severity"] for x in f
                 if x["kind"] == "noop-in-comproot"))


# ----------------------------------------------------------------------------- #
# Pattern 3 — no-inbound-auth (inbound PEP / auth wiring)                        #
# ----------------------------------------------------------------------------- #
class NoInboundAuthTests(unittest.TestCase):

    def test_GO_resource_server_pep_and_require_scope(self):
        """main.py installs a resource-server PEP + per-route require_scope +
        auth/verification/scope middleware — recognised despite main.py not being
        named *auth*."""
        files = {
            "main.py":
                "from fastapi import FastAPI, Depends\n"
                "from server_stack import VerificationMiddleware\n"
                "from di_fastapi import ScopeMiddleware\n"
                "from demo_service.resource_server_config import "
                "install_resource_server\n"
                "def create_application():\n"
                "    application = FastAPI()\n"
                "    application.add_middleware(ScopeMiddleware)\n"
                "    application.add_middleware(VerificationMiddleware)\n"
                "    resource_server = install_resource_server(application)\n"
                "    application.include_router(\n"
                "        router,\n"
                "        dependencies=[Depends("
                "resource_server.require_scope('audit:read'))],\n"
                "    )\n"
                "    return application\n",
        }
        f = run_python_pass(files)
        self.assertNotIn("no-inbound-auth", kinds(f, "block"))
        self.assertIn("auth-manual-verify", kinds(f, "warn"))

    def test_NOGO_http_surface_with_no_auth_anywhere(self):
        """An HTTP app with endpoints and zero PEP/auth-middleware/require_scope
        anywhere — the genuine defect MUST still BLOCK."""
        files = {
            "main.py":
                "from fastapi import FastAPI\n"
                "def create_application():\n"
                "    application = FastAPI()\n"
                "    application.include_router(router)\n"
                "    application.add_middleware(GzipMiddleware)\n"
                "    return application\n",
        }
        f = run_python_pass(files)
        self.assertIn("no-inbound-auth", kinds(f, "block"))


# ----------------------------------------------------------------------------- #
# Rust — const-eval assertions are not runtime panics                            #
# ----------------------------------------------------------------------------- #
class ConstEvalMaskTests(unittest.TestCase):
    """A `const _: () = { assert!(..) };` block is checked by the compiler and cannot
    execute, so it is not a denial-of-service path. Everything else must still block."""

    def panics(self, src):
        scan = prescan.mask_const_eval(src)
        return [m.group(0) for m in prescan.RS_PANIC.finditer(scan)]

    def test_const_eval_assertions_are_not_panics(self):
        src = (
            "const MAX: i64 = 900;\n"
            "pub const DEFAULT_TTL_SECS: i64 = 300;\n"
            "const _: () = {\n"
            "    assert!(DEFAULT_TTL_SECS > 0 && DEFAULT_TTL_SECS <= MAX);\n"
            "    assert!(DEFAULT_OVERLAP_SECS > 0);\n"
            "};\n"
        )
        self.assertEqual(self.panics(src), [])

    def test_the_control_a_runtime_panic_beside_one_still_blocks(self):
        """Negative control: masking must not swallow the rest of the file."""
        src = (
            "const _: () = { assert!(TTL > 0); };\n"
            "fn decide(input: &str) -> Key {\n"
            "    parse(input).unwrap()\n"
            "}\n"
        )
        self.assertEqual(self.panics(src), [".unwrap()"])

    def test_line_numbers_survive_masking(self):
        """Offsets are preserved, so a later finding still reports its true line."""
        src = "const _: () = {\n    assert!(A > 0);\n};\n\nlet k = load().unwrap();\n"
        scan = prescan.mask_const_eval(src)
        self.assertEqual(len(scan), len(src))
        m = prescan.RS_PANIC.search(scan)
        self.assertEqual(prescan.line_of(scan, m.start()), 5)

    def test_a_nested_brace_does_not_end_the_mask_early(self):
        src = (
            "const _: () = {\n"
            "    let t = Thing { a: 1 };\n"
            "    assert!(t.a > 0);\n"
            "};\n"
        )
        self.assertEqual(self.panics(src), [])


class RustTestRegionTest(unittest.TestCase):
    """The production slice blanks every test-gated item and keeps everything else."""

    SRC = (
        "pub fn a() -> u8 { 1 }\n"
        "impl S {\n"
        "    #[cfg(test)]\n"
        "    fn helper() { x.expect(\"test helper\"); }\n"
        "    pub fn after(&self) { y.unwrap(); }\n"
        "}\n"
        "#[cfg(not(test))]\n"
        "fn prod_only() { z.unwrap(); }\n"
        "#[cfg(all(test, unix))]\n"
        "mod tests { #[test] fn t() { w.unwrap(); } }\n"
    )

    def test_test_items_are_blanked_and_production_after_them_is_kept(self):
        prod = prescan.rust_prod_slice(self.SRC)
        self.assertNotIn("test helper", prod)
        self.assertNotIn("w.unwrap", prod)
        self.assertIn("y.unwrap", prod)        # production AFTER an indented helper
        self.assertIn("z.unwrap", prod)        # cfg(not(test)) is production
        self.assertEqual(prod.count("\n"), self.SRC.count("\n"))  # lines preserved


if __name__ == "__main__":
    unittest.main(verbosity=2)
