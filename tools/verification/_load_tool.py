# SPDX-License-Identifier: Apache-2.0
"""Import an extensionless tool script as a module, so its tests can address it.

The lane entry points — `verify`, `verify-tests`, `check-generated`, the gates — are
executable scripts with no `.py`, so a test cannot `import` them. Every suite that wants
one therefore built a loader by hand, and seven copies of the same four lines is seven
copies of the same latent bug: none of them registered the module in `sys.modules`, which
is not merely untidy. Python resolves a class's defining namespace through
`sys.modules[cls.__module__]`, so the first `@dataclass` in any loaded tool raises
`AttributeError: 'NoneType' object has no attribute '__dict__'` — at import, in the suite,
about a change that was correct.

That is exactly what happened: a dataclass added to `verify` turned an unrelated, untouched
suite red. One loader, used everywhere.
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType

HERE = Path(__file__).resolve().parent


def load_tool(script: str, module_name: str | None = None) -> ModuleType:
    """The tool named by `script` (relative to `tools/verification/`), as a module.

    Registered under `module_name` before execution, because a module that is not in
    `sys.modules` while its own body runs cannot resolve its own namespace.
    """
    name = module_name or script.replace("-", "_")
    loader = SourceFileLoader(name, str(HERE / script))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module
