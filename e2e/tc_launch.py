"""Run a Tracecat worker module with its readiness file under $DECA_E2E_RUN_DIR (test harness only).

Tracecat 1.5.2 hard-codes /var/run/tracecat/worker-ready, which needs root outside a container.
The source tree is not modified; in the container image the default path is used as-is.
"""

import os
import runpy
import sys
from pathlib import Path

import tracecat.executor.startup as startup
import tracecat.temporal.worker_lifecycle as lifecycle

ready = Path(os.environ["DECA_E2E_RUN_DIR"]) / f"{sys.argv[1].rsplit('.', 1)[-1]}-ready"
lifecycle.WORKER_READY_FILE = ready
startup.WORKER_READY_FILE = ready
lifecycle.worker_readiness.__wrapped__.__defaults__ = (ready,)

module = sys.argv[1]
sys.argv = [module]
runpy.run_module(module, run_name="__main__", alter_sys=True)
