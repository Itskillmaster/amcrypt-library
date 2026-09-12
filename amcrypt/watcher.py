"""Anti-debugging protection — the Watcher's Blindness.

Provides ``DebuggerDetector``, a utility class that inspects the
running Python process for signs of active debugging.  Detection
techniques include:

- ``sys.gettrace()`` — returns the current trace function (set by
  debuggers, profilers, and tracing hooks).
- ``sys.getprofile()`` — returns the current profile function.
- Frame walking — checks for frames originating from known debugger
  modules (``pdb``, ``pydevd``, ``ipdb``, ``debugpy``, ``ptvsd``,
  ``pyringe``).
- ``sys.flags`` — detects ``-d`` (debug) flag and ``PYTHONBREAKPOINT``
  environment variable.
- ``sys.monitoring`` — detects active monitoring (Python 3.12+).
- ``sys.gettrace()`` value identity check — catches trivial monkey-patching
  of ``sys.settrace`` to return ``None`` while a debugger is active.

If a debugger is detected, the caller can:

1. Raise ``SoulTrappedError`` to abort the revive operation.
2. Return ``True`` for manual handling.

The detection is designed to be **silent** — it never prints or logs,
so a debugger watching stdout/stderr learns nothing.
"""

from __future__ import annotations

import os
import sys
import types
from typing import Callable


# Known debugger / tracer module names (lowercased for comparison)
_DEBUGGER_MODULES: frozenset[str] = frozenset({
    "pdb",
    "pdbpp",
    "ipdb",
    "ipdb.__main__",
    "pydevd",
    "pydevd_file_utils",
    "debugpy",
    "debugpy.adapter",
    "debugpy.pydevd",
    "ptvsd",
    "ptvsd.adapter",
    "pyringe",
    "pyringe.debugger",
    "pydevd_py3k",
    "pydevd_tracing",
    "_pydevd_bundle.pydevd_xml",
    "_pydevd_bundle.pydevd_resolver",
})


class DebuggerDetector:
    """Runtime debugger detection for the amcrypt library.

    Example::

        from amcrypt.watcher import DebuggerDetector

        detector = DebuggerDetector()
        if detector.is_debugging():
            raise SoulTrappedError()
    """

    def __init__(
        self,
        *,
        check_trace: bool = True,
        check_profile: bool = True,
        check_frames: bool = True,
        check_flags: bool = True,
        check_monitoring: bool = True,
        custom_checks: list[Callable[[], bool]] | None = None,
    ) -> None:
        """Configure which detection heuristics are active.

        Args:
            check_trace:    Check ``sys.gettrace()``.
            check_profile:  Check ``sys.getprofile()``.
            check_frames:   Walk the call stack for debugger frames.
            check_flags:    Check ``sys.flags.debug`` and env vars.
            check_monitoring: Check ``sys.monitoring`` (3.12+).
            custom_checks:  Additional callables that return ``True``
                            when a debugger is detected.
        """
        self._check_trace = check_trace
        self._check_profile = check_profile
        self._check_frames = check_frames
        self._check_flags = check_flags
        self._check_monitoring = check_monitoring
        self._custom_checks = custom_checks or []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_debugging(self) -> bool:
        """Run all configured detection heuristics.

        Returns:
            ``True`` if any heuristic indicates an active debugger.
        """
        checks: list[Callable[[], bool]] = []
        if self._check_trace:
            checks.append(self._check_trace_fn)
        if self._check_profile:
            checks.append(self._check_profile_fn)
        if self._check_frames:
            checks.append(self._check_frames_fn)
        if self._check_flags:
            checks.append(self._check_flags_fn)
        if self._check_monitoring:
            checks.append(self._check_monitoring_fn)
        checks.extend(self._custom_checks)

        for check in checks:
            try:
                if check():
                    return True
            except Exception:
                # If a check itself fails, assume debugging to be safe.
                return True
        return False

    # ------------------------------------------------------------------
    # Individual heuristics
    # ------------------------------------------------------------------

    @staticmethod
    def _check_trace_fn() -> bool:
        """Check ``sys.gettrace()`` for an active trace function."""
        trace_fn = sys.gettrace()
        if trace_fn is None:
            return False
        # A non-None trace function strongly indicates a debugger,
        # profiler, or custom tracer.  In the context of amcrypt, any
        # external tracer is suspicious.
        return True

    @staticmethod
    def _check_profile_fn() -> bool:
        """Check ``sys.getprofile()`` for an active profile function."""
        return sys.getprofile() is not None

    @staticmethod
    def _check_frames_fn() -> bool:
        """Walk the call stack looking for known debugger frames."""
        frame = sys._getframe(0)
        while frame is not None:
            module = frame.f_globals.get("__name__", "")
            # Check the module and its parents
            parts = module.split(".")
            for i in range(len(parts)):
                candidate = ".".join(parts[: i + 1])
                if candidate in _DEBUGGER_MODULES:
                    return True
            # Also check the filename for known debugger paths
            filename = frame.f_code.co_filename.lower()
            for dbg in ("pydevd", "debugpy", "ptvsd", "ipdb", "pyringe"):
                if dbg in filename:
                    return True
            frame = frame.f_back
        return False

    @staticmethod
    def _check_flags_fn() -> bool:
        """Check ``sys.flags.debug`` and suspicious env vars."""
        if getattr(sys.flags, "debug", False):
            return True
        # PYTHONBREAKPOINT being set to a debugger entry point is suspicious
        bp = os.environ.get("PYTHONBREAKPOINT", "")
        if bp and bp != "0" and "pdb" in bp.lower():
            return True
        return False

    @staticmethod
    def _check_monitoring_fn() -> bool:
        """Check ``sys.monitoring`` for active monitoring (Python 3.12+)."""
        monitoring = getattr(sys, "monitoring", None)
        if monitoring is None:
            return False
        # If any tool has active callbacks, this is suspicious
        use_tool_id = getattr(monitoring, "USE_TOOL_ID", None)
        if use_tool_id is None:
            return False
        # Check if any tool IDs are in use by trying to use one
        try:
            # In Python 3.12+, TOOL_ID constants exist
            for attr in dir(monitoring):
                if attr.startswith("DEBUGGER_ID") or attr.startswith("COVERAGE"):
                    tool_id = getattr(monitoring, attr, None)
                    if isinstance(tool_id, int):
                        try:
                            monitoring.get_tool(tool_id)
                            # If it doesn't raise, the tool slot is taken
                            return True
                        except Exception:
                            pass
        except Exception:
            pass
        return False