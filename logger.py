"""
Logging configuration for SOC Multi-Agent System.

Exports:
    get_logger(name)         - standard python Logger, namespaced under soc_agent.<name>
    get_step_logger(step)    - small helper with .start/.info/.warn/.error/.done that
                               emits greppable, structured, key=value log lines
    log_context(trace_id)    - context manager (contextvars-backed) that stamps every
                               subsequent log line with trace=<id> for the duration of
                               the block; works across asyncio.create_task boundaries

Formatting is switched via env LOG_FORMAT / settings.log_format:
    "text" (default) - human readable single-line records
    "json"           - one JSON object per line, ready for Splunk/ELK

Only the standard library is used.
"""
from __future__ import annotations

import contextvars
import json
import logging
import logging.handlers
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

# -- context ---------------------------------------------------------------

_trace_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("soc_trace_id", default="")
_step_var: contextvars.ContextVar[str] = contextvars.ContextVar("soc_step", default="")


def current_trace_id() -> str:
    return _trace_id_var.get()


def current_step() -> str:
    return _step_var.get()


@contextmanager
def log_context(trace_id: str = "", step: str | None = None) -> Iterator[None]:
    """Bind trace_id (and optionally step) onto every log line inside this block.

    Works across asyncio.create_task because contextvars are copied into new tasks.
    """
    t_token = _trace_id_var.set(trace_id or _trace_id_var.get())
    s_token = _step_var.set(step) if step is not None else None
    try:
        yield
    finally:
        _trace_id_var.reset(t_token)
        if s_token is not None:
            _step_var.reset(s_token)


# -- formatting ------------------------------------------------------------

def _read_env_settings() -> tuple[str, str]:
    """Read LOG_LEVEL and LOG_FORMAT from env. settings.py mirrors these but importing
    the settings module here would cause a circular import (settings uses logger)."""
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    fmt = os.getenv("LOG_FORMAT", "text").lower()
    if fmt not in ("text", "json"):
        fmt = "text"
    return level, fmt


class _TextFormatter(logging.Formatter):
    """Human formatter: ``TS [LEVEL] [logger] message | trace=... k=v ...``.

    step_logger already embeds the step marker inside the message itself so we
    don't repeat it here.
    """

    default_time_format = "%Y-%m-%d %H:%M:%S"

    def format(self, record: logging.LogRecord) -> str:
        ts = self.formatTime(record, self.default_time_format)
        base = f"{ts} [{record.levelname}] [{record.name}] {record.getMessage()}"
        trace = _trace_id_var.get()
        extras: list[str] = []
        if trace:
            extras.append(f"trace={trace}")
        fields = getattr(record, "soc_fields", None)
        if fields:
            for k, v in fields.items():
                extras.append(f"{k}={_render_value(v)}")
        if extras:
            base = f"{base} | {' '.join(extras)}"
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"
        return base


class _JsonFormatter(logging.Formatter):
    default_time_format = "%Y-%m-%dT%H:%M:%S"

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, self.default_time_format),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "trace_id": _trace_id_var.get() or None,
            "step": getattr(record, "soc_step", None) or _step_var.get() or None,
            "fields": getattr(record, "soc_fields", {}) or {},
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def _render_value(v: Any) -> str:
    if isinstance(v, (str, int, float, bool)) or v is None:
        s = str(v)
    else:
        try:
            s = json.dumps(v, default=str, ensure_ascii=False)
        except Exception:
            s = repr(v)
    # keep single-line: strip newlines and cap length
    s = s.replace("\n", " ").replace("\r", " ")
    if len(s) > 500:
        s = s[:497] + "..."
    if " " in s and not (s.startswith("{") or s.startswith("[")):
        s = f'"{s}"'
    return s


# -- root logger set up once -----------------------------------------------

_LEVEL, _FORMAT = _read_env_settings()

_root = logging.getLogger("soc_agent")
_root.setLevel(getattr(logging, _LEVEL, logging.INFO))
_root.propagate = False

if not _root.handlers:
    _fmt = _JsonFormatter() if _FORMAT == "json" else _TextFormatter()
    _level = getattr(logging, _LEVEL, logging.INFO)

    _stream = logging.StreamHandler()
    _stream.setLevel(_level)
    _stream.setFormatter(_fmt)
    _root.addHandler(_stream)

    _log_dir = Path(os.getenv("LOG_DIR", "logs"))
    try:
        _log_dir.mkdir(parents=True, exist_ok=True)
        _file = logging.handlers.RotatingFileHandler(
            _log_dir / "soc_agent.log",
            maxBytes=10 * 1024 * 1024,   # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        _file.setLevel(_level)
        _file.setFormatter(_fmt)
        _root.addHandler(_file)
    except OSError:
        # Filesystem unwritable — carry on with stream-only logging.
        pass


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a namespaced logger under soc_agent."""
    if name:
        return logging.getLogger(f"soc_agent.{name}")
    return _root


# -- step logger -----------------------------------------------------------

class StepLogger:
    """Structured per-step logger.

    Every method emits a single line prefixed by a directional marker so a full
    workflow trace is easy to eyeball or grep::

        >>> [stage2] START ...   step start
            [stage2] ...          step info
        <<< [stage2] DONE ...    step done
    """

    __slots__ = ("step", "_log")

    def __init__(self, step: str) -> None:
        self.step = step
        self._log = logging.getLogger(f"soc_agent.{step}")

    # -- helpers
    def _emit(self, level: int, marker: str, msg: str, exc: BaseException | None = None,
              **fields: Any) -> None:
        text = f"{marker} [{self.step}] {msg}" if marker else f"[{self.step}] {msg}"
        extra = {"soc_fields": fields, "soc_step": self.step}
        if exc is not None:
            exc_info = (type(exc), exc, exc.__traceback__)
            self._log.log(level, text, extra=extra, exc_info=exc_info)
        else:
            self._log.log(level, text, extra=extra)

    # -- api
    def start(self, msg: str = "", **fields: Any) -> None:
        self._emit(logging.INFO, ">>>", f"START {msg}".rstrip(), **fields)

    def info(self, msg: str, **fields: Any) -> None:
        self._emit(logging.INFO, "   ", msg, **fields)

    def warn(self, msg: str, **fields: Any) -> None:
        self._emit(logging.WARNING, "   ", msg, **fields)

    warning = warn

    def error(self, msg: str, exc: BaseException | None = None, **fields: Any) -> None:
        self._emit(logging.ERROR, "   ", msg, exc=exc, **fields)

    def done(self, msg: str = "", **fields: Any) -> None:
        self._emit(logging.INFO, "<<<", f"DONE {msg}".rstrip(), **fields)

    def debug(self, msg: str, **fields: Any) -> None:
        self._emit(logging.DEBUG, "   ", msg, **fields)


def get_step_logger(step: str) -> StepLogger:
    """Return a StepLogger scoped to a named pipeline step (e.g. 'stage0', 'stage2')."""
    return StepLogger(step)


__all__ = [
    "get_logger",
    "get_step_logger",
    "log_context",
    "current_trace_id",
    "current_step",
    "StepLogger",
]
