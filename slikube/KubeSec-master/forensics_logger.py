import logging
import time
from pathlib import Path

# Resolves to <repo_root>/forensics.log
LOG_PATH = Path(__file__).resolve().parents[2] / "forensics.log"


def safe_preview(value, max_len: int = 80) -> str:
    """Return a single-line, length-bounded representation safe for log files."""
    text = repr(value)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def get_forensics_logger(module_name: str) -> logging.Logger:
    """Return a module-scoped logger writing structured forensic events to forensics.log."""
    root_logger = logging.getLogger("slikube.forensics")
    if not root_logger.handlers:
        root_logger.setLevel(logging.INFO)
        root_logger.propagate = False

        handler = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
        formatter = logging.Formatter(
            fmt="%(asctime)sZ | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    return logging.getLogger(f"slikube.forensics.{module_name}")


def log_exception(logger: logging.Logger, func_name: str, exc: Exception, context: str) -> None:
    """Log an exception once at its origin frame without duplicating across recursive calls."""
    if not getattr(exc, "_forensics_logged", False):
        logger.error(
            "func=%s status=ERROR exc_type=%s exc_msg=%s %s",
            func_name,
            type(exc).__name__,
            safe_preview(str(exc), 120),
            context,
        )
        try:
            setattr(exc, "_forensics_logged", True)
        except Exception:
            pass