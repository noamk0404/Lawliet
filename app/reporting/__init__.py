"""Public JSON-reporting API, loaded only when a report function is requested.

Keeping this package initializer light lets the CLI render help and version
information without importing the PE analyzer or its optional dependencies.
"""

from typing import Any

__all__ = ["binary_analysis_to_dict", "save_dict_to_json"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from . import report_serialization

        return getattr(report_serialization, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
