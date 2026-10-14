"""Optional YARA matching against the original file bytes, never execution."""

from pathlib import Path

from .analysis_constants import YARA_SCAN_TIMEOUT_SECONDS
from .analysis_models import YaraScanResult


def scan_yara_rules(data: bytes, rules_path: str | Path) -> YaraScanResult:
    """Compile one source rules file and scan bytes; failures are not clean results."""
    path = Path(rules_path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"YARA rules file not found: {path}")

    # Keep the native dependency optional for every run without -y.
    try:
        import yara
    except ModuleNotFoundError as error:
        raise ValueError(
            "YARA scanning requires yara-python. Install it in this Python "
            "environment with: python -m pip install yara-python"
        ) from error
    except ImportError as error:
        raise ValueError(f"YARA native library could not be loaded: {error}") from error

    try:
        rules = yara.compile(filepath=str(path), includes=False)
        matches = rules.match(
            data=data,
            timeout=YARA_SCAN_TIMEOUT_SECONDS,
            console_callback=lambda message: None,
        )
    except yara.TimeoutError as error:
        raise ValueError(
            f"YARA scan timed out after {YARA_SCAN_TIMEOUT_SECONDS} seconds"
        ) from error
    except yara.Error as error:
        raise ValueError(
            f"YARA rules could not be compiled or scanned: {error}"
        ) from error

    return YaraScanResult(
        rules_file=str(path),
        matched_rules=sorted({match.rule for match in matches}),
    )
