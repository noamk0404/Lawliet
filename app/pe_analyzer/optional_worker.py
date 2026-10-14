"""Isolated entry point for optional parsers. Arguments always designate data."""

import json
import sys
from dataclasses import asdict

from .signatures import inspect_authenticode
from .analysis_models import StageResult
from .managed_metadata import inspect_dotnet


def main():
    engines = {"authenticode": inspect_authenticode, "dotnet": inspect_dotnet}
    try:
        result = engines[sys.argv[1]](sys.argv[2])
    except ImportError as error:
        result = StageResult("unavailable", notes=[str(error)])
    except Exception as error:
        result = StageResult("failed", notes=[f"{type(error).__name__}: {error}"])
    print(json.dumps(asdict(result), ensure_ascii=True))


if __name__ == "__main__":
    main()
