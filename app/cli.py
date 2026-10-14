import argparse
import sys
from pathlib import Path
from typing import Sequence

VERSION = "1.0.0-beta.1"
BANNER = r"""
 _        ___        __  _      ___  _____ _____
| |      / \ \      / / | |    |_ _|| ____|_   _|
| |     / _ \ \ /\ / /  | |     | | |  _|   | |
| |___ / ___ \ V  V /   | |___  | | | |___  | |
|_____/_/   \_\_/\_/    |_____||___||_____| |_|
""".strip("\n")


def format_banner() -> str:
    """Return the shared colored introduction for help and analysis runs."""
    from reporting.terminal_report import color_text, supports_color

    color_enabled = supports_color(sys.stdout)
    banner = color_text(BANNER, "96", color_enabled)
    title = color_text("LAWLIET // PE STATIC ANALYZER", "95", color_enabled)
    tagline = color_text(
        "Static Windows PE analysis -- the examined file is never executed.",
        "92",
        color_enabled,
    )
    return f"{banner}\n{title}\n\n{tagline}\n"


class BrandedArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        return f"{format_banner()}\n{super().format_help()}"


def _positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "string length must be a positive integer"
        ) from error
    if number <= 0:
        raise argparse.ArgumentTypeError("string length must be a positive integer")
    return number


def build_parser() -> argparse.ArgumentParser:

    parser = BrandedArgumentParser(
        prog="lawliet",
        description=(
            "Inspect PE structure, imports, indicators, mitigations, and suspicious "
            "evidence."
        ),
        epilog=(
            "examples:\n"
            "  %(prog)s sample.exe\n"
            "  %(prog)s sample.exe -e reports/analysis.json\n"
            "  %(prog)s sample.exe -s 8\n"
            "  %(prog)s sample.exe -y rules.yar"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file",
        type=Path,
        metavar="FILE",
        help="path to the EXE, DLL, or other PE file to examine",
    )
    parser.add_argument(
        "-e",
        "--export",
        type=Path,
        metavar="JSON_PATH",
        help="export the examination as JSON instead of printing it",
    )
    parser.add_argument(
        "-s",
        "--strings",
        type=_positive_integer,
        metavar="MIN_LENGTH",
        help="print extracted strings with at least this many characters (analysis always scans strings)",
    )
    parser.add_argument(
        "-y",
        "--yara",
        type=Path,
        metavar="RULES_FILE",
        help="test the file against a YARA source rules file (off by default)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print all analysis details, including non-suspicious results (console only)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
        help="show the version number and exit",
    )
    parser.add_argument(
        "--authenticode",
        action="store_true",
        help="verify embedded signatures with optional LIEF and offline Windows trust",
    )
    parser.add_argument(
        "--dotnet",
        action="store_true",
        help="inspect managed metadata with optional dnfile",
    )
    for name, executable in (("die", "diec"), ("capa", "capa"), ("floss", "floss")):
        parser.add_argument(
            f"--{name}",
            nargs="?",
            const=executable,
            metavar="ENGINE_PATH",
            help=f"enable optional {name}; optionally supply its executable path",
        )
    parser.add_argument(
        "--capa-rules", type=Path, metavar="RULES_PATH",
        help="capa rule file or directory (needed when capa has no embedded rules)",
    )
    parser.add_argument(
        "--capa-signatures", type=Path, metavar="SIGNATURES_PATH",
        help="capa library-signature directory (needed by some pip installs)",
    )
    parser.add_argument(
        "--tool-timeout",
        type=_positive_integer,
        default=60,
        metavar="SECONDS",
        help="per-engine timeout, 1–600 seconds (default 60)",
    )
    parser.add_argument(
        "--entropy-window",
        type=_positive_integer,
        default=4096,
        metavar="BYTES",
        help="local entropy window, 512–65536 bytes (default 4096)",
    )
    return parser


def run_cli(arguments: Sequence[str] | None = None) -> int:

    parser = build_parser()
    supplied_arguments = list(arguments) if arguments is not None else sys.argv[1:]
    if not supplied_arguments:
        parser.print_help()
        return 0

    options = parser.parse_args(supplied_arguments)
    print(format_banner(), flush=True)

    try:
        from reporting.terminal_report import ConsoleReport
        from pe_analyzer import analyze_pe_binary
        from pe_analyzer.analysis_models import AnalysisOptions
        from pefile import PEFormatError
        from reporting import save_dict_to_json
        from reporting.terminal_report import terminal_report
    except ModuleNotFoundError as error:
        missing_package = error.name or "required dependency"
        parser.exit(
            1,
            f"error: Python package '{missing_package}' is not installed.\n"
            "Activate the project environment first:\n"
            "  call ..\\.venv\\Scripts\\activate.bat\n"
            "Then run this command again with 'python cli.py'.\n",
        )

    try:
        console = ConsoleReport()
        result = analyze_pe_binary(
            options.file,
            minimum_string_length=options.strings,
            yara_rules_path=options.yara,
            progress=console.progress,
            analysis_options=AnalysisOptions(
                authenticode=options.authenticode,
                dotnet=options.dotnet,
                die=options.die,
                capa=options.capa,
                capa_rules=str(options.capa_rules) if options.capa_rules else None,
                capa_signatures=str(options.capa_signatures) if options.capa_signatures else None,
                floss=options.floss,
                tool_timeout=options.tool_timeout,
                entropy_window=options.entropy_window,
            ),
        )
        if options.export is None:
            report = terminal_report(result, verbose=options.verbose)
            console.render(report)
        else:
            output_path = options.export.expanduser()
            save_dict_to_json(
                result,
                filename=output_path.name,
                output_dir=output_path.parent,
            )
    except (OSError, ValueError, PEFormatError) as error:
        parser.exit(1, f"error: {error}\n")

    return 0


def main() -> None:
    """Run the command-line interface."""
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
