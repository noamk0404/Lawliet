```text
 _        ___        __  _      ___  _____ _____
| |      / \ \      / / | |    |_ _|| ____|_   _|
| |     / _ \ \ /\ / /  | |     | | |  _|   | |
| |___ / ___ \ V  V /   | |___  | | | |___  | |
|_____/_/   \_\_/\_/    |_____||___||_____| |_|
```

# Lawliet

Lawliet is a command-line tool for inspecting **Windows Portable Executable (PE) files only**, such as `.exe` and `.dll` files. It examines file structure, imported functions, strings, and embedded content to highlight suspicious indicators and produce a risk score. The file being analyzed is never executed.

## Setup

Install Python 3 with the Windows `py` launcher, download or clone this repository, and open a terminal in the `Lawliet` directory. Run:

```console
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Usage

Analyze a file and view its report in the terminal:

```console
.\app\run_lawliet.bat "C:\path\to\sample.exe"
```

Add an option to the same command:

- `-e reports\analysis.json` — save the report as JSON instead of printing it.
- `-s 8` — display extracted strings of at least eight characters.
- `-v` — show all analysis details.
- `--help` — list all available options.

## Beta

Lawliet is a **beta version** under active development. Features and report formats may change, and bugs, false positives, or missed indicators are possible. Findings and risk scores support investigation; they do not confirm malware or guarantee that a file is safe.
