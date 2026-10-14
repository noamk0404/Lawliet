@echo off
setlocal

set "CLI_DIRECTORY=%~dp0"
set "VENV_PYTHON=%CLI_DIRECTORY%..\.venv\Scripts\python.exe"

if not exist "%VENV_PYTHON%" (
    echo Error: the project virtual environment was not found.
    echo Expected: "%VENV_PYTHON%"
    echo.
    echo Create it from the Lawliet directory with:
    echo   py -m venv .venv
    echo   .venv\Scripts\python.exe -m pip install pefile
    echo.
    pause
    exit /b 1
)

"%VENV_PYTHON%" "%CLI_DIRECTORY%cli.py" %*
set "CLI_EXIT_CODE=%ERRORLEVEL%"

if "%~1"=="" (
    echo.
    pause
)

exit /b %CLI_EXIT_CODE%
