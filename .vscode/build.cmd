@echo off
setlocal
rem Windows VS Code entry point: cmd.exe is the shell, not the Python launcher.
rem Prefer the Python 3 launcher, then fall back to python.exe on PATH.
rem The build helper lives with VS Code settings and needs no scripts directory.
cd /d "%~dp0.." || exit /b 1
where py.exe >nul 2>nul
if not errorlevel 1 goto :launcher
where python.exe >nul 2>nul
if not errorlevel 1 goto :python
echo ERROR: Python 3.10+ was not found on PATH.
echo Install Python 3.10 or later, then restart VS Code. Check "py -3 --version" or "python --version".
exit /b 1
:launcher
py -3 "%~dp0build.py" %*
exit /b %errorlevel%
:python
python "%~dp0build.py" %*
exit /b %errorlevel%
