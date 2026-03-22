@echo off
REM Generate Yggdrasil NG configuration file if it does not already exist.
REM Called by the MSI installer as a custom action during first install.
REM
REM Usage: updateconfig.bat "path\to\yggdrasil.exe" "path\to\yggdrasil.toml"

set YGGDRASIL_EXE=%~1
set CONFIG_FILE=%~2

if exist "%CONFIG_FILE%" (
    echo Configuration already exists at %CONFIG_FILE%, skipping generation.
    exit /b 0
)

REM Ensure the config directory exists
for %%F in ("%CONFIG_FILE%") do mkdir "%%~dpF" 2>nul

"%YGGDRASIL_EXE%" --genconf="%CONFIG_FILE%" --no-replace
if %ERRORLEVEL% neq 0 (
    echo WARNING: Failed to generate configuration file.
    exit /b 0
)

echo Configuration generated at %CONFIG_FILE%.
