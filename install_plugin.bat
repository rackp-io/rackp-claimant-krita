@echo off
REM Installs the RACKP Claimant add-on into Krita's pykrita directory.

SET PYKRITA=%APPDATA%\krita\pykrita
SET SRC=%~dp0

echo Install target: %PYKRITA%

IF NOT EXIST "%PYKRITA%" mkdir "%PYKRITA%"

REM Copy the .desktop service file
copy /Y "%SRC%rackp_claimant.desktop" "%PYKRITA%\rackp_claimant.desktop"

REM Copy the plugin package (robocopy, overwrite)
robocopy "%SRC%rackp_claimant" "%PYKRITA%\rackp_claimant" /E /IS /IT

echo.
echo Installation complete. Please restart Krita.
echo Then enable it: Settings - Python Plugin Manager - RACKP Claimant
pause
