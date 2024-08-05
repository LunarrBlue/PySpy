@echo off
echo Only run this script if you have already ran build.bat an would like to rebuild the EXE.
pause

echo Deleting past bulid files.
del script.spec
del script.py
rd /s /q build
rd /s /q dist

echo Finished deleting build files. Please run build.bat to build again.
pause
exit /b 0