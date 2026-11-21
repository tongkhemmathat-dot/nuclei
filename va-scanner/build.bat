@echo off
rem Rebuild dist\VA-Scanner\VA-Scanner.exe. Needs: pip install pyinstaller sslyze
cd /d "%~dp0"
python nuclei_gui.py --test || exit /b 1
python -m PyInstaller --onefile --noconsole --name VA-Scanner --collect-all sslyze --collect-all nassl ^
  --distpath dist\VA-Scanner --workpath "%TEMP%\va-build" --specpath "%TEMP%\va-build" -y nuclei_gui.py || exit /b 1
rem sslyze reads its CA trust stores from pem_files\ next to a frozen exe
for /f "delims=" %%p in ('python -c "import sslyze,os;print(os.path.join(os.path.dirname(sslyze.__file__),'plugins','certificate_info','trust_stores','pem_files'))"') do xcopy /e /i /y /q "%%p" dist\VA-Scanner\pem_files >nul
echo Built dist\VA-Scanner. Zip that folder WITHOUT reports\ to share.
