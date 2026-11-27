@echo off
rem Rebuild dist\VA-Scanner\VA-Scanner.exe (+ _internal\). Needs: pip install pyinstaller sslyze sv-ttk
rem onedir, not onefile: onefile's unpack-to-Temp bootloader trips Defender's Bearfoos.A!ml heuristic.
cd /d "%~dp0"
python nuclei_gui.py --test || exit /b 1
set B=%TEMP%\va-build
rem build in Temp: PyInstaller -y wipes its output dir, and dist\VA-Scanner holds nuclei.exe, templates and reports
python -m PyInstaller --onedir --noconsole --name VA-Scanner --collect-all sslyze --collect-all nassl --collect-data sv_ttk ^
  --distpath "%B%\dist" --workpath "%B%" --specpath "%B%" -y nuclei_gui.py || exit /b 1
if exist dist\VA-Scanner\_internal rmdir /s /q dist\VA-Scanner\_internal
xcopy /e /i /y /q "%B%\dist\VA-Scanner" dist\VA-Scanner >nul || exit /b 1
rem sslyze reads its CA trust stores from pem_files\ next to a frozen exe
for /f "delims=" %%p in ('python -c "import sslyze,os;print(os.path.join(os.path.dirname(sslyze.__file__),'plugins','certificate_info','trust_stores','pem_files'))"') do xcopy /e /i /y /q "%%p" dist\VA-Scanner\pem_files >nul
echo Built dist\VA-Scanner. Zip that folder WITHOUT reports\ to share.
