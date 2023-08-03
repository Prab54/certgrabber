@echo off
setlocal enabledelayedexpansion

REM Set the path to the "dls" directory (assuming it is in the same directory as the batch script)
set "dls_dir=%~dp0dls"

REM Set the path to the "verifypfx" executable (assuming it is in the same directory as the batch script)
set "verifypfx_path=%~dp0verifypfx"

REM Set the path to the "common_roots.txt" file (assuming it is in the same directory as the batch script)
set "common_roots_file=%~dp0common_roots.txt"

REM Change directory to the "dls" directory
pushd "%dls_dir%"

REM Loop through each file in the directory
for %%F in (*) do (
    echo Running verifypfx on %%F ...
    "%verifypfx_path%" "%%F" "%common_roots_file%"
)

REM Restore the previous working directory
popd

echo All files processed.
pause
