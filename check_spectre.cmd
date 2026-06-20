@echo off
REM Check Spectre libs for VS 18 (Insiders) toolchains.
set VSROOT=C:\Program Files\Microsoft Visual Studio\18\Community

echo === Toolchains present under %VSROOT% ===
dir "%VSROOT%\VC\Tools\MSVC" /b 2>nul

echo.
echo === Spectre lib check ===
for /d %%I in ("%VSROOT%\VC\Tools\MSVC\*") do (
    echo --- %%~nxI ---
    if exist "%%I\lib\x64\spectre\libcmt.lib" (
        echo   [OK] lib\x64\spectre\libcmt.lib
    ) else if exist "%%I\lib\spectre\x64\libcmt.lib" (
        echo   [OK] lib\spectre\x64\libcmt.lib
    ) else (
        echo   [MISSING] libcmt.lib not in either spectre subfolder
    )
)

echo.
echo === Full lib folder layout (first toolchain) ===
for /d %%I in ("%VSROOT%\VC\Tools\MSVC\*") do (
    echo Looking under %%I\lib
    dir "%%I\lib" /b 2>nul
    echo --- spectre subdirs ---
    dir /s /b "%%I\lib\spectre" 2>nul | findstr /i "libcmt.lib"
    dir /s /b "%%I\lib\x64" 2>nul | findstr /i "spectre"
    goto :done
)
:done
echo.
pause
