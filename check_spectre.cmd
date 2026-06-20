@echo off
REM Diagnostic — verifies Spectre-mitigated libs are installed where the
REM WDK build chain expects them. Run inside the VM.

echo === Visual Studio editions present ===
dir "C:\Program Files\Microsoft Visual Studio\2022" /b 2>nul
dir "C:\Program Files (x86)\Microsoft Visual Studio\2022" /b 2>nul

echo.
echo === MSVC toolchain version(s) under Community ===
dir "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC" /b 2>nul

echo.
echo === Spectre lib check (Community / x64) ===
for /d %%I in ("C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\*") do (
    echo --- %%~nxI ---
    if exist "%%I\lib\spectre\x64\libcmt.lib" (
        echo   [OK] libcmt.lib FOUND
    ) else (
        echo   [MISSING] libcmt.lib NOT FOUND
    )
    if exist "%%I\lib\spectre\x64\libcpmt.lib" (
        echo   [OK] libcpmt.lib FOUND
    ) else (
        echo   [MISSING] libcpmt.lib NOT FOUND
    )
    if exist "%%I\atlmfc\lib\spectre\x64\atls.lib" (
        echo   [OK] atls.lib FOUND
    ) else (
        echo   [MISSING] atls.lib NOT FOUND
    )
)

echo.
echo === WDK kernel mode lib path ===
dir "C:\Program Files (x86)\Windows Kits\10\Lib" /b 2>nul

echo.
echo === DONE ===
pause
