@echo off
REM Find Visual Studio install + verify Spectre libs.

echo === Searching for cl.exe (C compiler) across all drives ===
for %%D in (C D E F G) do (
    if exist %%D:\ (
        echo Searching %%D:\
        dir /s /b "%%D:\cl.exe" 2>nul | findstr /i "MSVC" 2>nul
    )
)

echo.
echo === Searching for VS install directory ===
for %%D in (C D E F G) do (
    if exist %%D:\ (
        dir /s /b "%%D:\Microsoft Visual Studio" 2>nul | findstr /i "devenv.exe$"
    )
)

echo.
echo === Looking for spectre folders anywhere under VS ===
for %%D in (C D E F G) do (
    if exist %%D:\ (
        dir /s /b "%%D:\spectre" 2>nul | findstr /i "lib\\spectre\\x64$"
    )
)

echo.
echo === DONE ===
pause
