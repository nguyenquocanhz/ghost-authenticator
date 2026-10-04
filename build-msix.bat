@echo off
setlocal enabledelayedexpansion
title Builder Ghost Authenticator MSIX for Microsoft Store

echo.
echo ========================================================
echo   Ghost Authenticator - MSIX Packaging Tool
echo   Target: Microsoft Store (Windows 10 / 11)
echo ========================================================
echo.

:: 1. Kiem tra dotnet SDK
where dotnet >nul 2>nul
if %errorlevel% neq 0 (
    echo [LOI] Khong tim thay dotnet SDK.
    echo Vui long cai dat .NET SDK 8.0 tro len tai: https://dotnet.microsoft.com/download
    echo.
    pause
    exit /b 1
)

:: 2. Tim makeappx.exe va makepri.exe tu goi Microsoft.Windows.SDK.BuildTools
set "BUILDTOOLS_BASE=%USERPROFILE%\.nuget\packages\microsoft.windows.sdk.buildtools"
set "MAKEAPPX="
set "MAKEPRI="

for /f "delims=" %%I in ('dir /b /s "%BUILDTOOLS_BASE%\makeappx.exe" 2^>nul') do (
    echo %%I | findstr /i "\\x64\\makeappx.exe" >nul
    if !errorlevel! equ 0 (
        set "MAKEAPPX=%%I"
    )
)

for /f "delims=" %%I in ('dir /b /s "%BUILDTOOLS_BASE%\makepri.exe" 2^>nul') do (
    echo %%I | findstr /i "\\x64\\makepri.exe" >nul
    if !errorlevel! equ 0 (
        set "MAKEPRI=%%I"
    )
)

if not defined MAKEAPPX (
    echo [INFO] Dang cai dat build tools Microsoft.Windows.SDK.BuildTools...
    dotnet add package Microsoft.Windows.SDK.BuildTools
    for /f "delims=" %%I in ('dir /b /s "%BUILDTOOLS_BASE%\makeappx.exe" 2^>nul') do (
        echo %%I | findstr /i "\\x64\\makeappx.exe" >nul
        if !errorlevel! equ 0 set "MAKEAPPX=%%I"
    )
    for /f "delims=" %%I in ('dir /b /s "%BUILDTOOLS_BASE%\makepri.exe" 2^>nul') do (
        echo %%I | findstr /i "\\x64\\makepri.exe" >nul
        if !errorlevel! equ 0 set "MAKEPRI=%%I"
    )
)

if not defined MAKEAPPX (
    echo [LOI] Khong tim thay cong cu makeappx.exe!
    pause
    exit /b 1
)

echo [TIM THAY] Cong cu dong goi:
echo !MAKEAPPX!
echo.

:: 3. Bien dich ung dung
echo [1/4] Dang bien dich du an (Release x64)...
dotnet publish Authenticator.csproj -c Release -r win-x64 --self-contained false -p:Platform=x64
if %errorlevel% neq 0 (
    echo [LOI] dotnet publish that bai!
    pause
    exit /b 1
)

:: 4. Chuan bi staging layout
echo [2/4] Dang chuan bi layout dong goi...
set "PUBLISH_DIR=bin\x64\Release\net8.0-windows10.0.19041.0\win-x64\publish"
set "STAGE_DIR=obj\msix_staging"
set "DIST_DIR=dist"

if exist "%STAGE_DIR%" rmdir /s /q "%STAGE_DIR%"
mkdir "%STAGE_DIR%"
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"

xcopy /e /y /q "%PUBLISH_DIR%\*" "%STAGE_DIR%\" >nul
copy /y "Package.appxmanifest" "%STAGE_DIR%\AppxManifest.xml" >nul

:: 5. Tao index tai nguyen PRI
echo [3/4] Dang index tai nguyen giao dien (makepri)...
"!MAKEPRI!" createconfig /cf "%STAGE_DIR%\priconfig.xml" /dq en-US /o >nul
"!MAKEPRI!" new /pr "%STAGE_DIR%" /cf "%STAGE_DIR%\priconfig.xml" /of "%STAGE_DIR%\resources.pri" /o >nul
if exist "%STAGE_DIR%\priconfig.xml" del "%STAGE_DIR%\priconfig.xml" >nul

:: 6. Dong goi thanh file MSIX
echo [4/4] Dang dong goi file MSIX (makeappx)...
set "MSIX_OUTPUT=%DIST_DIR%\GhostAuthenticator_1.0.0_x64.msix"
"!MAKEAPPX!" pack /d "%STAGE_DIR%" /p "%MSIX_OUTPUT%" /o
if %errorlevel% neq 0 (
    echo [LOI] Dong goi MSIX that bai!
    pause
    exit /b 1
)

:: Don dep thu muc staging tam
if exist "%STAGE_DIR%" rmdir /s /q "%STAGE_DIR%"

echo.
echo ========================================================
echo   [THANH CONG] File MSIX da duoc tao tai:
echo   %MSIX_OUTPUT%
echo ========================================================
echo.
echo File nay da san sang de upload len Microsoft Partner Center!
echo.
explorer.exe "%DIST_DIR%"
pause
