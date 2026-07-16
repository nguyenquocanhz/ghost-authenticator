@echo off
title Builder Authenticator Desktop
echo.
echo ========================================================
echo   Dang bien dich Ghost Authenticator Desktop App...
echo ========================================================
echo.

:: Kiem tra xem dotnet CLI da duoc cai dat chua
where dotnet >nul 2>nul
if %errorlevel% neq 0 (
    echo [LOI] Khong tim thay dotnet SDK.
    echo Vui long tai va cai dat .NET SDK 8.0 tro len tai:
    echo https://dotnet.microsoft.com/download
    echo.
    pause
    exit /b
)

:: Khoi phuc va publish du an thanh 1 file exe duy nhat
echo Dang dung 'dotnet publish' de compile thanh 1 file exe chay truc tiep...
echo Vui long doi trong giay lat...
echo.

dotnet publish -c Release -p:PublishSingleFile=true --self-contained false

if %errorlevel% neq 0 (
    echo.
    echo [LOI] Bien dich that bai!
    echo Vui long kiem tra cac thong tin loi tren.
    echo.
    pause
    exit /b
)

echo.
echo ========================================================
echo   [THANH CONG] File exe da duoc tao tai:
echo   bin\Release\net8.0-windows\publish\
echo ========================================================
echo.
explorer.exe "bin\Release\net8.0-windows\publish\"
pause
