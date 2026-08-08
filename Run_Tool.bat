@echo off
chcp 65001 > nul

:: Nếu không có tham số hidden, khởi chạy lại bản thân ở chế độ ẩn bằng VBScript
if "%1"=="hidden" goto :RUN

set "TEMP_VBS=%temp%\hide_launcher_%random%.vbs"
echo Set WshShell = CreateObject("WScript.Shell") > "%TEMP_VBS%"
echo WshShell.Run """%~f0"" hidden", 0, False >> "%TEMP_VBS%"
wscript "%TEMP_VBS%"
del "%TEMP_VBS%"
exit /b

:RUN
if exist "dist\AutoResetConn.exe" (
    start "" "dist\AutoResetConn.exe"
) else (
    uv run --with requests --with psycopg2-binary --with cryptography AutoResetConn.py
)
