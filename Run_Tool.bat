@echo off
chcp 65001 > nul
title AutoResetConn Launcher
echo Dang khoi dong Auto Reset DB Tool...

if exist "dist\AutoResetConn.exe" (
    start "" "dist\AutoResetConn.exe"
) else (
    $env:PYTHONUTF8=1; uv run --with requests --with psycopg2-binary --with cryptography AutoResetConn.py
)
