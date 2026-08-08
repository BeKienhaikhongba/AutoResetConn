Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

If fso.FileExists("AutoResetConn.py") Then
    WshShell.Run "uv run --with requests --with psycopg2-binary --with cryptography AutoResetConn.py", 0, False
ElseIf fso.FileExists("dist\AutoResetConn.exe") Then
    WshShell.Run chr(34) & "dist\AutoResetConn.exe" & chr(34), 0, False
ElseIf fso.FileExists("AutoResetConn.exe") Then
    WshShell.Run chr(34) & "AutoResetConn.exe" & chr(34), 0, False
End If
