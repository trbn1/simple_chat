REM Build client/server executable files.
REM Installed pyinstaller is required.
pyinstaller --onefile client.py
pyinstaller --onefile server.py