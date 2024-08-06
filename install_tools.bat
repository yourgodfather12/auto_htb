@echo off
REM Batch script to install required tools on Windows
REM Replace with appropriate installation commands for each tool

:: Check and install Python3
where python3 >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Installing Python3...
    choco install python3
)

:: Check and install other tools
for %%I in (amass sublist3r theHarvester nmap gobuster nikto wpscan sqlmap ffuf searchsploit enum4linux hydra) do (
    where %%I >nul 2>&1
    IF %ERRORLEVEL% NEQ 0 (
        echo Installing %%I...
        choco install %%I
    )
)

echo All tools installed.
pause
