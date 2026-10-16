@echo off
title Sentinel AI - GitHub Deployment Assistant
echo ===================================================================
echo        SENTINEL AI: 1-CLICK GITHUB DEPLOYMENT ASSISTANT
echo ===================================================================
echo.
echo Ensuring Git is in PATH...
set "PATH=%LOCALAPPDATA%\Programs\MinGit\cmd;%PATH%"

where git >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Git was not found in PATH or MinGit directory.
    pause
    exit /b 1
)

echo.
echo [STEP 1] Ensure you have created a new empty repository on GitHub:
echo          https://github.com/new
echo          (Name it e.g. Network_Anomaly_Detection or Sentinel-AI)
echo          Do NOT check "Add a README", .gitignore, or license.
echo.
set /p GH_USER="Enter your GitHub Username (e.g. nethra): "
if "%GH_USER%"=="" (
    echo Username cannot be empty.
    pause
    exit /b 1
)

set /p GH_REPO="Enter your GitHub Repository Name (press Enter for 'Network_Anomaly_Detection'): "
if "%GH_REPO%"=="" set GH_REPO=Network_Anomaly_Detection

echo.
echo Configuring remote origin: https://github.com/%GH_USER%/%GH_REPO%.git ...
git remote remove origin 2>nul
git remote add origin https://github.com/%GH_USER%/%GH_REPO%.git
git branch -M main

echo.
echo ===================================================================
echo [STEP 2] Pushing code to GitHub...
echo If prompted, sign in via browser or paste your Personal Access Token.
echo ===================================================================
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo ===================================================================
    echo [SUCCESS] Your code is live on GitHub!
    echo Repository: https://github.com/%GH_USER%/%GH_REPO%
    echo ===================================================================
    echo.
    echo You can now deploy it on Render (100%% Free):
    echo 1. Go to https://render.com and sign in with GitHub.
    echo 2. Click "New +" -^> "Web Service".
    echo 3. Pick "%GH_REPO%" and click Deploy!
    echo ===================================================================
) else (
    echo.
    echo [NOTE] If push failed due to authentication, you can:
    echo 1. Use GitHub Personal Access Token (Settings -^> Developer Settings -^> Tokens)
    echo 2. Or upload the project folder via GitHub Desktop or web interface.
)

pause
