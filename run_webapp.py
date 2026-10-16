"""
SENTINEL AI // ONE-CLICK WEB APPLICATION LAUNCHER
Starts the high-performance FastAPI backend and flagship SOC Web App.
"""

import sys
import threading
import time
import webbrowser
import uvicorn

def open_browser():
    time.sleep(1.2)
    webbrowser.open("http://localhost:8000")

if __name__ == "__main__":
    print("=" * 65)
    print("🛡️  STARTING SENTINEL AI // DEFENSIVE NETWORK ANOMALY PLATFORM")
    print("=" * 65)
    print("🌐 Dashboard URL: http://localhost:8000")
    print("📑 Swagger API:  http://localhost:8000/docs")
    print("=" * 65)
    print("🚀 Automatically opening browser at http://localhost:8000 ...")
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("webapp.server:app", host="0.0.0.0", port=8000, reload=True)
