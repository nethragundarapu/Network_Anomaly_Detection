# 🚀 Sentinel AI — Comprehensive Production Deployment Handbook

This guide outlines step-by-step strategies to deploy the **Sentinel AI Network Anomaly Defense Platform** to production environments, ranging from free cloud hosting to enterprise container clusters.

---

## 📋 Deployment Options Comparison

| Platform | Difficulty | Cost | Best For | SSL / HTTPS |
| :--- | :--- | :--- | :--- | :--- |
| **Render.com** *(Recommended)* | Easy (3 mins) | Free Tier | Portfolio, Live Demos, Fast Share | Automatic |
| **Railway.app** | Easy (3 mins) | $5 Credit / Month | Rapid Git push deployments | Automatic |
| **Docker Compose (VPS)** | Intermediate | $4 - $6 / mo (Hetzner/DigitalOcean) | Complete control, 24/7 reliability | Nginx / Certbot |
| **Google Cloud Run / AWS ECS** | Advanced | Pay-per-use (often $0 - $2) | Enterprise scale, zero idle cost | Automatic |
| **Streamlit Community Cloud** | Very Easy | Free | Alternative Streamlit edition | Automatic |

---

## 🌐 Option 1: Render.com (100% Free & Recommended)

Render offers a generous free tier with automatic Git deployments, free SSL certificates, and custom domains.

### Step 1: Push your Code to GitHub
1. Initialize Git in your project folder (if not done already):
   ```bash
   git init
   git add .
   git commit -m "feat: Sentinel AI v3.0 Web App with Docker & FastAPI"
   ```
2. Create a new repository on [GitHub](https://github.com/new) and push your code:
   ```bash
   git remote add origin https://github.com/<your-username>/Network_Anomaly_Detection.git
   git branch -M main
   git push -u origin main
   ```

### Step 2: Deploy on Render
1. Go to [render.com](https://render.com) and sign in with GitHub.
2. Click **New +** → **Web Service**.
3. Select your repository `Network_Anomaly_Detection`.
4. Configure the settings:
   - **Name**: `sentinel-ai-defense`
   - **Environment**: `Python 3`
   - **Region**: Closest to you (e.g., Oregon or Frankfurt)
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn webapp.server:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path**: `/healthz`
5. Click **Create Web Service**. Within ~2 minutes, your live web application will be accessible at `https://sentinel-ai-defense.onrender.com`.

*(Note: Render automatically detects the included `render.yaml` if you choose "Blueprint" deployment).*

---

## 🐳 Option 2: Docker Container Deployment (Any Server / Cloud VM)

The project includes an optimized, production-ready `Dockerfile` and `docker-compose.yml`.

### Local Testing with Docker:
```bash
docker compose up --build -d
```
Visit `http://localhost:8000` to verify the container is running and healthy.

### Deploying to a Linux VPS (DigitalOcean, Linode, AWS EC2):
1. SSH into your server:
   ```bash
   ssh root@your-server-ip
   ```
2. Clone your repository:
   ```bash
   git clone https://github.com/<your-username>/Network_Anomaly_Detection.git
   cd Network_Anomaly_Detection
   ```
3. Run with Docker Compose:
   ```bash
   docker compose up -d --build
   ```
4. Check container health status:
   ```bash
   docker ps
   ```

---

## 🛡️ Option 3: Production VPS with Nginx Reverse Proxy & SSL (HTTPS)

For a public custom domain (e.g., `sentinel.yourdomain.com`) on Ubuntu 22.04 / 24.04:

### 1. Run the Service via Systemd:
Create a service file `/etc/systemd/system/sentinel.service`:
```ini
[Unit]
Description=Sentinel AI Web Application
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/Network_Anomaly_Detection
ExecStart=/home/ubuntu/Network_Anomaly_Detection/.venv/bin/uvicorn webapp.server:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```
Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinel
sudo systemctl start sentinel
```

### 2. Configure Nginx:
Create `/etc/nginx/sites-available/sentinel`:
```nginx
server {
    server_name sentinel.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
Enable site and acquire free SSL via Let's Encrypt:
```bash
sudo ln -s /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d sentinel.yourdomain.com
```

---

## ☁️ Option 4: Serverless Container (Google Cloud Run / AWS ECS)

### Google Cloud Run (Recommended for Zero-Idle Cost):
1. Install [Google Cloud SDK](https://cloud.google.com/sdk).
2. Build and submit container image:
   ```bash
   gcloud builds submit --tag gcr.io/<PROJECT_ID>/sentinel-ai
   ```
3. Deploy to Cloud Run:
   ```bash
   gcloud run deploy sentinel-ai \
     --image gcr.io/<PROJECT_ID>/sentinel-ai \
     --platform managed \
     --region us-central1 \
     --allow-unauthenticated \
     --port 8000 \
     --memory 1Gi
   ```
Cloud Run scales down to zero when idle ($0 cost) and wakes up in < 2 seconds.

---

## 🎈 Option 5: Streamlit Community Cloud (Alternative Edition)

If you specifically want to deploy the Streamlit version:
1. Push repository to GitHub.
2. Sign in to [share.streamlit.io](https://share.streamlit.io/).
3. Click **New app**.
4. Select your repository, branch `main`, and main file path `app.py`.
5. Click **Deploy!**

---

## 🔒 Production Security Checklist

- [x] **Non-root container user**: Dockerfile runs under unprivileged user `sentinel`.
- [x] **Health check probes**: Configured `/healthz` endpoint for automated recovery.
- [x] **Defensive scope enforcement**: Passive statistical ML inference only; no raw socket sniffers or packet injection.
- [x] **Rate limiting / Reverse proxy**: Recommend placing Cloudflare or Nginx in front for DDoS protection.
- [x] **CORS & CSRF**: Controlled via FastAPI middleware if extending cross-origin clients.

---

## ❓ Need Assistance?
Check the API documentation live at `http://localhost:8000/docs` or run `python run_webapp.py` locally.
