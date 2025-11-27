# ACDI Backend Deployment Guide

## Quick Deploy to Railway (Recommended - 5 minutes)

### Step 1: Create Railway Account
Go to https://railway.app and sign up with GitHub

### Step 2: Install Railway CLI
```bash
npm install -g @railway/cli
```

### Step 3: Login
```bash
railway login
```

### Step 4: Create New Project
```bash
cd acdi-mvp
railway init
```
Select "Empty Project" when prompted.

### Step 5: Deploy
```bash
railway up
```

### Step 6: Get Your URL
```bash
railway domain
```
This gives you a URL like: `https://acdi-mvp-production.up.railway.app`

### Step 7: Test It
```bash
curl https://YOUR-RAILWAY-URL/api/v1/health
curl https://YOUR-RAILWAY-URL/api/v1/demo/quick-scan?target=test.gov
```

### Step 8: Enter URL in v0.app
Go back to v0.app and enter your Railway URL in the `NEXT_PUBLIC_API_URL` field.

---

## Alternative: Deploy to Render.com

### Step 1: Create Account
Go to https://render.com and sign up

### Step 2: Create New Web Service
1. Click "New" → "Web Service"
2. Connect your GitHub repo (or use "Deploy from Git URL")
3. Configure:
   - **Name:** acdi-api
   - **Environment:** Docker
   - **Region:** Oregon (US West)
   - **Instance Type:** Free (or Starter for production)

### Step 3: Deploy
Click "Create Web Service"

### Step 4: Get URL
Your URL will be: `https://acdi-api.onrender.com`

---

## Alternative: Manual Docker Deploy

If you have a server with Docker:

```bash
# Clone/upload the acdi-mvp folder to your server

# Build
docker build -t acdi-platform .

# Run
docker run -d -p 8000:8000 --name acdi acdi-platform

# Your API is now at http://YOUR-SERVER-IP:8000
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 8000 | Port to run on (Railway sets this automatically) |
| `ENVIRONMENT` | production | Runtime environment |
| `LOG_LEVEL` | INFO | Logging verbosity |

---

## Verify Deployment

After deploying, test these endpoints:

```bash
# Health check
curl https://YOUR-URL/api/v1/health
# Expected: {"status":"healthy","timestamp":"..."}

# API info
curl https://YOUR-URL/api/v1/info
# Expected: {"name":"ACDI Platform API","version":"1.0.0",...}

# Demo scan (no network required)
curl "https://YOUR-URL/api/v1/demo/quick-scan?target=demo.agency.gov"
# Expected: Full CBOM JSON response
```

---

## Connecting to v0.app

Once deployed:

1. Copy your deployment URL (e.g., `https://acdi-api-production.up.railway.app`)
2. Go back to v0.app
3. In the environment variable dialog:
   - Variable: `NEXT_PUBLIC_API_URL`
   - Value: Your deployment URL (no trailing slash)
4. Click Submit
5. Your dashboard should now connect to the live backend!

---

## Troubleshooting

### "Connection refused" in v0.app
- Make sure your backend is deployed and running
- Check the URL doesn't have a trailing slash
- Test the URL directly in browser: `https://YOUR-URL/api/v1/health`

### CORS errors
- The backend is configured to allow all origins for demo
- If issues persist, check browser console for specific error

### Railway deploy fails
- Make sure Dockerfile is in the root directory
- Check Railway logs: `railway logs`

### Render deploy fails
- Check build logs in Render dashboard
- Ensure Docker build completes successfully

---

## Production Considerations

Before going live with real data:

1. **Restrict CORS** - Edit `src/api/main.py` to only allow your domain
2. **Add Authentication** - Implement JWT or API key auth
3. **Use HTTPS** - Railway/Render provide this automatically
4. **Monitor Logs** - Set up log aggregation
5. **Backup Data** - Add database persistence if needed

---

## Cost Estimates

| Platform | Free Tier | Paid |
|----------|-----------|------|
| Railway | $5 credit/month | ~$5-20/month |
| Render | 750 hours/month | ~$7/month |
| Fly.io | 3 shared VMs | ~$5/month |

For demos and pilots, free tiers are sufficient.
