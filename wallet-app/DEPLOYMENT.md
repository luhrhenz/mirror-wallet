# 🚀 Wallet Application Deployment Guide

## Overview
This guide will help you deploy your enhanced wallet application to Render, making it accessible from any device worldwide with enterprise-grade security features.

## 📋 Prerequisites

### 1. GitHub Repository
- Ensure your code is pushed to GitHub (✅ Already done)
- Repository: `luhrhenz/mirror-wallet`

### 2. MongoDB Database
- Create a MongoDB Atlas account at [mongodb.com/atlas](https://mongodb.com/atlas)
- Create a free cluster (M0 tier is sufficient for development)
- Get your connection string

### 3. Render Account
- Create an account at [render.com](https://render.com)

## 🛠️ Step-by-Step Deployment

### Step 1: Deploy Backend to Render

1. **Visit Render Dashboard**
   - Go to [dashboard.render.com](https://dashboard.render.com)
   - Sign in to your account

2. **Create New Web Service**
   - Click **"New"** → **"Web Service"**
   - Select **"Build and deploy from a Git repository"**

3. **Connect GitHub Repository**
   - Click **"Connect"** next to your GitHub account
   - Search for `mirror-wallet` repository
   - Click **"Connect"**

4. **Configure Service Settings**
   ```
   Service Name: mirror-wallet-backend (or your preferred name)
   Runtime: Node.js
   Branch: main
   Root Directory: wallet-app/backend
   Build Command: npm install
   Start Command: npm start
   ```

5. **Add Environment Variables**
   Click **"Advanced"** and add these environment variables:

   ```
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/wallet_app?retryWrites=true&w=majority
   JWT_SECRET=your_super_secret_jwt_key_minimum_32_chars
   ENCRYPTION_KEY=your_32_character_encryption_key
   NODE_ENV=production
   ```

6. **Deploy the Service**
   - Click **"Create Web Service"**
   - Wait for the build to complete (usually 3-5 minutes)

### Step 2: Get Your Application URL

Once deployed, Render will provide you with a URL like:
```
https://mirror-wallet-backend.onrender.com
```

### Step 3: Test Your Deployment

1. **Test the API endpoints:**
   ```bash
   curl https://your-app-name.onrender.com/api/health
   curl https://your-app-name.onrender.com/api/wallets
   ```

2. **Update Frontend Configuration**
   - Update all API endpoints in your frontend files
   - Replace `http://localhost:3000` with your Render URL

### Step 4: Deploy Frontend (Optional)

Deploy your frontend to Netlify, Vercel, or another hosting service:

1. **Netlify Deployment:**
   - Go to [netlify.com](https://netlify.com)
   - Drag and drop your `wallet-app/frontend` folder
   - Update API endpoints to point to your Render backend

2. **Vercel Deployment:**
   - Install Vercel CLI: `npm i -g vercel`
   - Run `vercel` in your frontend directory
   - Follow the prompts to deploy

## 🔧 Environment Variables Setup

### Required Variables for Render:

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGODB_URI` | MongoDB connection string | `mongodb+srv://user:pass@cluster.mongodb.net/db` |
| `JWT_SECRET` | Secret key for JWT tokens | `your_super_secret_jwt_key_minimum_32_chars` |
| `ENCRYPTION_KEY` | 32-character key for data encryption | `your_32_character_encryption_key` |
| `NODE_ENV` | Environment mode | `production` |

### Generate Secure Keys:

1. **JWT Secret (minimum 32 characters):**
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

2. **Encryption Key (exactly 32 characters):**
   ```bash
   node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
   ```

## 📱 Accessing Your Application

### From Any Device:
1. **Mobile Phone:** Open browser and go to your Render URL
2. **Tablet:** Same as mobile - works on all devices
3. **Desktop:** Access from any computer worldwide

### Example URLs:
- **Backend API:** `https://your-app-name.onrender.com`
- **Frontend (if deployed):** `https://your-frontend-domain.com`

## 🔒 Security Features Active

Your deployed application includes:
- ✅ JWT Authentication
- ✅ AES-256-GCM Encryption
- ✅ Rate Limiting
- ✅ Input Validation
- ✅ Structured Logging
- ✅ CORS Protection
- ✅ Environment-based Configuration

## 🐛 Troubleshooting

### Common Issues:

1. **Build Failures:**
   - Check build logs in Render dashboard
   - Ensure all dependencies are in `package.json`
   - Verify Node.js version compatibility

2. **Database Connection Issues:**
   - Verify MongoDB connection string
   - Check MongoDB Atlas network access settings
   - Ensure database user has proper permissions

3. **Environment Variables:**
   - Confirm all required variables are set in Render
   - Check variable names match exactly (case-sensitive)
   - Verify values are not empty

### Getting Help:
- Check Render dashboard logs
- Review application logs in Render
- Test locally first: `npm start`

## 📊 Monitoring

### Render Dashboard Features:
- Real-time logs
- Service metrics
- Automatic deployments on git push
- Custom domains (paid plans)
- SSL certificates (automatic)

### Health Checks:
Your application includes health check endpoints:
- `GET /api/health` - Application health
- `GET /api/wallets` - Database connectivity

## 🎉 Success Checklist

- [ ] Backend deployed to Render
- [ ] Environment variables configured
- [ ] Application accessible via Render URL
- [ ] Database connection working
- [ ] Frontend updated with new API endpoints
- [ ] Application tested on mobile device
- [ ] Security features verified

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review Render documentation
3. Check application logs in Render dashboard
4. Test locally to isolate issues

Your wallet application is now ready for worldwide access with enterprise-grade security! 🌍✨