# Vercel Deployment Guide

## Environment Variables

Add the following environment variable in your Vercel project settings:

1. Go to your project on Vercel
2. Navigate to **Settings** → **Environment Variables**
3. Add the following:

### Required:
- **Name:** `VITE_ALCHEMY_API_KEY`
- **Value:** Your Alchemy API key (get free at https://www.alchemy.com/)
- **Environment:** Production, Preview, Development

## Steps:

1. Sign up for free at https://www.alchemy.com/
2. Create a new app for Ethereum Mainnet
3. Copy your API key
4. Add it to Vercel environment variables
5. Redeploy your application

## Note:
Without the Alchemy API key, the app will still work but won't be able to fetch historical messages from the blockchain. Messages will only appear after they're sent while the app is open.
