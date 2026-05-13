# SLIM Block Cipher

A browser-based UI for the SLIM block cipher — 32-bit block, 80-bit key, 32 Feistel rounds.

## Deploy to Vercel

### Option A — Vercel CLI
```bash
npm i -g vercel
cd slim-cipher
vercel
```

### Option B — Vercel Dashboard (no CLI)
1. Go to https://vercel.com/new
2. Choose "Deploy without a Git repository" → drag & drop this folder
   — or —
   Push this folder to a GitHub repo, then import it on Vercel

That's it. No build step, no dependencies.

## Project structure
```
slim-cipher/
├── vercel.json       # tells Vercel to serve the public/ folder
├── README.md
└── public/
    └── index.html    # entire app — HTML + CSS + JS, self-contained
```
